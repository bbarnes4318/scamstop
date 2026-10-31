"""Panel API over real HTTP, with fakeredis behind it."""
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import fakeredis
import pytest

from scamstop import store as storemod
from scamstop.ui import Panel, make_handler, valid_value

PW = "test-pw"


@pytest.fixture()
def panel(tmp_path, monkeypatch):
    fr = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(storemod.Store, "from_url",
                        classmethod(lambda cls, url, **kw: cls(fr, **kw)))
    cfgp = tmp_path / "config.yaml"
    cfgp.write_text(f"""
dry_run: true
evidence:
  kill_log: {tmp_path}/kills.jsonl
  flag_log: {tmp_path}/flags.jsonl
metrics:
  textfile: {tmp_path}/m.prom
status_file: {tmp_path}/state/status.json
""")
    now = int(time.time())
    (tmp_path / "kills.jsonl").write_text(json.dumps({"ts": now, "dry": True, "rule": "irs_threat", "rule_name": "IRS",
                                                      "matched": "irs you owe", "callid": "c1"}) + "\n")
    (tmp_path / "m.prom").write_text(f"scamstop_active 7\nscamstop_last_poll_seconds {now}\n")
    p = Panel(str(cfgp), PW, allow_restart=False)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(p))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", p
    srv.shutdown()


def call(base, path, method="GET", body=None, pw=PW):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {pw}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_page_is_public_api_is_not(panel):
    base, _ = panel
    with urllib.request.urlopen(base + "/") as r:
        assert b"ScamStop" in r.read()
    assert call(base, "/api/status", pw="wrong")[0] == 401


def test_status(panel):
    base, _ = panel
    code, s = call(base, "/api/status")
    assert code == 200 and s["mode"] == "watching" and s["running"] and s["active_calls"] == 7
    assert s["would_stop_today"] == 1 and s["stopped_today"] == 0


def test_events(panel):
    base, _ = panel
    _, ev = call(base, "/api/events?limit=10")
    assert ev[0]["rule"] == "irs_threat" and ev[0]["kind"] == "kill"


def test_config_save_merges_and_ignores_unknown(panel):
    base, p = panel
    call(base, "/api/config", "POST", {"dry_run": False, "rtpengine": {"port": 2223}, "evil": 1})
    u = p.user_cfg()
    assert u["dry_run"] is False and u["rtpengine"]["port"] == 2223 and "evil" not in u
    assert u["evidence"]["kill_log"].endswith("kills.jsonl")  # untouched keys survive


def test_rules_toggle(panel):
    base, p = panel
    call(base, "/api/rules", "POST", {"id": "arrest_threat", "state": "off"})
    call(base, "/api/rules", "POST", {"id": "amazon_impersonation", "state": "flag"})
    rules = {r["id"]: r["state"] for r in call(base, "/api/rules")[1]}
    assert rules["arrest_threat"] == "off" and rules["amazon_impersonation"] == "flag"
    call(base, "/api/rules", "POST", {"id": "amazon_impersonation", "state": "kill"})
    assert "amazon_impersonation" not in p.cfg()["rules"]["actions"]
    assert call(base, "/api/rules", "POST", {"id": "nope", "state": "off"})[0] == 400


def test_scan(panel):
    base, _ = panel
    _, r = call(base, "/api/scan", "POST", {"text": "Go buy Google Play cards now."})
    assert r["killed"] and r["hits"][0]["rule_id"] == "gift_card_payment"


def test_blocks_validate_add_remove(panel):
    base, _ = panel
    assert call(base, "/api/blocks", "POST", {"kind": "media", "value": "not-an-ip"})[0] == 400
    assert call(base, "/api/blocks", "POST", {"kind": "cli", "value": "8004321000", "ttl": 0})[0] == 200
    assert call(base, "/api/blocks")[1]["cli"][0]["value"] == "8004321000"
    call(base, "/api/blocks?kind=cli&value=8004321000", "DELETE")
    assert call(base, "/api/blocks")[1]["cli"] == []


def test_customers(panel):
    base, _ = panel
    call(base, "/api/customers", "POST", {"ip": "203.0.113.10"})
    assert call(base, "/api/customers")[1] == {"mode": "listed", "ips": ["203.0.113.10"]}
    assert call(base, "/api/customers", "POST", {"ip": "bad"})[0] == 400
    call(base, "/api/customers?ip=203.0.113.10", "DELETE")
    assert call(base, "/api/customers")[1]["ips"] == []


def test_snippet_and_restart_request(panel, tmp_path):
    base, _ = panel
    assert "sbc:block:media" in call(base, "/api/snippet?type=kamailio")[1]["text"]
    r = call(base, "/api/restart", "POST")[1]                    # daemon is running: ask it to restart itself
    assert r["ok"] and (tmp_path / "state" / "restart-request").exists()
    (tmp_path / "m.prom").write_text("scamstop_last_poll_seconds 1\n")
    r = call(base, "/api/restart", "POST")[1]                    # not running and not allowed to start it
    assert r["ok"] is False and "systemctl start" in r["message"]


def test_valid_value():
    assert valid_value("media", "1.2.3.4") and not valid_value("media", "1.2.3")
    assert valid_value("tag", "CNX123") and not valid_value("tag", "x;rm")
    assert valid_value("cli", "8004321000") and not valid_value("cli", "0004321000")


def test_warning_audio_get_upload_reset(panel, tmp_path):
    base, p = panel
    p.save_cfg({"warn": {"file": str(tmp_path / "warning.wav")}})
    req = urllib.request.Request(base + "/api/warning", headers={"Authorization": f"Bearer {PW}"})
    with urllib.request.urlopen(req) as r:
        default = r.read()
    assert default[:4] == b"RIFF"
    bad = urllib.request.Request(base + "/api/warning", data=b"<html>", method="POST", headers={"Authorization": f"Bearer {PW}"})
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(bad)
    good = urllib.request.Request(base + "/api/warning", data=b"ID3fake-mp3", method="POST", headers={"Authorization": f"Bearer {PW}"})
    urllib.request.urlopen(good)
    assert (tmp_path / "warning.wav").read_bytes() == b"ID3fake-mp3"
    call(base, "/api/warning", "DELETE")
    assert (tmp_path / "warning.wav").read_bytes() == default


def test_labels_and_smart_unlock(panel, tmp_path):
    base, p = panel
    p.save_cfg({"smart": {"labels_file": str(tmp_path / "labels.jsonl"), "proven": {"min_reviewed": 2, "min_precision": 0.9}}})
    flags = tmp_path / "flags.jsonl"
    flags.write_text("".join(json.dumps({"ts": int(time.time()), "rule": "smart_check", "callid": f"s{i}",
                                         "transcript": "buy cards"}) + "\n" for i in range(3)))
    code, r = call(base, "/api/smart", "POST", {"mode": "kill"})
    assert code == 400 and "0 reviewed" in r["error"]                    # locked until proven
    call(base, "/api/label", "POST", {"callid": "s0", "rule": "smart_check", "label": "scam"})
    call(base, "/api/label", "POST", {"callid": "s1", "rule": "smart_check", "label": "scam"})
    st = call(base, "/api/smart")[1]
    assert st["reviewed"] == 2 and st["precision"] == 1.0 and st["proven"]
    assert call(base, "/api/smart", "POST", {"mode": "kill"})[0] == 200
    assert p.cfg()["smart"]["mode"] == "kill"
    assert call(base, "/api/label", "POST", {"callid": "nope", "rule": "smart_check", "label": "scam"})[0] == 400
    ev = call(base, "/api/events?limit=10")[1]
    assert {e["callid"]: e["label"] for e in ev if e["rule"] == "smart_check"}["s0"] == "scam"
    assert "buy cards" in (tmp_path / "labels.jsonl").read_text()        # transcript kept for retraining
