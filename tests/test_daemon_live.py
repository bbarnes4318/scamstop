"""Gatekeeper (no switch edits), live config reload and speech-model auto-download."""
import io
import json
import os
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import fakeredis
import numpy as np
import yaml

from scamstop import config, model
from scamstop.control import Dialog
from scamstop.daemon import Daemon
from scamstop.platforms.base import Platform, number_of
from scamstop.store import Store


class FakePlatform(Platform):
    name = "fake"

    def __init__(self, calls, ringing=False):
        self._calls, self.ended = calls, []
        self.can_end_ringing = ringing

    def all_calls(self):
        return [c for c in self._calls if c.callid not in self.ended]

    def audio(self, dlg, side, stop):
        while not stop():
            time.sleep(0.05)
            yield np.zeros(400, np.int16)

    def end(self, dlg):
        self.ended.append(dlg.callid)


def daemon(tmp_path, calls, ringing=False, extra=None):
    cfgp = tmp_path / "config.yaml"
    user = {"dry_run": False, "redis": {"customer_key": None},
            "evidence": {"kill_log": str(tmp_path / "kills.jsonl"), "flag_log": str(tmp_path / "flags.jsonl")},
            "warn": {"file": str(tmp_path / "w.wav")}, "smart": {"enabled": False},
            "status_file": str(tmp_path / "status.json"), "metrics": {"textfile": None}}
    user.update(extra or {})
    cfgp.write_text(yaml.safe_dump(user))
    fr = fakeredis.FakeRedis(decode_responses=True)
    orig = Store.from_url
    Store.from_url = classmethod(lambda cls, url, **kw: cls(fr, **kw))
    try:
        d = Daemon(config.load(str(cfgp)), str(cfgp), FakePlatform(calls, ringing))
    finally:
        Store.from_url = orig
    d.queues = [__import__("queue").Queue()]
    return d, cfgp


def test_number_of():
    assert number_of("sip:+18135550100@1.2.3.4;user=phone") == "8135550100"
    assert number_of("8135550100") == "8135550100" and number_of("sip:anonymous@x") == ""


def test_gatekeeper_ends_blocked_calls_without_switch_edits(tmp_path):
    calls = [Dialog(1, "a1@74.81.33.58", "t", "10.0.0.1", from_uri="sip:+12025550111@x", to_uri="sip:+18655550122@y"),
             Dialog(2, "b2@9.9.9.9", "t", "10.0.0.1", from_uri="sip:+18004321000@x", to_uri="sip:+18655550123@y"),
             Dialog(3, "c3@9.9.9.9", "t", "10.0.0.1", from_uri="sip:+12025550111@x", to_uri="sip:+14235550100@y"),
             Dialog(4, "CNX33890_9@1.1.1.1", "t", "10.0.0.1"),
             Dialog(5, "ok@8.8.4.4", "t", "10.0.0.1", from_uri="sip:+12025550111@x", to_uri="sip:+18655550199@y")]
    d, _ = daemon(tmp_path, calls)
    d.store.block("host", "74.81.33.58")
    d.store.block("cli", "8004321000")
    d.store.block("dnc", "4235550100")
    d.store.block("tag", "CNX33890")
    d.poll_once(set())
    assert sorted(d.platform.ended) == ["CNX33890_9@1.1.1.1", "a1@74.81.33.58", "b2@9.9.9.9", "c3@9.9.9.9"]
    assert list(d.listeners) == ["ok@8.8.4.4"]                  # only the clean call is listened to
    log = (tmp_path / "kills.jsonl").read_text()
    assert log.count("blocked_") == 4 and '"side": "gate"' in log
    for group in d.listeners.values():
        for l in group:
            l.stop = True


def test_ringing_calls_wait_until_answer_on_sip(tmp_path):
    call = Dialog(1, "r@74.81.33.58", "t", "10.0.0.1", state="early")
    d, _ = daemon(tmp_path, [call])
    d.store.block("host", "74.81.33.58")
    d.poll_once(set())
    assert d.platform.ended == []          # SIP proxies can't end an unanswered dialog: wait
    call.state = "up"
    d.poll_once(set())
    assert d.platform.ended == ["r@74.81.33.58"]


def test_platforms_that_can_end_ringing_calls_do(tmp_path):
    call = Dialog(1, "r@74.81.33.58", "t", "10.0.0.1", state="early")
    d, _ = daemon(tmp_path, [call], ringing=True)
    d.store.block("host", "74.81.33.58")
    d.poll_once(set())
    assert d.platform.ended == ["r@74.81.33.58"]
    assert '"ringing": true' in (tmp_path / "kills.jsonl").read_text()


def test_dry_run_gate_logs_only(tmp_path):
    d, _ = daemon(tmp_path, [Dialog(1, "a@74.81.33.58", "t", "10.0.0.1")], extra={"dry_run": True})
    d.store.block("host", "74.81.33.58")
    d.poll_once(set())
    assert d.platform.ended == [] and "blocked_host" in (tmp_path / "kills.jsonl").read_text()


def test_live_reload_applies_rules_and_flags_restart_sections(tmp_path):
    d, cfgp = daemon(tmp_path, [])
    assert any(r.id == "arrest_threat" for r in d.rules) and not d.cfg["dry_run"]
    u = yaml.safe_load(cfgp.read_text())
    u.update(dry_run=True, rules={"disabled": ["arrest_threat"]}, asterisk={"url": "http://other:8088"})
    time.sleep(0.01)
    cfgp.write_text(yaml.safe_dump(u))
    os.utime(cfgp, (time.time() + 5, time.time() + 5))
    d.check_reload()
    assert d.cfg["dry_run"] and d.enf.dry                       # applied live
    assert not any(r.id == "arrest_threat" for r in d.rules)
    assert d.status["restart_needed"] == ["asterisk"]            # platform settings need a restart
    assert d.cfg["asterisk"]["url"] != "http://other:8088"       # ...and are not half-applied
    d.write_status()
    assert json.loads((tmp_path / "status.json").read_text())["restart_needed"] == ["asterisk"]


def test_bad_config_is_not_applied(tmp_path):
    d, cfgp = daemon(tmp_path, [])
    cfgp.write_text("dry_run: [unclosed")
    os.utime(cfgp, (time.time() + 5, time.time() + 5))
    d.check_reload()
    assert "config_error" in d.status and d.cfg["dry_run"] is False


def _fake_model_archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:bz2") as tar:
        for name in model.NEEDED + ("README.md", "encoder-epoch-99-avg-1.onnx"):
            data = name.encode() * 100
            info = tarfile.TarInfo(f"{model.MODEL_NAME}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_model_auto_download_extracts_only_needed_files(tmp_path):
    blob = _fake_model_archive()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    seen = []
    try:
        d = tmp_path / "model"
        assert model.ensure(str(d), f"http://127.0.0.1:{srv.server_address[1]}/m.tar.bz2", seen.append)
        assert sorted(os.listdir(d)) == sorted(model.NEEDED) and seen[-1] == 100
        assert model.ensure(str(d), "http://unused") is False     # already there
    finally:
        srv.shutdown()


def test_clean_calls_keep_being_listened_to_across_polls(tmp_path):
    """Regression: the gatekeeper used to mark every checked call as ended on the second poll."""
    d, _ = daemon(tmp_path, [Dialog(1, "ok@8.8.4.4", "t", "10.0.0.1")])
    finished = set()
    for _ in range(4):
        d.poll_once(finished)
        time.sleep(0.05)
    assert list(d.listeners) == ["ok@8.8.4.4"] and all(l.is_alive() for l in d.listeners["ok@8.8.4.4"])
    assert d.platform.ended == [] and not finished
    for l in d.listeners["ok@8.8.4.4"]:
        l.stop = True
