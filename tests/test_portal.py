"""Hosted portal: sign-up, approval, company-scoped access."""
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import fakeredis
import pytest

from scamstop import store as storemod
from scamstop.ui import FAILS, Panel, make_handler


@pytest.fixture()
def portal(tmp_path, monkeypatch):
    FAILS.clear()
    fr = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(storemod.Store, "from_url", classmethod(lambda cls, url, **kw: cls(fr, **kw)))
    cfgp = tmp_path / "config.yaml"
    cfgp.write_text(f"""
hosted: {{enabled: true, sbc_address: 203.0.113.5, default_carrier: "10.9.8.7:5060", brand: SafeCall}}
evidence: {{kill_log: {tmp_path}/kills.jsonl, flag_log: {tmp_path}/flags.jsonl}}
smart: {{labels_file: {tmp_path}/labels.jsonl}}
metrics: {{textfile: {tmp_path}/m.prom}}
status_file: {tmp_path}/status.json
""")
    p = Panel(str(cfgp), "adminpw", False)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(p))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", p, fr, tmp_path
    srv.shutdown()


def call(base, path, method="GET", body=None, tok=None):
    h = {"Content-Type": "application/json"}
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    req = urllib.request.Request(base + path, method=method, headers=h,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def signup(base, email="ops@acme.com"):
    code, r = call(base, "/api/signup", "POST", {"name": "Acme", "email": email, "password": "correct horse 1"})
    assert code == 200 and r["role"] == "tenant"
    return r["token"]


def test_public_info(portal):
    base, *_ = portal
    assert call(base, "/api/public")[1] == {"hosted": True, "brand": "SafeCall", "signup_open": True, "support_email": ""}


def test_signup_connect_and_approval_flow(portal):
    base, p, fr, _ = portal
    tok = signup(base)
    code, me = call(base, "/api/me", tok=tok)
    assert me["tenant"]["status"] == "pending" and me["connect"]["sbc_address"] == "203.0.113.5"
    assert me["tenant"]["carrier_mode"] == "default" and me["connect"]["default_available"]
    call(base, "/api/me/ips", "POST", {"ip": "198.51.100.10"}, tok)
    assert call(base, "/api/status", tok=tok)[1]["mode"] == "pending"
    assert fr.get("sbc:cust:198.51.100.10") is None                      # not routed before approval
    # admin approves
    _, adm = call(base, "/api/login", "POST", {"password": "adminpw"})
    tid = me["tenant"]["id"]
    _, lst = call(base, "/api/tenants", tok=adm["token"])
    assert [t["id"] for t in lst["tenants"]] == [tid]
    call(base, f"/api/tenants/{tid}", "POST", {"status": "active"}, adm["token"])
    assert fr.get("sbc:cust:198.51.100.10") == tid and fr.get("sbc:route:198.51.100.10") == "10.9.8.7:5060"
    # tenant switches to their own carrier and turns protection on
    call(base, "/api/me", "POST", {"carrier_mode": "own", "carrier": "sip:64.34.1.2:5080", "dry_run": False}, tok)
    assert fr.get("sbc:route:198.51.100.10") == "64.34.1.2:5080"
    st = call(base, "/api/status", tok=tok)[1]
    assert st["role"] == "tenant" and st["mode"] == "offline"             # daemon not running in this test


def test_companies_only_see_their_own_calls_and_cannot_use_admin(portal):
    base, p, fr, tmp = portal
    a, b = signup(base, "a@a.co"), signup(base, "b@b.co")
    ta = call(base, "/api/me", tok=a)[1]["tenant"]["id"]
    tb = call(base, "/api/me", tok=b)[1]["tenant"]["id"]
    now = int(time.time())
    (tmp / "kills.jsonl").write_text("".join(json.dumps({"ts": now, "tenant": t, "rule": "irs_threat", "callid": c,
                                                         "transcript": "x"}) + "\n" for t, c in ((ta, "ca"), (tb, "cb"))))
    assert [e["callid"] for e in call(base, "/api/events", tok=a)[1]] == ["ca"]
    assert call(base, "/api/label", "POST", {"callid": "cb", "rule": "irs_threat", "label": "scam"}, a)[0] == 400
    for method, path in (("GET", "/api/tenants"), ("GET", "/api/config"), ("POST", "/api/blocks"), ("GET", "/api/syscheck")):
        assert call(base, path, method, {} if method == "POST" else None, a)[0] == 403
    assert call(base, f"/api/tenants/{tb}", "POST", {"status": "active"}, a)[0] == 403


def test_bad_logins_lock_out(portal):
    base, *_ = portal
    signup(base, "a@a.co")
    for _ in range(10):
        call(base, "/api/login", "POST", {"email": "a@a.co", "password": "nope"})
    assert call(base, "/api/login", "POST", {"email": "a@a.co", "password": "correct horse 1"})[0] == 429


def test_signup_closed(portal):
    base, p, *_ = portal
    p.save_cfg({"hosted": {"signup_open": False}})
    assert call(base, "/api/signup", "POST", {"name": "X", "email": "x@x.co", "password": "0123456789"})[0] == 403
