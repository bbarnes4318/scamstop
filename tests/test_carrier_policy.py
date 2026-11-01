"""Carrier integration mode: the carrier's mandatory policy wins; customers cannot weaken it."""
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import fakeredis
import pytest
import yaml

from scamstop import config, policy
from scamstop.control import Dialog
from scamstop.daemon import Enforcer, Stats
from scamstop.platforms.sip import SipPlatform
from scamstop.rules import Hit
from scamstop.store import Store
from scamstop.tenants import Tenants, make_token


def cfg(carrier=True, dry=True, **pol):
    c = config.load(None)
    c["dry_run"] = dry
    c["carrier"]["enabled"] = carrier
    c["carrier"]["policy"].update(pol)
    c["hosted"]["enabled"] = True
    for k in ("kill_log", "flag_log", "enforcement_log", "escalation_log"):
        c["evidence"][k] = None
    return c


def test_carrier_policy_overrides_global_dry_run_and_tenant_settings():
    c = cfg(carrier=True, dry=True)
    p = policy.effective(c, {"id": "t_1", "dry_run": True, "warn_mode": "warn_only"})
    assert p.source == "carrier" and not p.dry_run and p.warn_mode == "warn_then_hangup" and p.terminates


def test_bad_carrier_warn_mode_cannot_weaken_enforcement():
    p = policy.effective(cfg(warn_mode="typo"))
    assert p.warn_mode == "warn_then_hangup" and not p.dry_run


def test_explicit_operator_advisory_carrier_mode_is_the_only_off_switch():
    p = policy.effective(cfg(enforce=False))
    assert p.dry_run and p.source == "carrier"


def test_standalone_advisory_mode_is_preserved():
    c = cfg(carrier=False, dry=True)
    assert policy.effective(c).dry_run
    assert policy.effective(c, {"id": "t", "dry_run": True, "warn_mode": "off"}).dry_run
    # and a standalone tenant's own choice still applies
    assert not policy.effective(c, {"id": "t", "dry_run": False, "warn_mode": "off"}).dry_run


def test_tenant_cannot_change_protection_in_carrier_mode():
    r = fakeredis.FakeRedis(decode_responses=True)
    T = Tenants(Store(r), {"enabled": True}, carrier=True, operator="PVN")
    t = T.create("Acme", "a@acme.example", "longpassword1")
    assert t["dry_run"] is False
    for change in ({"dry_run": True}, {"warn_mode": "off"}, {"warn_mode": "warn_only", "name": "x"}):
        with pytest.raises(policy.PolicyLocked):
            T.update(t["id"], **change)
    assert T.get(t["id"])["name"] == "Acme"     # nothing partially applied
    T.update(t["id"], name="Acme 2")            # unrelated fields still editable
    assert T.get(t["id"])["name"] == "Acme 2"


def test_enforcer_ignores_tenant_watch_only_in_carrier_mode():
    c = cfg(carrier=True, dry=True)

    class P:
        ended = []

        def end(self, d):
            P.ended.append(d.callid)

    e = Enforcer(c, SipPlatform(P(), None), Store(fakeredis.FakeRedis(decode_responses=True)), Stats())
    e.tenants = type("T", (), {"for_ip": lambda self, ip: {"id": "t_1", "dry_run": True, "warn_mode": "warn_only"}})()
    assert e.handle(Dialog(1, "k@9.9.9.9", "s", "10.0.0.1"), Hit("gift_card_payment", "g", "kill", "x"), "t")
    assert P.ended == ["k@9.9.9.9"]


# ---- the HTTP API ---------------------------------------------------------------------------------

@pytest.fixture
def carrier_portal(tmp_path):
    from scamstop import ui
    cfgp = tmp_path / "config.yaml"
    cfgp.write_text(yaml.safe_dump({"hosted": {"enabled": True, "signup_open": True},
                                    "carrier": {"enabled": True, "operator": "PVN"},
                                    "metrics": {"textfile": None}}))
    fr = fakeredis.FakeRedis(decode_responses=True)
    panel = ui.Panel(str(cfgp), "adminpw", False)
    panel.store = lambda cfg=None: Store(fr)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), ui.make_handler(panel))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", panel, fr
    srv.shutdown()


def call(base, path, body=None, token=None, method=None):
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base + path, json.dumps(body).encode() if body is not None else None, h,
                                 method=method or ("POST" if body is not None else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_portal_signup_closed_and_tenant_api_refuses_policy_changes(carrier_portal):
    base, panel, fr = carrier_portal
    pub = call(base, "/api/public")[1]
    assert pub["carrier"] and not pub["signup_open"] and pub["operator"] == "PVN"
    assert call(base, "/api/signup", {"name": "X", "email": "x@x.example", "password": "longpassword1"})[0] == 403
    t = panel.tenants().create("Acme", "a@acme.example", "longpassword1")
    tok = make_token(panel.secret, t["id"])
    for body in ({"dry_run": True}, {"warn_mode": "off"}, {"warn_mode": "warn_only"}):
        code, resp = call(base, "/api/me", body, tok)
        assert code == 403 and "PVN" in resp["error"]
    assert panel.tenants().get(t["id"])["dry_run"] is False
    # the admin tenant-edit route cannot weaken it either: that is a config-file decision
    admin = make_token(panel.secret, "admin")
    assert call(base, f"/api/tenants/{t['id']}", {"dry_run": True}, admin)[0] == 403
    # and the panel cannot edit the carrier section at all
    call(base, "/api/config", {"carrier": {"enabled": False}}, admin)
    assert panel.cfg()["carrier"]["enabled"] is True


def test_panel_cannot_write_customer_registry_in_carrier_mode(carrier_portal):
    base, panel, fr = carrier_portal
    admin = make_token(panel.secret, "admin")
    code, _ = call(base, "/api/customers", {"ip": "203.0.113.9"}, admin)
    assert code == 403 and not fr.exists("sbc:cust:203.0.113.9")
