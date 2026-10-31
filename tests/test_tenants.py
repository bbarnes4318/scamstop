import time

import fakeredis
import pytest

from scamstop import config
from scamstop.control import Dialog
from scamstop.daemon import Enforcer, Stats
from scamstop.platforms.sip import SipPlatform
from scamstop.rules import Hit
from scamstop.store import Store
from scamstop.tenants import Tenants, make_token, parse_carrier, read_token


def tenants(**hosted):
    st = Store(fakeredis.FakeRedis(decode_responses=True))
    h = dict(config.load(None)["hosted"], enabled=True, sbc_address="203.0.113.5", **hosted)
    return Tenants(st, h), st


def test_signup_is_pending_and_routes_nothing_until_approved():
    T, st = tenants()
    t = T.create("Acme Dialers", "Ops@Acme.com", "correct horse battery")
    assert t["status"] == "pending" and t["email"] == "ops@acme.com" and t["dry_run"]
    T.update(t["id"], carrier="64.34.1.2")
    T.add_ip(t["id"], "198.51.100.10")
    assert st.r.get("sbc:cust:198.51.100.10") is None          # SBC rejects: not approved
    T.set_status(t["id"], "active")
    assert st.r.get("sbc:cust:198.51.100.10") == t["id"]
    assert st.r.get("sbc:route:198.51.100.10") == "64.34.1.2:5060"
    T.set_status(t["id"], "suspended")
    assert st.r.get("sbc:cust:198.51.100.10") is None and st.r.get("sbc:route:198.51.100.10") is None


def test_default_termination_and_validation():
    T, st = tenants(default_carrier="10.20.30.40:5080")
    t = T.create("B", "b@b.co", "0123456789")
    assert t["carrier_mode"] == "default"
    T.add_ip(t["id"], "198.51.100.20")
    T.set_status(t["id"], "active")
    assert st.r.get("sbc:route:198.51.100.20") == "10.20.30.40:5080"
    with pytest.raises(ValueError, match="SBC itself"):
        T.update(t["id"], carrier_mode="own", carrier="203.0.113.5")
    with pytest.raises(ValueError):
        T.add_ip(t["id"], "127.0.0.1")
    with pytest.raises(ValueError, match="already exists"):
        T.create("B2", "B@b.co", "0123456789")
    with pytest.raises(ValueError, match="10 characters"):
        T.create("C", "c@c.co", "short")


def test_ip_cannot_be_claimed_by_two_tenants():
    T, _ = tenants()
    a = T.create("A", "a@a.co", "0123456789")
    b = T.create("B", "b@b.co", "0123456789")
    T.add_ip(a["id"], "198.51.100.30")
    with pytest.raises(ValueError, match="another account"):
        T.add_ip(b["id"], "198.51.100.30")
    T.remove_ip(a["id"], "198.51.100.30")
    T.add_ip(b["id"], "198.51.100.30")


def test_login_and_tokens():
    T, _ = tenants()
    t = T.create("A", "a@a.co", "0123456789")
    assert T.authenticate("A@a.co", "0123456789")["id"] == t["id"]
    assert T.authenticate("a@a.co", "wrong") is None and T.authenticate("x@x.co", "0123456789") is None
    tok = make_token("s3cret", t["id"])
    assert read_token("s3cret", tok) == t["id"] and read_token("other", tok) is None
    assert read_token("s3cret", make_token("s3cret", "x", hours=-1)) is None


def test_parse_carrier():
    assert parse_carrier("sip:SIP.Carrier.com:5080;transport=udp") == "sip.carrier.com:5080"
    assert parse_carrier("64.34.1.2") == "64.34.1.2:5060"
    with pytest.raises(ValueError):
        parse_carrier("bad host!")


class FakeProxy:
    def __init__(self):
        self.ended = []

    def end(self, d):
        self.ended.append(d.callid)


def test_daemon_uses_each_companys_own_settings(tmp_path):
    T, st = tenants()
    a = T.create("Watching Co", "a@a.co", "0123456789")      # watch-only (default)
    b = T.create("Strict Co", "b@b.co", "0123456789")
    for t, ip in ((a, "198.51.100.1"), (b, "198.51.100.2")):
        T.update(t["id"], carrier="64.34.1.2")
        T.add_ip(t["id"], ip)
        T.set_status(t["id"], "active")
    T.update(b["id"], dry_run=False, warn_mode="off")
    cfg = config.load(None)
    cfg["dry_run"] = False
    cfg["evidence"]["kill_log"] = str(tmp_path / "k.jsonl")
    p = FakeProxy()
    e = Enforcer(cfg, SipPlatform(p, None), st, Stats(), T)
    hit = Hit("irs_threat", "IRS", "kill", "irs you owe")
    e.handle(Dialog(1, "x1@9.9.9.9", "t", "198.51.100.1"), hit, "t")
    e.handle(Dialog(2, "x2@9.9.9.9", "t", "198.51.100.2"), hit, "t")
    assert p.ended == ["x2@9.9.9.9"]                         # only the company that turned protection on
    log = (tmp_path / "k.jsonl").read_text()
    assert f'"tenant": "{a["id"]}"' in log and f'"tenant": "{b["id"]}"' in log
