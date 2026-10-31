import threading
from http.server import ThreadingHTTPServer

import fakeredis
import pytest

from scamstop import config
from scamstop.feed import FeedClient
from scamstop.feed_server import Feed, make_handler, valid
from scamstop.store import Store


def feed(tmp_path, **kw):
    return Feed(str(tmp_path / "feed.db"), **kw)


def ind(kind, value, rule="gift_card_payment"):
    return {"indicators": [{"kind": kind, "value": value, "rule": rule}]}


def published(f):
    return {(i["kind"], i["value"]) for i in f.published()}


def test_validation_rejects_private_and_junk():
    assert valid("media", "74.81.33.58")
    assert not valid("media", "10.0.0.5") and not valid("media", "127.0.0.1") and not valid("host", "192.168.1.1")
    assert valid("cli", "8004321000") and not valid("cli", "911")
    assert valid("tag", "CNX33890") and not valid("tag", "CNX'; drop")
    assert not valid("dnc", "2025550123")  # victims' numbers are never shared


def test_one_network_is_not_enough(tmp_path):
    f = feed(tmp_path)
    a = f.register("a", "1.1.1.1")["install_id"]
    b = f.register("b", "1.1.1.2")["install_id"]  # same /24 as a
    f.report(a, "1.1.1.1", ind("media", "74.81.33.58"))
    f.report(b, "1.1.1.2", ind("media", "74.81.33.58"))
    assert published(f) == set()


def test_two_networks_publish(tmp_path):
    f = feed(tmp_path)
    a = f.register("a", "1.1.1.1")["install_id"]
    b = f.register("b", "2.2.2.2")["install_id"]
    f.report(a, "1.1.1.1", ind("media", "74.81.33.58"))
    f.report(b, "2.2.2.2", ind("media", "74.81.33.58", "bail_scam"))
    [i] = f.published()
    assert i["reporters"] == 2 and i["networks"] == 2 and set(i["rules"]) == {"gift_card_payment", "bail_scam"}


def test_trusted_install_publishes_alone_and_ban_withdraws(tmp_path):
    f = feed(tmp_path)
    a = f.register("carrier", "1.1.1.1")["install_id"]
    f.admin("trust", a)
    f.report(a, "1.1.1.1", ind("cli", "8004321000"))
    assert published(f) == {("cli", "8004321000")}
    f.admin("ban", a)
    assert published(f) == set()


def test_allowlist_overrides(tmp_path):
    f = feed(tmp_path, min_networks=1)
    a = f.register("a", "1.1.1.1")["install_id"]
    f.report(a, "1.1.1.1", ind("host", "8.8.8.8"))
    f.admin("allow", "host", "8.8.8.8", "google dns")
    assert published(f) == set()


def test_quota_and_registration_limit(tmp_path):
    f = feed(tmp_path, min_networks=1, max_reports_per_day=2, max_registrations_per_ip=1)
    a = f.register("a", "3.3.3.3")["install_id"]
    r = f.report(a, "3.3.3.3", {"indicators": [{"kind": "cli", "value": f"800432100{i}", "rule": "x"} for i in range(5)]})
    assert r == {"accepted": 2, "rejected": 3}
    with pytest.raises(PermissionError):
        f.register("again", "3.3.3.3")


@pytest.fixture()
def server(tmp_path):
    f = feed(tmp_path, min_networks=1)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(f, False))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", f
    srv.shutdown()


def client(url, tmp_path, name, **feedcfg):
    cfg = config.load(None)
    cfg["feed"].update(enabled=True, url=url, **feedcfg)
    cfg["evidence"]["kill_log"] = None
    st = Store(fakeredis.FakeRedis(decode_responses=True))
    return FeedClient(cfg, st, str(tmp_path / f"{name}.json")), st


def test_end_to_end_share_and_apply(server, tmp_path):
    url, _ = server
    a, sa = client(url, tmp_path, "a")
    b, sb = client(url, tmp_path, "b")
    sa.block("media", "74.81.33.58", 3600, "bail_scam x2")      # caught on network A
    sa.block("cli", "8004321000", 0, "manual")
    sa.block("dnc", "2025550123", 0, "manual")                   # never shared
    assert a.sync()["shared"] == 2
    r = b.sync()                                                 # network B pulls
    assert r["added"] == 2 and sb.is_blocked("media", "74.81.33.58") and not sb.is_blocked("dnc", "2025550123")
    assert sb.list_blocks("media")[0]["reason"].startswith("feed:bail_scam")
    assert b.sync()["added"] == 0                                # idempotent (and 304 path)
    sa.unblock("media", "74.81.33.58")                           # A lifts its block...
    assert a.sync()["withdrawn"] == 1                            # ...and withdraws its report
    server[1]._cache = None
    assert b.sync()["removed"] == 1 and not sb.is_blocked("media", "74.81.33.58")


def test_feed_never_overrides_local_or_blocks_customers(server, tmp_path):
    url, f = server
    a, sa = client(url, tmp_path, "a")
    b, sb = client(url, tmp_path, "b")
    sa.block("media", "74.81.33.58", 0, "bail_scam x2")
    sa.block("host", "51.161.91.166", 0, "irs_threat x2")
    a.sync()
    sb.r.set("sbc:cust:74.81.33.58", 1)                          # that IP is B's own customer
    sb.block("host", "51.161.91.166", 0, "manual")               # B already blocked it locally
    b.sync()
    assert not sb.is_blocked("media", "74.81.33.58")
    assert sb.list_blocks("host")[0]["reason"] == "manual"


def test_state_file_hides_key(server, tmp_path):
    url, _ = server
    a, _ = client(url, tmp_path, "a")
    a.sync()
    assert "key" not in a.public_state() and a.public_state()["install_id"].startswith("ss_")
    assert oct((tmp_path / "a.json").stat().st_mode)[-3:] == "600"
