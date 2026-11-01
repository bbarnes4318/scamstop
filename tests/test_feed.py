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


def test_public_site_install_script_and_downloads(tmp_path):
    import hashlib
    import urllib.error
    import urllib.request
    from scamstop.feed_server import Downloads
    d = tmp_path / "dl"
    d.mkdir()
    blob = b"#!/bin/sh\necho installer\n" * 100
    (d / "scamstop-installer-linux-x86_64.run").write_bytes(blob)
    (d / "secret.txt").write_text("nope")
    f = feed(tmp_path, min_networks=1)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(f, False, Downloads(str(d)), "https://scamstop.example.net"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        page = urllib.request.urlopen(base + "/").read().decode()
        assert "curl -fsSL https://scamstop.pvnvoice.com/install | sudo bash" in page and "/v1/stats" in page
        sh = urllib.request.urlopen(base + "/install").read().decode()
        assert "https://scamstop.example.net/download/scamstop-installer-linux-x86_64.run" in sh and "sha256sum -c" in sh
        assert urllib.request.urlopen(base + "/download/scamstop-installer-linux-x86_64.run").read() == blob
        sums = urllib.request.urlopen(base + "/download/SHA256SUMS").read().decode()
        assert sums == f"{hashlib.sha256(blob).hexdigest()}  scamstop-installer-linux-x86_64.run\n"
        for bad in ("/download/..%2Fsecret.txt", "/download/../feed.db", "/download/missing.run"):
            with pytest.raises(urllib.error.HTTPError):
                urllib.request.urlopen(base + bad)
        req = urllib.request.Request(base + "/download/scamstop-installer-linux-x86_64.run", method="HEAD")
        r = urllib.request.urlopen(req)
        assert r.headers["Content-Length"] == str(len(blob)) and r.read() == b""
    finally:
        srv.shutdown()


def test_site_template_assets_privacy_and_subscribe(tmp_path):
    import json
    import urllib.error
    import urllib.request
    from scamstop import __version__
    from scamstop.feed_server import Downloads
    d = tmp_path / "dl"
    d.mkdir()
    (d / "scamstop-installer-linux-x86_64.run").write_bytes(b"x" * 3_000_000)
    f = feed(tmp_path, min_networks=1)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(f, False, Downloads(str(d))))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    def status(path):
        try:
            return urllib.request.urlopen(base + path).status
        except urllib.error.HTTPError as e:
            return e.code

    def sub(email, website=""):
        req = urllib.request.Request(base + "/v1/subscribe", json.dumps({"email": email, "website": website}).encode(),
                                     {"Content-Type": "application/json"})
        try:
            r = urllib.request.urlopen(req)
            return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, None

    try:
        page = urllib.request.urlopen(base + "/").read().decode()
        assert __version__ in page and "{{" not in page and "3 MB" in page
        r = urllib.request.urlopen(base + "/assets/panel-dashboard.webp")
        assert r.status == 200 and r.headers["Content-Type"] == "image/webp"
        r = urllib.request.urlopen(base + "/assets/warning-en.wav")
        assert r.status == 200 and r.headers["Content-Type"] == "audio/wav"
        assert status("/assets/..%2Ffeed.db") == 404 and status("/assets/missing.png") == 404
        assert "support@pvnvoice.com" in urllib.request.urlopen(base + "/privacy").read().decode()

        assert sub("Ann@Example.com") == (200, {"ok": True})
        assert "ann@example.com" in f.admin("subscribers")
        assert sub("bot@example.com", website="http://spam") == (200, {"ok": True})
        assert "bot@example.com" not in f.admin("subscribers")
        assert sub("not-an-email")[0] == 400
        for i in range(4):  # 5th valid subscribe from this IP today (the honeypot hit isn't counted)
            assert sub(f"u{i}@example.com")[0] == 200
        assert sub("sixth@example.com")[0] == 429
    finally:
        srv.shutdown()
