import subprocess, shutil, pytest

from scamstop import block603
from scamstop.control import Dialog


def test_reason_header_format():
    g = {"redress_tel": "(904) 512-8487", "location": "LN"}
    assert block603.reason(g) == 'SIP;cause=603;text="v=analytics1;tel=+19045128487";location=LN'
    g = {"redress_url": "https://pvnvoice.com/unblock", "redress_email": "a@b.co", "redress_tel": "+442071234567"}
    assert block603.reason(g) == ('SIP;cause=603;text="v=analytics1;url=https://pvnvoice.com/unblock;'
                                  'email=a@b.co;tel=+442071234567";location=TN')
    assert block603.problems(g) == []


def test_problems():
    assert block603.problems({})                       # no contact at all
    assert block603.problems({"redress_url": "http://x.com"})
    assert block603.problems({"redress_tel": "12"})
    assert block603.problems({"redress_tel": "9045128487", "location": "XX"})
    assert not block603.problems({"redress_tel": "1-904-512-8487"})


def test_fill_escapes_for_script_strings():
    out = block603.fill('append_to_reply("Reason: SCAMSTOP_REASON\\r\\n");', {"redress_tel": "9045128487", "location": "TN"})
    assert out == 'append_to_reply("Reason: SIP;cause=603;text=\\"v=analytics1;tel=+19045128487\\";location=TN\\r\\n");'


def test_snippets_have_no_403_for_analytics_blocks():
    from scamstop.ui import SNIPPETS
    for path in SNIPPETS.values():
        text = path.read_text()
        assert 'Forbidden' not in text
        assert text.count(block603.TOKEN) == 5
        assert '603' in text and 'Network Blocked' in text
        # destination (do-not-call) blocks are not analytics-based and keep 403
        assert 'Destination Not Permitted' in text


@pytest.mark.skipif(not shutil.which("kamailio"), reason="kamailio not installed")
def test_kamailio_snippet_parses(tmp_path):
    from scamstop.ui import SNIPPETS
    body = block603.fill(SNIPPETS["kamailio"].read_text(), {"redress_tel": "9045128487"})
    cfg = tmp_path / "k.cfg"
    cfg.write_text('#!KAMAILIO\nlisten=udp:127.0.0.1:5199\n' + "".join(
        f'loadmodule "{m}.so"\n' for m in ("tm", "sl", "textops", "pv", "xlog", "ndb_redis", "dialog")) +
        'modparam("ndb_redis", "server", "name=sbc;addr=127.0.0.1;port=6379;db=0")\n'
        'request_route { route(SCAMSTOP); }\n' + body)
    r = subprocess.run(["kamailio", "-c", "-f", str(cfg)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-800:]


class FakeFs:
    name = "freeswitch"; can_end_ringing = True

    def __init__(self):
        from scamstop.platforms.freeswitch import FreeswitchPlatform
        self.cmds = []
        self.p = FreeswitchPlatform({"host": "x", "port": 1, "password": "p"})
        self.p.api = self.cmds.append


def test_freeswitch_reject_sends_603_with_reason():
    f = FakeFs()
    d = Dialog(id="u-1", callid="c", caller_tag="", caller_ip="", bind_addr="", from_uri="", to_uri="", state="early")
    f.p.reject(d, block603.reason({"redress_tel": "9045128487"}))
    assert f.cmds[-1] == "uuid_kill u-1 CALL_REJECTED"
    assert 'uuid_setvar u-1 sip_reason SIP;cause=603;text="v=analytics1;tel=+19045128487";location=TN' in f.cmds
    assert "uuid_setvar u-1 sip_603plus_passthrough true" in f.cmds


def test_asterisk_reject_never_sends_rejected_cause():
    from scamstop.platforms.asterisk import AsteriskPlatform
    calls = []
    a = AsteriskPlatform.__new__(AsteriskPlatform)
    a.req = lambda method, path, **kw: calls.append((method, path, kw))
    d = Dialog(id="ch1", callid="c", caller_tag="", caller_ip="", bind_addr="", from_uri="", to_uri="", state="early")
    a.reject(d, "x")
    assert calls == [("DELETE", "/channels/ch1", {"reason": "normal"})]
