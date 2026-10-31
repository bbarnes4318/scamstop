import time

import fakeredis
import numpy as np

from scamstop import audio, config, rtpengine
from scamstop.control import Dialog
from scamstop.daemon import Enforcer, Stats
from scamstop.platforms.sip import SipPlatform
from scamstop.rules import Hit
from scamstop.store import Store


def store():
    return Store(fakeredis.FakeRedis(decode_responses=True))


def test_strikes_persist_and_count_distinct_calls():
    s = store()
    assert s.add_strike("host", "1.2.3.4", "a", 60) == 1
    assert s.add_strike("host", "1.2.3.4", "a", 60) == 1
    assert s.add_strike("host", "1.2.3.4", "b", 60) == 2


def test_block_ttl_and_sweep():
    s = store()
    s.block("media", "9.9.9.9", ttl_s=1, reason="t")
    s.block("media", "8.8.8.8", ttl_s=0)
    assert s.is_blocked("media", "9.9.9.9")
    s.r.zadd("sbc:block:media:exp", {"9.9.9.9": time.time() - 1})
    assert s.sweep() == 1
    assert not s.is_blocked("media", "9.9.9.9") and s.is_blocked("media", "8.8.8.8")


def test_customer_cache():
    s = store()
    s.r.set("sbc:cust:5.5.5.5", 1)
    assert s.is_customer("5.5.5.5") and not s.is_customer("6.6.6.6")
    assert Store(s.r, customer_key=None).is_customer("anything")


class FakeProxy:
    def __init__(self):
        self.ended = []

    def end(self, d):
        self.ended.append(d.callid)


def enforcer(dry=False, **centers):
    cfg = config.load(None)
    cfg["dry_run"] = dry
    cfg["centers"].update(centers)
    for k in ("kill_log", "flag_log"):
        cfg["evidence"][k] = None
    p, s = FakeProxy(), store()
    return Enforcer(cfg, SipPlatform(p, None), s, Stats()), p, s


def dlg(cid, ip="10.0.0.1"):
    return Dialog(1, cid, "tag", ip)


KILL = Hit("gift_card_payment", "Gift card", "kill", "google play cards")


def test_two_kills_block_center():
    e, p, s = enforcer()
    e.handle(dlg("x1@74.81.33.58"), KILL, "t")
    assert not s.is_blocked("host", "74.81.33.58")
    e.handle(dlg("x2@74.81.33.58"), KILL, "t")
    assert p.ended == ["x1@74.81.33.58", "x2@74.81.33.58"]
    assert s.is_blocked("host", "74.81.33.58")


def test_dry_run_kills_nothing():
    e, p, s = enforcer(dry=True)
    e.handle(dlg("x1@74.81.33.58"), KILL, "t")
    e.handle(dlg("x2@74.81.33.58"), KILL, "t")
    assert p.ended == [] and not s.is_blocked("host", "74.81.33.58")


def test_never_blocks_the_customer_itself():
    e, p, s = enforcer(strategies=["source_ip"])
    e.handle(dlg("a", "10.0.0.1"), KILL, "t")
    e.handle(dlg("b", "10.0.0.1"), KILL, "t")
    assert p.ended == ["a", "b"] and not s.is_blocked("src", "10.0.0.1")


def test_flag_never_hangs_up():
    e, p, s = enforcer()
    e.handle(dlg("x@1.1.1.1"), Hit("suspicious_charge", "s", "flag", "m"), "t")
    assert p.ended == []


def test_g711_roundtrip_values():
    assert audio.ULAW[0xFF] == 0 and audio.ULAW[0x00] == -32124
    assert audio.ALAW[0xD5] == 8 and audio.ALAW[0x55] == -8
    up = audio.upsample_8k_16k(np.array([0, 100, 200], np.int16))
    assert list(up) == [0, 50, 100, 150, 200, 200]


def test_rtp_payload_with_csrc_and_ext():
    hdr = bytes([0x80 | 0x10 | 1, 0]) + b"\0" * 10 + b"\0" * 4 + b"\xbe\xde\x00\x01" + b"\0" * 4
    assert audio.rtp_payload(hdr + b"\x01\x02") == (0, b"\x01\x02")
    assert audio.rtp_payload(b"\x00" * 20) is None


def test_bencode_roundtrip():
    msg = {"command": "query", "call-id": "abc", "n": 3, "l": ["x"]}
    assert rtpengine.bdecode(rtpengine.bencode(msg))[0] == msg


class FakeRtp:
    def __init__(self, ms=1000, fail=False):
        self.ms, self.fail, self.played = ms, fail, []

    def play(self, callid, tag, file):
        if self.fail:
            raise RuntimeError("no transcoding")
        self.played.append(tag)
        return self.ms

    def other_tag(self, callid, tag):
        return "victim-from-rtpengine"

    def media_ip(self, *a):
        return None


def warn_enforcer(mode, rtp, **warn):
    e, p, s = enforcer()
    e.platform.rtp = rtp
    e.cfg["warn"].update(mode=mode, max_wait_s=3, **warn)
    return e, p, s


def test_warn_then_hangup_waits_for_warning():
    rtp = FakeRtp(ms=200)
    e, p, s = warn_enforcer("warn_then_hangup", rtp)
    d = Dialog(1, "w1@9.9.9.9", "scammer", "10.0.0.1", callee_tag="victim")
    e.handle(d, KILL, "t")
    assert rtp.played == ["victim"] and p.ended == []   # warning first
    time.sleep(0.9)
    assert p.ended == ["w1@9.9.9.9"]                     # then the hang-up


def test_warn_only_never_hangs_up_but_still_strikes():
    rtp = FakeRtp()
    e, p, s = warn_enforcer("warn_only", rtp)
    e.handle(Dialog(1, "a@9.9.9.9", "s", "10.0.0.1", callee_tag="v"), KILL, "t")
    e.handle(Dialog(1, "b@9.9.9.9", "s", "10.0.0.1", callee_tag="v"), KILL, "t")
    time.sleep(0.2)
    assert p.ended == [] and s.is_blocked("host", "9.9.9.9")


def test_warning_failure_falls_back_to_immediate_hangup():
    e, p, s = warn_enforcer("warn_then_hangup", FakeRtp(fail=True))
    e.handle(Dialog(1, "f@9.9.9.9", "s", "10.0.0.1", callee_tag="v"), KILL, "t")
    assert p.ended == ["f@9.9.9.9"]


def test_victim_tag_from_rtpengine_and_play_to_both():
    rtp = FakeRtp(ms=100)
    e, p, s = warn_enforcer("warn_then_hangup", rtp, play_to="both")
    e.handle(Dialog(1, "x@9.9.9.9", "scammer", "10.0.0.1"), KILL, "t")
    assert rtp.played == ["victim-from-rtpengine", "scammer"]


def test_mode_off_hangs_up_without_warning():
    rtp = FakeRtp()
    e, p, s = warn_enforcer("off", rtp)
    e.handle(Dialog(1, "o@9.9.9.9", "s", "10.0.0.1", callee_tag="v"), KILL, "t")
    assert rtp.played == [] and p.ended == ["o@9.9.9.9"]


def test_bundled_warning_installed(tmp_path):
    from scamstop.daemon import ensure_warning_file
    target = tmp_path / "w" / "warning.wav"
    ensure_warning_file(str(target))
    assert target.read_bytes()[:4] == b"RIFF"
