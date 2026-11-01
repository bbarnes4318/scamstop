"""Drive Daemon.worker with a fake recognizer to exercise the live loop without audio."""
import queue
import threading
import time

import fakeredis
import numpy as np

from scamstop import config
from scamstop.control import Dialog
from scamstop.daemon import Daemon, Enforcer, Stats
from scamstop.platforms.sip import SipPlatform
from scamstop.rules import CampaignGate, load_rules
from scamstop.store import Store


class FakeStream:
    def __init__(self, script):
        self.script, self.i, self.fed = script, 0, 0

    def accept_waveform(self, sr, x):  # sherpa: a stream method, not the recognizer's
        self.fed += len(x)


class FakeRec:
    """Each accepted chunk reveals one more utterance; every chunk is an endpoint."""
    def __init__(self, script):
        self.script = script

    def create_stream(self):
        return FakeStream(self.script)

    def is_ready(self, s):
        return False

    def decode_streams(self, ss):
        pass

    def get_result(self, s):
        return s.script[s.i] if s.i < len(s.script) else ""

    def is_endpoint(self, s):
        return True

    def reset(self, s):
        s.i += 1


class FakeProxy:
    def __init__(self):
        self.ended = []

    def end(self, d):
        self.ended.append(d.callid)


class FakeListener:
    def __init__(self, cid, side="caller"):
        self.dlg, self.t0, self.stop = Dialog(1, cid, "t", "10.0.0.1"), 0, False
        self.side, self.key = side, (cid, side)


def make(script, tmp_path, victim_script=None):
    cfg = config.load(None)
    cfg["dry_run"] = False
    for k in ("kill_log", "flag_log", "review_log", "watch_log"):
        cfg["evidence"][k] = str(tmp_path / f"{k}.jsonl")
    d = Daemon.__new__(Daemon)
    d.cfg, d.stats, d.watch, d.on_text = cfg, Stats(), None, None
    d.listeners, d.killed, d.klock = {}, set(), threading.Lock()
    d.terminated, d.evidence_by_call = set(), {}
    d.rules, d.gate = load_rules(["en_scams", "en_victim"]), CampaignGate()
    d.proxy = FakeProxy()
    d.enf = Enforcer(cfg, SipPlatform(d.proxy, None), Store(fakeredis.FakeRedis(decode_responses=True)), d.stats)
    q = queue.Queue()
    rec = FakeRec(script)
    if victim_script is not None:
        rec = SideRec({"caller": script, "victim": victim_script}, ["caller", "victim"])
    threading.Thread(target=d.worker, args=(rec, q), daemon=True).start()
    return d, q


class SideRec(FakeRec):
    """Gives each side its own script; streams are created in the order sides first send audio."""
    def __init__(self, scripts, order):
        self.scripts, self.order = scripts, list(order)

    def create_stream(self):
        side = self.order.pop(0)
        return FakeStream(self.scripts[side])


def test_worker_kills_scam_call(tmp_path):
    d, q = make(["hello this is the", "internal revenue service", "you owe back taxes"], tmp_path)
    lst = FakeListener("call1@74.81.33.58")
    chunk = np.zeros(8000, np.float32)
    for _ in range(4):
        q.put((lst, chunk))
        time.sleep(0.05)
    q.put((lst, None))
    time.sleep(0.2)
    assert d.proxy.ended == ["call1@74.81.33.58"] and lst.stop
    assert "irs_threat" in (tmp_path / "kill_log.jsonl").read_text()
    assert d.stats.v["errors"] == 0


def test_worker_leaves_legit_call(tmp_path):
    d, q = make(["hi this is a licensed agent", "about your medicare plan options"], tmp_path)
    lst = FakeListener("call2@1.2.3.4")
    for _ in range(3):
        q.put((lst, np.zeros(8000, np.float32)))
        time.sleep(0.05)
    q.put((lst, None))
    time.sleep(0.2)
    assert d.proxy.ended == [] and not lst.stop and d.stats.v["errors"] == 0


def test_victim_side_kills_call_once(tmp_path):
    d, q = make(["hi this is the benefits line calling back"], tmp_path,
                victim_script=["wait", "you want me to go buy google play cards", "how many cards"])
    caller, victim = FakeListener("v1@74.81.33.58", "caller"), FakeListener("v1@74.81.33.58", "victim")
    d.listeners["v1@74.81.33.58"] = [caller, victim]
    chunk = np.zeros(8000, np.float32)
    q.put((caller, chunk))   # caller stream is created first, then victim
    time.sleep(0.05)
    for _ in range(4):
        q.put((victim, chunk))
        time.sleep(0.05)
    time.sleep(0.2)
    assert d.proxy.ended == ["v1@74.81.33.58"]                     # one hang-up, not two
    assert caller.stop and victim.stop                              # both forks stopped
    log = (tmp_path / "kill_log.jsonl").read_text()
    assert '"side": "victim"' in log and "victim_gift_cards" in log
    assert log.count("\n") == 1                                    # "how many cards" didn't trigger a second kill
