import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from scamstop import config
from scamstop.control import Dialog
from scamstop.rules import CallMatcher, normalize
from scamstop.smart import Classifier, LLMJudge, SmartCheck, evaluate

HELD = [(normalize(l.split("\t", 1)[1]), int(l.split("\t", 1)[0]))
        for l in (Path(__file__).parent / "data" / "smart_heldout.txt").read_text().splitlines() if l.strip()]


def test_bundled_model_on_heldout_calls():
    r = evaluate(Classifier.load(), HELD)
    assert r["auc"] >= 0.95                       # never trained on these
    assert r["@0.85"]["false_positives"] == 0     # the default threshold never flags a legit held-out line


def test_obvious_cases():
    c = Classifier.load()
    assert c.score("this is officer brown there is a warrant go buy store cards and do not tell your bank") > 0.9
    assert c.score("hi this is a licensed agent about your medicare advantage options what is your zip code") < 0.2


def test_train_save_load_roundtrip(tmp_path):
    data = [("buy gift cards now officer warrant", 1), ("your medicare plan options zip code", 0)] * 20
    c = Classifier.train(data, epochs=3)
    c.save(tmp_path / "m.npz")
    c2 = Classifier.load(tmp_path / "m.npz")
    assert abs(c.score("buy gift cards") - c2.score("buy gift cards")) < 0.01


class L:
    def __init__(self, cid="c1", side="caller"):
        self.dlg, self.side = Dialog(1, cid, "t", "10.0.0.1"), side


def smart(**over):
    cfg = config.load(None)["smart"]
    cfg.update(over)
    hits = []
    return SmartCheck(cfg, lambda lst, hit, text: hits.append(hit)), hits


SCAM_WORDS = ("this is the social security administration your number was used in a crime "
              "a warrant will be issued unless you cooperate you have to go to the store and buy cards "
              "do not tell anyone at the bank stay on the line with me")


def test_flags_once_and_respects_min_words():
    sc, hits = smart()
    m = CallMatcher([], None)
    sc.observe(L(), m, "this is the social security")          # too few words
    assert hits == []
    m.commit(SCAM_WORDS)
    sc.observe(L(), m, "")
    sc.observe(L(), m, "and more words " * 10)
    assert len(hits) == 1 and hits[0].action == "flag" and hits[0].rule_id == "smart_check"


def test_kill_mode_needs_kill_threshold_and_ignores_victim_side():
    sc, hits = smart(mode="kill", kill_threshold=0.5)
    m = CallMatcher([], None)
    m.commit(SCAM_WORDS)
    sc.observe(L(side="victim"), m, "")
    assert hits == []
    sc.observe(L(), m, "")
    assert hits[0].action == "kill"


class FakeLLM(BaseHTTPRequestHandler):
    verdict = {"scam": True, "confidence": 0.93, "reason": "gift card demand"}

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert body["messages"][0]["role"] == "system"
        out = json.dumps({"choices": [{"message": {"content": "Sure: " + json.dumps(self.verdict)}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def llm_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeLLM)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/v1/chat/completions"


def test_llm_second_opinion_confirms():
    srv, url = llm_server()
    try:
        cfg = config.load(None)["smart"]["llm"]
        cfg.update(enabled=True, url=url)
        sc, hits = smart(llm=cfg)
        m = CallMatcher([], None)
        m.commit(SCAM_WORDS)
        sc.observe(L(), m, "")
        time.sleep(0.5)
        assert len(hits) == 1 and "llm 0.93" in hits[0].matched
    finally:
        srv.shutdown()


def test_llm_saying_no_suppresses_flag():
    srv, url = llm_server()
    FakeLLM.verdict = {"scam": False, "confidence": 0.9, "reason": "insurance sale"}
    try:
        cfg = config.load(None)["smart"]["llm"]
        cfg.update(enabled=True, url=url)
        sc, hits = smart(llm=cfg)
        m = CallMatcher([], None)
        m.commit(SCAM_WORDS)
        sc.observe(L(), m, "")
        time.sleep(0.5)
        assert hits == []
    finally:
        FakeLLM.verdict = {"scam": True, "confidence": 0.93, "reason": "gift card demand"}
        srv.shutdown()


def test_llm_unreachable_falls_back_to_classifier():
    cfg = config.load(None)["smart"]["llm"]
    cfg.update(enabled=True, url="http://127.0.0.1:9/v1/chat/completions", timeout_s=1)
    sc, hits = smart(llm=cfg)
    m = CallMatcher([], None)
    m.commit(SCAM_WORDS)
    sc.observe(L(), m, "")
    time.sleep(1.5)
    assert len(hits) == 1 and "llm unavailable" in hits[0].matched


# ---- continuous, bounded scoring ---------------------------------------------------------------

from scamstop.smart import LLMResponseError, parse_verdict  # noqa: E402

LEGIT = ("hi this is a licensed agent calling about your medicare advantage options what is your zip code "
         "and do you have your red white and blue card handy we can look at plans in your area today ")


def test_later_stronger_evidence_still_escalates_after_a_flag():
    sc, hits = smart(mode="kill", threshold=0.5, kill_threshold=0.999, every_words=5)
    m = CallMatcher([], None)
    m.commit(SCAM_WORDS)
    sc.observe(L(), m, "")
    assert [h.action for h in hits] == ["flag"]
    sc.c["kill_threshold"] = 0.6            # stronger evidence (simulated by a lower bar) arrives later
    m.commit(SCAM_WORDS + " " + SCAM_WORDS)
    sc.observe(L(), m, "")
    assert [h.action for h in hits] == ["flag", "kill"]   # dedup: one flag, then one kill
    m.commit(SCAM_WORDS * 3)
    sc.observe(L(), m, "")
    assert len(hits) == 2


def test_scoring_continues_while_quiet_and_is_bounded():
    sc, hits = smart(every_words=5, max_scores_per_call=3)
    m = CallMatcher([], None)
    for i in range(10):
        m.commit(LEGIT + "more words here please " * i)
        sc.observe(L(), m, "")
    assert sc.counters["smart_scores"] == 3 and sc.counters["smart_score_cap"] > 0 and hits == []


def test_reused_callid_starts_fresh():
    sc, hits = smart()
    m = CallMatcher([], None)
    m.commit(SCAM_WORDS)
    first = L()
    first.t0 = 1
    sc.observe(first, m, "")
    second = L()
    second.t0 = 2                          # same Call-ID, a new call
    sc.observe(second, m, "")
    assert len(hits) == 2


class ScriptedLLM:
    """Replaces LLMJudge: answers from a list, can block until released."""
    def __init__(self, answers, gate=None):
        self.answers, self.gate, self.seen = list(answers), gate, []

    def judge(self, caller, victim=""):
        self.seen.append((caller, victim))
        if self.gate:
            self.gate.wait(5)
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a


def llm_smart(answers, gate=None, **llm):
    cfg = config.load(None)["smart"]
    cfg["llm"].update(enabled=True, url="http://unused", reask_words=10, **llm)
    cfg["every_words"] = 5
    hits = []
    sc = SmartCheck(cfg, lambda lst, hit, text: hits.append(hit))
    sc.llm = ScriptedLLM(answers, gate)
    return sc, hits


def wait_idle(sc):
    for _ in range(100):
        if sc.outstanding == 0:
            return
        time.sleep(0.02)


def test_negative_verdict_does_not_end_evaluation():
    sc, hits = llm_smart([{"scam": False, "confidence": 0.9, "reason": "sale"},
                          {"scam": True, "confidence": 0.95, "reason": "gift cards"}])
    m = CallMatcher([], None)
    m.commit(SCAM_WORDS)
    sc.observe(L(), m, "")
    wait_idle(sc)
    assert hits == []
    m.commit(SCAM_WORDS + " and now go to the store and buy the cards")
    sc.observe(L(), m, "")
    wait_idle(sc)
    assert len(hits) == 1 and "llm 0.95" in hits[0].matched and len(sc.llm.seen) == 2


def test_llm_gets_both_speakers_labelled():
    sc, hits = llm_smart([{"scam": True, "confidence": 0.95, "reason": "x"}])
    m, vm = CallMatcher([], None), CallMatcher([], None, side="victim")
    vm.commit("wait you want me to buy google play cards")
    sc.observe(L(side="victim"), vm, "")
    m.commit(SCAM_WORDS)
    sc.observe(L(), m, "")
    wait_idle(sc)
    caller, victim = sc.llm.seen[0]
    assert "social security" in caller and victim.startswith("wait you want me")
    from scamstop.smart import speaker_transcript
    t = speaker_transcript(caller, victim)
    assert t.startswith("CALLER:\n") and "\n\nCALLED PARTY:\n" in t


def test_delayed_verdict_for_an_ended_call_is_dropped():
    gate = threading.Event()
    sc, hits = llm_smart([{"scam": True, "confidence": 0.99, "reason": "x"}], gate)
    m = CallMatcher([], None)
    m.commit(SCAM_WORDS)
    sc.observe(L(), m, "")
    sc.forget("c1")                         # the call ended while the model was thinking
    gate.set()
    wait_idle(sc)
    assert hits == [] and sc.counters["smart_llm_stale"] == 1


def test_delayed_verdict_for_a_reused_callid_is_dropped():
    gate = threading.Event()
    sc, hits = llm_smart([{"scam": True, "confidence": 0.99, "reason": "x"}], gate)
    sc.is_live = lambda cid, gen: gen[2] == 2   # the daemon now knows only the new call
    m = CallMatcher([], None)
    m.commit(SCAM_WORDS)
    old = L()
    old.t0 = 1
    sc.observe(old, m, "")
    gate.set()
    wait_idle(sc)
    assert hits == [] and sc.counters["smart_llm_stale"] == 1


def test_llm_work_is_bounded():
    gate = threading.Event()
    sc, hits = llm_smart([{"scam": False, "confidence": 0.5, "reason": ""}] * 10, gate,
                         max_outstanding=2, max_concurrent=2)
    m = CallMatcher([], None)
    m.commit(SCAM_WORDS)
    for i in range(5):
        sc.observe(L(cid=f"c{i}"), m, "")
    assert sc.outstanding == 2 and sc.counters["smart_llm_requests"] == 2
    assert sc.counters["smart_llm_skipped_overload"] == 3
    assert len(hits) == 3 and all("llm overloaded" in h.matched for h in hits)   # visible fallback
    gate.set()
    wait_idle(sc)


def test_per_call_llm_questions_are_bounded():
    sc, hits = llm_smart([{"scam": False, "confidence": 0.9, "reason": ""}] * 10, max_per_call=2)
    m = CallMatcher([], None)
    for i in range(6):
        m.commit(SCAM_WORDS + " more" * (15 * i))
        sc.observe(L(), m, "")
        wait_idle(sc)
    assert len(sc.llm.seen) == 2


def test_invalid_llm_reply_is_rejected_and_falls_back_visibly():
    sc, hits = llm_smart([LLMResponseError("scam must be true or false")])
    m = CallMatcher([], None)
    m.commit(SCAM_WORDS)
    sc.observe(L(), m, "")
    wait_idle(sc)
    assert sc.counters["smart_llm_invalid"] == 1 and "llm unavailable" in hits[0].matched


import pytest  # noqa: E402


@pytest.mark.parametrize("content", [
    '{"scam": "true", "confidence": 0.9}', '{"scam": 1, "confidence": 0.9}', '{"scam": true, "confidence": "0.9"}',
    '{"scam": true, "confidence": true}', '{"scam": true, "confidence": 1.5}', '{"scam": true, "confidence": NaN}',
    '{"scam": true}', '["scam", true]', 'yes it is a scam', '{"scam": true, "confidence": 0.9} {"scam": false}',
    '{"scam": true, "confidence": 0.9, "reason": 5}', None, 42,
])
def test_parse_verdict_rejects_wrong_types(content):
    with pytest.raises(LLMResponseError):
        parse_verdict(content)


def test_parse_verdict_accepts_valid_replies():
    assert parse_verdict('{"scam": false, "confidence": 0, "reason": "ok"}')["confidence"] == 0.0
    assert parse_verdict('```json\n{"scam": true, "confidence": 0.8, "reason": "x"}\n```')["scam"] is True
    assert parse_verdict('Sure: {"scam": true, "confidence": 1}')["confidence"] == 1.0
