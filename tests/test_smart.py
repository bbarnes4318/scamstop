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
