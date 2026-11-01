"""Smart check: scores the last ~30 seconds of a call for scam intent.

Layer 1, built in: a logistic-regression classifier over hashed word and character
n-grams. Character n-grams keep working when the speech model mishears a word.
Pure numpy, well under a millisecond per score, no downloads.

Layer 2, optional: a local LLM (Ollama, llama.cpp server, vLLM: anything with an
OpenAI-compatible /v1/chat/completions) gives a second opinion, only on windows
the classifier already finds suspicious.

Ships flag-only. The panel tracks how often its flags were right; it can be set to
hang up only after it has proven itself on your own calls.

Scoring is continuous and bounded: a call keeps being re-scored every `every_words` new
words (up to `max_scores_per_call`) after a flag or a negative/uncertain LLM verdict, so
stronger evidence later in the call can still escalate it. Notifications are deduplicated
(one flag, one kill per call) without stopping evaluation.
"""
from __future__ import annotations

import json
import math
import os
import re
import threading
import time
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

DIM = 1 << 18
BUNDLED_MODEL = Path(__file__).parent / "models" / "smart-en.npz"
_WORD = re.compile(r"[a-z']+")


def features(text: str) -> tuple[np.ndarray, np.ndarray]:
    """Hashed, log-scaled, L2-normalized word 1-2 grams + char 3-5 grams."""
    words = _WORD.findall(text.lower())
    grams = [f"w:{w}" for w in words] + [f"b:{a}_{b}" for a, b in zip(words, words[1:])]
    for w in words:
        p = f" {w} "
        for n in (3, 4, 5):
            grams += [f"c:{p[i:i + n]}" for i in range(max(1, len(p) - n + 1))]
    if not grams:
        return np.zeros(0, np.int64), np.zeros(0, np.float32)
    idx = np.fromiter((zlib.crc32(g.encode()) & (DIM - 1) for g in grams), np.int64, len(grams))
    uniq, counts = np.unique(idx, return_counts=True)
    val = (1 + np.log(counts)).astype(np.float32)
    return uniq, val / np.linalg.norm(val)


class Classifier:
    def __init__(self, w: np.ndarray, b: float):
        self.w, self.b = w, b

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Classifier":
        z = np.load(path or BUNDLED_MODEL)
        w = np.zeros(DIM, np.float32)
        w[z["idx"]] = z["val"].astype(np.float32)
        return cls(w, float(z["b"]))

    def save(self, path: str | os.PathLike) -> None:
        nz = np.flatnonzero(np.abs(self.w) > 1e-4)
        os.makedirs(os.path.dirname(str(path)) or ".", exist_ok=True)
        np.savez_compressed(path, idx=nz.astype(np.int32), val=self.w[nz].astype(np.float16), b=np.float32(self.b))

    def score(self, text: str) -> float:
        idx, val = features(text)
        z = float(self.w[idx] @ val) + self.b if len(idx) else self.b
        return 1 / (1 + math.exp(-max(-30, min(30, z))))

    @classmethod
    def train(cls, data: list[tuple[str, int]], epochs: int = 12, lr: float = 0.5, l2: float = 1e-6,
              seed: int = 1) -> "Classifier":
        rng = np.random.default_rng(seed)
        feats = [features(t) for t, _ in data]
        y = np.array([l for _, l in data], np.float32)
        w, b = np.zeros(DIM, np.float32), 0.0
        for ep in range(epochs):
            step = lr / (1 + ep * 0.5)
            for i in rng.permutation(len(data)):
                idx, val = feats[i]
                z = float(w[idx] @ val) + b
                g = 1 / (1 + math.exp(-max(-30, min(30, z)))) - y[i]
                w[idx] -= step * (g * val + l2 * w[idx])
                b -= step * g * 0.1
        return cls(w, b)


def evaluate(clf: Classifier, data: list[tuple[str, int]], thresholds=(0.5, 0.7, 0.8, 0.85, 0.9, 0.95)) -> dict:
    scores = np.array([clf.score(t) for t, _ in data])
    y = np.array([l for _, l in data])
    out = {"n": len(data), "scams": int(y.sum())}
    # ROC AUC by rank
    order = scores.argsort()
    ranks = np.empty(len(scores))
    ranks[order] = np.arange(1, len(scores) + 1)
    pos = y == 1
    if pos.sum() and (~pos).sum():
        out["auc"] = round(float((ranks[pos].sum() - pos.sum() * (pos.sum() + 1) / 2) / (pos.sum() * (~pos).sum())), 4)
    for t in thresholds:
        pred = scores >= t
        tp, fp, fn = int((pred & pos).sum()), int((pred & ~pos).sum()), int((~pred & pos).sum())
        out[f"@{t}"] = {"precision": round(tp / (tp + fp), 3) if tp + fp else None,
                        "recall": round(tp / (tp + fn), 3) if tp + fn else None, "false_positives": fp}
    return out


LLM_PROMPT = """You review live phone call transcripts for a phone carrier's fraud team.
The transcript is speech-recognition output (lowercase, no punctuation, may contain misheard words).
It has two labeled parts: CALLER is the party that placed the call (the dialer side, the one that may be a scammer);
CALLED PARTY is the person who answered. Judge whether the CALLER is running a scam; the called party's words are evidence.
Legitimate calls on this network include insurance sales (Medicare, final expense, ACA, auto), legal intake, appointment reminders,
booked customer support, surveys and customer service.
Scams include: government/police/IRS/SSA impersonation and threats, tech support, fake bank fraud departments, fake orders and refunds,
demands for gift cards, crypto, wire transfers or cash pickup, grandparent/bail stories, prize or grant fees, utility shutoff threats,
and coaching the called party to lie or keep secrets.
Reply with JSON only: {"scam": true or false, "confidence": 0.0 to 1.0, "reason": "under 15 words"}"""


class LLMResponseError(ValueError):
    """The model server answered something that is not a valid verdict."""


def parse_verdict(content) -> dict:
    """Strictly validate the model's reply: exactly one JSON object (surrounding prose or a
    ```json fence is tolerated) with a real boolean "scam" and a numeric "confidence" in
    [0, 1]. "true" as a string, 1 for true, or a confidence of "0.9" are all rejected."""
    if not isinstance(content, str) or len(content) > 4000:
        raise LLMResponseError("reply is not text")
    t = content.strip()
    fence = re.fullmatch(r"```(?:json)?\s*(\{.*\})\s*```", t, re.S)
    if fence:
        t = fence.group(1)
    start = t.find("{")
    if start < 0:
        raise LLMResponseError("reply has no JSON object")
    try:
        v, end = json.JSONDecoder().raw_decode(t, start)
    except ValueError:
        raise LLMResponseError("reply is not JSON") from None
    if "{" in t[end:]:
        raise LLMResponseError("reply has more than one JSON object")
    if not isinstance(v, dict):
        raise LLMResponseError("reply is not a JSON object")
    scam, conf, reason = v.get("scam"), v.get("confidence"), v.get("reason", "")
    if not isinstance(scam, bool):
        raise LLMResponseError("scam must be true or false")
    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not math.isfinite(conf) or not 0 <= conf <= 1:
        raise LLMResponseError("confidence must be a number from 0 to 1")
    if not isinstance(reason, str):
        raise LLMResponseError("reason must be text")
    return {"scam": scam, "confidence": float(conf), "reason": " ".join(reason.split())[:120]}


def parse_response(body: bytes) -> dict:
    try:
        j = json.loads(body)
    except ValueError:
        raise LLMResponseError("server reply is not JSON") from None
    if not isinstance(j, dict) or not isinstance(j.get("choices"), list) or not j["choices"]:
        raise LLMResponseError("server reply has no choices")
    msg = j["choices"][0].get("message") if isinstance(j["choices"][0], dict) else None
    if not isinstance(msg, dict):
        raise LLMResponseError("server reply has no message")
    return parse_verdict(msg.get("content"))


def speaker_transcript(caller: str, victim: str = "", limit: int = 1500) -> str:
    """Both sides, explicitly labeled. The caller side is never mixed with the called party's."""
    out = f"CALLER:\n{caller[-limit:]}"
    if victim:
        out += f"\n\nCALLED PARTY:\n{victim[-(limit // 2):]}"
    return out


class LLMJudge:
    def __init__(self, cfg: dict):
        self.url, self.model = cfg["url"], cfg["model"]
        self.timeout = float(cfg.get("timeout_s", 6))
        self.key = cfg.get("api_key") or os.environ.get("SCAMSTOP_LLM_KEY", "")
        self.sem = threading.Semaphore(int(cfg.get("max_concurrent", 4)))

    def judge(self, transcript: str, victim: str = "") -> dict:
        body = {"model": self.model, "temperature": 0, "max_tokens": 80,
                "messages": [{"role": "system", "content": LLM_PROMPT},
                             {"role": "user", "content": speaker_transcript(transcript, victim)}]}
        h = {"Content-Type": "application/json"}
        if self.key:
            h["Authorization"] = f"Bearer {self.key}"
        with self.sem:
            req = urllib.request.Request(self.url, json.dumps(body).encode(), h)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = r.read(65536)
        return parse_response(data)


LEVELS = {"none": 0, "flag": 1, "kill": 2}


@dataclass
class CallState:
    gen: tuple
    last: int = 0                 # words scored at
    scores: int = 0
    level: str = "none"           # strongest notification sent so far
    best: float = 0.0
    llm_outstanding: bool = False
    llm_asked: int = 0
    llm_last: int = 0             # words when the LLM was last asked
    victim: str = ""
    ended: bool = False
    verdicts: list = field(default_factory=list)


class SmartCheck:
    """Per-call scoring. on_hit(listener, Hit, text) is called at most once per level
    (flag, then kill) per call; scoring itself continues for the life of the call."""

    def __init__(self, cfg: dict, on_hit, is_live=None):
        self.c = cfg
        self.clf = Classifier.load(cfg.get("model") or None)
        llm = cfg.get("llm", {}) or {}
        self.llm = LLMJudge(llm) if llm.get("enabled") else None
        self.pool = (ThreadPoolExecutor(max_workers=max(1, int(llm.get("max_concurrent", 4))),
                                        thread_name_prefix="scamstop-llm") if self.llm else None)
        self.max_outstanding = max(1, int(llm.get("max_outstanding", 16)))
        self.outstanding = 0
        self.on_hit = on_hit
        self.is_live = is_live            # (callid, gen) -> bool: is this exact call still up?
        self.state: dict[str, CallState] = {}
        self.lock = threading.Lock()
        self.counters = {"smart_scores": 0, "smart_llm_requests": 0, "smart_llm_errors": 0,
                         "smart_llm_invalid": 0, "smart_llm_skipped_overload": 0, "smart_llm_stale": 0,
                         "smart_score_cap": 0}

    def _inc(self, k, n=1):
        with self.lock:
            self.counters[k] = self.counters.get(k, 0) + n

    def window(self, text: str) -> str:
        return " ".join(text.split()[-int(self.c["window_words"]):])

    @staticmethod
    def generation(lst) -> tuple:
        d = lst.dlg
        return (d.callid, str(d.id), getattr(lst, "t0", 0))

    def _state(self, lst) -> CallState:
        gen = self.generation(lst)
        st = self.state.get(lst.dlg.callid)
        if st is None or st.gen != gen:  # first sight, or a reused Call-ID: start over
            st = CallState(gen)
            self.state[lst.dlg.callid] = st
        return st

    def observe(self, lst, matcher, partial: str) -> None:
        text = matcher.text(partial)
        if lst.side == "victim":
            with self.lock:
                st = self._state(lst)
                st.victim = " ".join(text.split()[-int(self.c["window_words"]):])
            return
        if lst.side != "caller":
            return
        n = len(text.split())
        with self.lock:
            st = self._state(lst)
            if st.ended or st.level == "kill" or n < self.c["min_words"] or n - st.last < self.c["every_words"]:
                return
            if st.scores >= int(self.c.get("max_scores_per_call", 200)):
                self.counters["smart_score_cap"] += 1
                return
            st.last, st.scores = n, st.scores + 1
            self.counters["smart_scores"] += 1
            victim = st.victim
        win = self.window(text)
        p = self.clf.score(win)
        with self.lock:
            st.best = max(st.best, p)
        if self.llm:
            return self._maybe_ask(lst, st, win, victim, p, n)
        self._decide(lst, st, p, f"score {p:.2f}", win)

    def _maybe_ask(self, lst, st: CallState, win: str, victim: str, p: float, n: int) -> None:
        lc = self.c["llm"]
        if p < lc["ask_above"]:
            return
        ask = overloaded = False
        with self.lock:
            if st.llm_outstanding:
                return
            if st.llm_asked >= int(lc.get("max_per_call", 4)) or (st.llm_asked and n - st.llm_last < int(lc.get("reask_words", 40))):
                pass  # bounded: no more questions for this call right now
            elif self.outstanding >= self.max_outstanding:
                self.counters["smart_llm_skipped_overload"] += 1
                overloaded = True
            else:
                ask = True
                st.llm_outstanding, st.llm_asked, st.llm_last = True, st.llm_asked + 1, n
                self.outstanding += 1
                self.counters["smart_llm_requests"] += 1
        if ask:
            self.pool.submit(self._ask_llm, lst, st, win, victim, p)
        elif overloaded and p >= self.c["threshold"]:
            # the second opinion is overloaded: fall back to the classifier alone, visibly
            self._decide(lst, st, p, f"score {p:.2f} (llm overloaded)", win, fallback=True)

    def _ask_llm(self, lst, st: CallState, win: str, victim: str, p: float) -> None:
        try:
            try:
                v = self.llm.judge(win, victim)
            except LLMResponseError as e:
                self._inc("smart_llm_invalid")
                v = {"error": f"invalid llm reply: {e}"}
            except Exception as e:
                self._inc("smart_llm_errors")
                v = {"error": f"llm error: {e}"[:120]}
            if not self._current(lst, st):
                self._inc("smart_llm_stale")  # the call ended or its Call-ID now names another call
                return
            with self.lock:
                st.verdicts.append(v)
            if "error" in v:
                if p >= self.c["threshold"]:  # LLM unavailable: fall back to the classifier alone
                    self._decide(lst, st, p, f"score {p:.2f} (llm unavailable)", win, fallback=True)
                return
            if v["scam"] and v["confidence"] >= self.c["llm"]["min_confidence"]:
                self._decide(lst, st, p, f"score {p:.2f}, llm {v['confidence']:.2f}: {v['reason']}", win, llm_ok=True)
            # negative or uncertain: nothing now; scoring continues and may ask again later
        finally:
            with self.lock:
                st.llm_outstanding = False
                self.outstanding -= 1

    def _current(self, lst, st: CallState) -> bool:
        with self.lock:
            if st.ended or self.state.get(lst.dlg.callid) is not st:
                return False
        return self.is_live(lst.dlg.callid, st.gen) if self.is_live else True

    def _decide(self, lst, st: CallState, p: float, why: str, win: str, llm_ok: bool = False,
                fallback: bool = False) -> None:
        from .rules import Hit
        if self.llm and not (llm_ok or fallback):
            return  # with a second opinion configured, the classifier alone only decides as a fallback
        level = "kill" if self.c["mode"] == "kill" and p >= self.c["kill_threshold"] else (
            "flag" if p >= self.c["threshold"] or llm_ok else "none")
        with self.lock:
            if st.ended or LEVELS[level] <= LEVELS[st.level]:
                return  # already notified at this level: keep evaluating, don't repeat
            st.level = level
        self.on_hit(lst, Hit("smart_check", "Smart check", level, why, "smart",
                             "strong" if level == "kill" else "context", "", "caller"), win)

    def forget(self, callid: str) -> None:
        with self.lock:
            st = self.state.pop(callid, None)
            if st:
                st.ended = True

    def active(self) -> int:
        with self.lock:
            return len(self.state)
