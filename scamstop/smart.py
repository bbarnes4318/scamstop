"""Smart check: scores the last ~30 seconds of a call for scam intent.

Layer 1, built in: a logistic-regression classifier over hashed word and character
n-grams. Character n-grams keep working when the speech model mishears a word.
Pure numpy, well under a millisecond per score, no downloads.

Layer 2, optional: a local LLM (Ollama, llama.cpp server, vLLM: anything with an
OpenAI-compatible /v1/chat/completions) gives a second opinion, only on windows
the classifier already finds suspicious.

Ships flag-only. The panel tracks how often its flags were right; it can be set to
hang up only after it has proven itself on your own calls.
"""
from __future__ import annotations

import json
import math
import os
import re
import threading
import urllib.request
import zlib
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
The transcript is speech-recognition output from the CALLER's side (lowercase, no punctuation, may contain misheard words).
Legitimate calls on this network include insurance sales (Medicare, final expense, ACA, auto), legal intake, appointment reminders, surveys and customer service.
Scams include: government/police/IRS/SSA impersonation and threats, tech support, fake bank fraud departments, fake orders and refunds,
demands for gift cards, crypto, wire transfers or cash pickup, grandparent/bail stories, prize or grant fees, utility shutoff threats, and coaching the victim to lie or keep secrets.
Reply with JSON only: {"scam": true or false, "confidence": 0.0 to 1.0, "reason": "under 15 words"}"""


class LLMJudge:
    def __init__(self, cfg: dict):
        self.url, self.model = cfg["url"], cfg["model"]
        self.timeout = float(cfg.get("timeout_s", 6))
        self.key = cfg.get("api_key") or os.environ.get("SCAMSTOP_LLM_KEY", "")
        self.sem = threading.Semaphore(int(cfg.get("max_concurrent", 4)))

    def judge(self, transcript: str) -> dict:
        body = {"model": self.model, "temperature": 0, "max_tokens": 80,
                "messages": [{"role": "system", "content": LLM_PROMPT},
                             {"role": "user", "content": f"Transcript:\n{transcript[-1500:]}"}]}
        h = {"Content-Type": "application/json"}
        if self.key:
            h["Authorization"] = f"Bearer {self.key}"
        with self.sem:
            req = urllib.request.Request(self.url, json.dumps(body).encode(), h)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                content = json.loads(r.read())["choices"][0]["message"]["content"]
        m = re.search(r"\{.*\}", content, re.S)
        v = json.loads(m.group(0)) if m else {}
        return {"scam": bool(v.get("scam")), "confidence": float(v.get("confidence") or 0),
                "reason": str(v.get("reason", ""))[:120]}


class SmartCheck:
    """Per-call scoring with throttling. on_hit(listener, Hit, text) is called at most once per call."""

    def __init__(self, cfg: dict, on_hit):
        self.c = cfg
        self.clf = Classifier.load(cfg.get("model") or None)
        self.llm = LLMJudge(cfg["llm"]) if cfg.get("llm", {}).get("enabled") else None
        self.on_hit = on_hit
        self.state: dict[str, dict] = {}  # callid -> {"last": words scored at, "done": bool}
        self.lock = threading.Lock()

    def window(self, text: str) -> str:
        return " ".join(text.split()[-int(self.c["window_words"]):])

    def observe(self, lst, matcher, partial: str) -> None:
        if lst.side != "caller" or matcher.killed:
            return
        text = matcher.text(partial)
        n = len(text.split())
        cid = lst.dlg.callid
        with self.lock:
            st = self.state.setdefault(cid, {"last": 0, "done": False})
            if st["done"] or n < self.c["min_words"] or n - st["last"] < self.c["every_words"]:
                return
            st["last"] = n
        win = self.window(text)
        p = self.clf.score(win)
        if self.llm:
            if p >= self.c["llm"]["ask_above"]:
                with self.lock:
                    st["done"] = True  # one LLM verdict per call
                threading.Thread(target=self._ask_llm, args=(lst, win, p), daemon=True).start()
            return
        if p >= self.c["threshold"]:
            with self.lock:
                st["done"] = True
            self._fire(lst, p, f"score {p:.2f}", win)

    def _ask_llm(self, lst, win: str, p: float) -> None:
        try:
            v = self.llm.judge(win)
        except Exception as e:
            v = {"scam": False, "confidence": 0, "reason": f"llm error: {e}"[:120]}
            if p >= self.c["threshold"]:  # LLM unreachable: fall back to the classifier alone
                return self._fire(lst, p, f"score {p:.2f} (llm unavailable)", win)
            return
        if v["scam"] and v["confidence"] >= self.c["llm"]["min_confidence"]:
            self._fire(lst, p, f"score {p:.2f}, llm {v['confidence']:.2f}: {v['reason']}", win)

    def _fire(self, lst, p: float, why: str, win: str) -> None:
        from .rules import Hit
        mode = self.c["mode"]
        action = "kill" if mode == "kill" and p >= self.c["kill_threshold"] else "flag"
        self.on_hit(lst, Hit("smart_check", "Smart check", action, why, "smart"), win)

    def forget(self, callid: str) -> None:
        with self.lock:
            self.state.pop(callid, None)
