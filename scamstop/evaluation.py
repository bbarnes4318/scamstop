"""Offline evaluation: phrase rules, smart classifier and the combined system, reported separately.

Input is labeled transcripts (JSONL, one call per line):
  {"id": "...", "label": 1|0, "caller": "...", "victim": "..."}   (victim optional)
or the legacy "<label>\\t<caller text>" lines of tests/data/smart_heldout.txt.

Numbers on the bundled fixtures are regression checks, not production accuracy evidence.
docs/evaluation.md describes how to build a representative labeled set from real calls.
"""
from __future__ import annotations

import json
from pathlib import Path

from .rules import CallEvidence, CallMatcher, Rule, normalize


def phrase_verdict(caller: str, victim: str, rules: list[Rule], window: int = 400, step: int = 8) -> tuple[str, list]:
    """Feed both sides word-by-word, interleaved, as the live daemon would. Returns
    ("kill" | "flag" | "none", hits)."""
    sides = {"caller": CallMatcher(rules, None, window, "caller"), "victim": CallMatcher(rules, None, window, "victim")}
    words = {"caller": normalize(caller or "").split(), "victim": normalize(victim or "").split()}
    ev = CallEvidence(rules)
    hits, i = [], 0
    while i < max(len(words["caller"]), len(words["victim"])):
        for side, m in sides.items():
            chunk = " ".join(words[side][i:i + step])
            if not chunk:
                continue
            for h in m.update(chunk):
                hits.append(h)
                c = ev.add(h)
                if c:
                    hits.append(c)
            m.commit(chunk)
        i += step
    if any(h.action == "kill" for h in hits):
        return "kill", hits
    return ("flag" if hits else "none"), hits


def smart_verdict(clf, caller: str, flag_t: float, kill_t: float, window_words: int = 75,
                  min_words: int = 25, every_words: int = 12) -> tuple[str, float]:
    """Max classifier score over the same sliding windows the live check scores."""
    words = normalize(caller or "").split()
    best = 0.0
    if len(words) < min_words:
        return "none", 0.0
    n = min_words
    while True:
        best = max(best, clf.score(" ".join(words[max(0, n - window_words):n])))
        if n >= len(words):
            break
        n = min(len(words), n + every_words)
    return ("kill" if best >= kill_t else "flag" if best >= flag_t else "none"), best


def load_labeled(path: str | Path) -> list[dict]:
    path = Path(path)
    out = []
    for i, line in enumerate(path.read_text().splitlines()):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{"):
            d = json.loads(line)
            if d.get("label") not in (0, 1) or not isinstance(d.get("caller", ""), str):
                raise ValueError(f"{path}:{i + 1}: need label 0/1 and a caller string")
            out.append({"id": str(d.get("id", i)), "label": int(d["label"]), "caller": d.get("caller", ""),
                        "victim": d.get("victim", "") or ""})
        else:
            lab, text = line.split("\t", 1)
            out.append({"id": str(i), "label": int(lab), "caller": text, "victim": ""})
    return out


def pairs_as_labeled(path: str | Path) -> list[dict]:
    import yaml
    out = []
    for p in yaml.safe_load(Path(path).read_text())["pairs"]:
        for kind, label in (("legit", 0), ("scam", 1)):
            out.append({"id": f"{p['id']}:{kind}", "label": label, "caller": p[kind].get("caller", ""),
                        "victim": p[kind].get("victim", "") or ""})
    return out


def _pr(pred: list[bool], y: list[int]) -> dict:
    tp = sum(1 for p, l in zip(pred, y) if p and l)
    fp = sum(1 for p, l in zip(pred, y) if p and not l)
    fn = sum(1 for p, l in zip(pred, y) if not p and l)
    return {"precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "true_positives": tp, "false_positives": fp, "false_negatives": fn}


def evaluate_system(calls: list[dict], rules: list[Rule], clf, smart_cfg: dict) -> dict:
    """Precision/recall at the configured flag and kill thresholds, for each layer and combined."""
    flag_t, kill_t = float(smart_cfg["threshold"]), float(smart_cfg["kill_threshold"])
    smart_kills = smart_cfg.get("mode") == "kill"
    y, rows = [c["label"] for c in calls], []
    for c in calls:
        pv, hits = phrase_verdict(c["caller"], c["victim"], rules)
        sv, score = smart_verdict(clf, c["caller"], flag_t, kill_t, int(smart_cfg.get("window_words", 75)),
                                  int(smart_cfg.get("min_words", 25)), int(smart_cfg.get("every_words", 12)))
        raw = clf.score(normalize(c["caller"]))  # the classifier alone, ignoring live min_words gating
        rows.append({"id": c["id"], "label": c["label"], "phrase": pv, "smart": sv, "score": round(score, 4),
                     "ungated_score": round(raw, 4),
                     "rules": sorted({h.rule_id for h in hits})})
    res = {
        "n": len(calls), "scams": sum(y),
        "thresholds": {"flag": flag_t, "kill": kill_t, "smart_mode": smart_cfg.get("mode")},
        "phrase": {"flag_or_kill": _pr([r["phrase"] != "none" for r in rows], y),
                   "kill": _pr([r["phrase"] == "kill" for r in rows], y)},
        # as the live check runs (needs min_words before it scores at all)
        "smart": {f"flag@{flag_t}": _pr([r["smart"] != "none" for r in rows], y),
                  f"kill@{kill_t}": _pr([r["smart"] == "kill" for r in rows], y),
                  "too_short_to_score": sum(1 for c in calls if len(normalize(c["caller"]).split()) < int(smart_cfg.get("min_words", 25)))},
        # the classifier alone on each whole transcript (what `smart-eval` measures)
        "smart_ungated": {f"flag@{flag_t}": _pr([r["ungated_score"] >= flag_t for r in rows], y),
                          f"kill@{kill_t}": _pr([r["ungated_score"] >= kill_t for r in rows], y)},
        "combined": {
            "flag_or_kill": _pr([r["phrase"] != "none" or r["smart"] != "none" for r in rows], y),
            # what actually ends calls with the current configuration
            "kill": _pr([r["phrase"] == "kill" or (smart_kills and r["smart"] == "kill") for r in rows], y),
        },
        "rows": rows,
        "note": "fixture results are regression checks, not production accuracy (docs/evaluation.md)",
    }
    return res
