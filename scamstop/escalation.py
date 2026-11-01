"""Customer / sub-account escalation (carrier integration mode).

Ending one scam call is a call-level decision. Quarantining a customer account is an
account-level decision and needs more:

* the call must carry trusted attribution from the switch (never a Contact or Call-ID host);
* only STRONG evidence counts: a strong phrase rule, a corroborated combination, or a
  smart-check kill. Context/weak matches ("hi grandma", "public defender"), off-campaign
  hits and shared-feed / block-list matches (external indicators) never count;
* evidence must come from `quarantine_after` distinct terminated calls inside `window_s`,
  covering at least `min_evidence_kinds` distinct kinds of evidence;
* the account escalated is the one that placed the calls: a reseller's CHILD, not the
  reseller. A reseller is only escalated (optionally, off by default) when several of its
  children have been quarantined.

The result is a `quarantined` deny record in sbc:fraud:v1:deny:customer:<id>, written
idempotently. Only a PVN operator turns that into `blocked` or clears it.
"""
from __future__ import annotations

import time

from .attribution import Attribution
from .fraud import FraudStore

STRONG_SOURCES = ("phrase_caller", "phrase_victim", "corroborated", "smart")


def evidence_kind(hit, side: str) -> str | None:
    """Which kind of strong evidence a kill hit is, or None if it must not count."""
    if hit.action != "kill" or getattr(hit, "strength", "strong") != "strong":
        return None
    if hit.rule_id == "smart_check":
        return "smart"
    if hit.rule_id == "corroborated":
        return "corroborated"
    if hit.category in ("campaign", "blocked", "account") or hit.rule_id.startswith("blocked_"):
        return None
    return "phrase_victim" if side == "victim" else "phrase_caller"


class Escalator:
    def __init__(self, cfg: dict, fraud: FraudStore, log=None):
        self.cfg, self.fraud, self.log = cfg, fraud, log or (lambda *a, **k: None)

    @property
    def e(self) -> dict:
        return self.cfg["carrier"]["escalation"]

    def record(self, attr: Attribution, hit, side: str, now: float | None = None) -> dict | None:
        """Record one enforced kill. Returns the escalation result if an account was quarantined."""
        e = self.e
        if not e.get("enabled", True):
            return None
        kind = evidence_kind(hit, side)
        if kind is None:
            return None
        if not attr.trusted:
            if self.cfg["carrier"]["attribution"].get("require_for_escalation", True):
                return None
        cid = attr.customer_id
        if not cid:
            return None
        now = now or time.time()
        window = int(e.get("window_s", 86400))
        ev = self.fraud.add_evidence(cid, attr.callid, kind, "strong", window, now)
        calls = {c for c, _, s in ev if s == "strong"}
        kinds = {k for _, k, s in ev if s == "strong" and k in STRONG_SOURCES}
        if len(calls) < int(e.get("quarantine_after", 3)) or len(kinds) < int(e.get("min_evidence_kinds", 2)):
            return None
        return self._quarantine(cid, f"auto_escalation", calls, kinds, now, attr.parent_id)

    def _quarantine(self, cid: str, reason: str, calls, kinds, now: float, parent_id: str | None) -> dict | None:
        e = self.e
        cur = self.fraud.get(cid)
        if cur and cur.get("active"):
            return None  # already quarantined or blocked: don't churn revisions
        window = int(e.get("window_s", 86400))
        bucket = int(now // window)
        ttl = int(e.get("quarantine_ttl_s", 0))
        res = self.fraud.set_state(
            cid, "quarantined", reason, f"auto-{cid}-{bucket}", f"auto:{cid}:{bucket}", "scamstop",
            expires_at=int(now) + ttl if ttl else 0, based_on_revision=cur["revision"] if cur else 0)
        out = dict(res, customer_id=cid, calls=sorted(calls)[:20], kinds=sorted(kinds), parent_id=parent_id)
        self.log(out)
        if res["result"] == "applied" and parent_id:
            out["parent"] = self._parent(parent_id, cid, now)
        return out

    def _parent(self, parent_id: str, child_id: str, now: float) -> dict:
        """Track quarantined children of a reseller. Escalating the reseller itself is opt-in."""
        p = self.e.get("parent") or {}
        k = f"{self.fraud.p}children:{parent_id}"
        window = int(self.e.get("window_s", 86400)) * 7
        pipe = self.fraud.r.pipeline()
        pipe.zadd(k, {child_id: now})
        pipe.zremrangebyscore(k, 0, now - window)
        pipe.expire(k, window + 60)
        pipe.zcard(k)
        n = int(pipe.execute()[-1])
        need = int(p.get("children_quarantined", 3))
        if not p.get("enabled") or n < need:
            return {"children_quarantined": n, "escalated": False, "review": n >= need}
        r = self._quarantine(parent_id, "children_quarantined", {f"child:{child_id}"}, {"children"}, now, None)
        return {"children_quarantined": n, "escalated": bool(r and r.get("result") == "applied")}
