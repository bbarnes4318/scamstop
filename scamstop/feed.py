"""Shared threat feed client: share what this network blocks, apply what others caught.

Feed blocks are stored like any other block, with reason "feed:<rules> x<reporters>".
Each sync replaces the full set: anything the feed no longer publishes is removed
here too. Local blocks always win and are never touched by the feed.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

from .store import Store

FEED_PREFIX = "feed:"
SHARE_KINDS = ("media", "host", "tag", "cli")
_RULE_ID = re.compile(r"^[a-z0-9_]+$")


def _rule_of(reason: str) -> str:
    first = (reason or "").split(" ")[0]
    return first if _RULE_ID.fullmatch(first) else "manual"


class FeedClient:
    def __init__(self, cfg: dict, store: Store, state_path: str | None = None):
        self.cfg, self.store = cfg, store
        self.f = cfg["feed"]
        self.state_path = state_path or self.f.get("state_file", "/var/lib/scamstop/feed.json")
        self.state = self._load()

    # state -------------------------------------------------------------------
    def _load(self) -> dict:
        try:
            with open(self.state_path) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _save(self):
        os.makedirs(os.path.dirname(self.state_path) or ".", exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(self.state, fh)
        os.chmod(tmp, 0o600)  # holds the install key
        os.replace(tmp, self.state_path)

    def public_state(self) -> dict:
        return {k: v for k, v in self.state.items() if k not in ("key", "etag", "last_list")}

    # http --------------------------------------------------------------------
    def _req(self, method: str, path: str, body=None, headers=None):
        url = self.f["url"].rstrip("/") + path
        h = {"Content-Type": "application/json", "User-Agent": "scamstop"}
        if self.state.get("key"):
            h["Authorization"] = f"Bearer {self.state['install_id']}:{self.state['key']}"
        h.update(headers or {})
        req = urllib.request.Request(url, json.dumps(body).encode() if body is not None else None, h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return 304, e.headers, b""
            raise RuntimeError(f"feed {path}: HTTP {e.code} {e.read()[:200]!r}") from None

    def register(self):
        _, _, data = self._req("POST", "/v1/register", {"name": self.f.get("name") or ""})
        j = json.loads(data)
        self.state.update(install_id=j["install_id"], key=j["key"], registered=int(time.time()))
        self._save()

    # sync --------------------------------------------------------------------
    def local_indicators(self) -> list[dict]:
        out = []
        for kind in SHARE_KINDS:
            for b in self.store.list_blocks(kind):
                if b["reason"].startswith(FEED_PREFIX):
                    continue
                auto = not b["reason"].startswith(("manual", "added in panel")) and _rule_of(b["reason"]) != "manual"
                if auto or self.f.get("share_manual", True):
                    out.append({"kind": kind, "value": b["value"], "rule": _rule_of(b["reason"])})
        return out[:1000]

    def rule_counts(self) -> dict:
        """Today's kills per rule, for the feed's public counters. No call details."""
        path = self.cfg["evidence"].get("kill_log")
        counts: dict[str, int] = {}
        if not path or not os.path.exists(path):
            return counts
        midnight = time.mktime(time.localtime()[:3] + (0, 0, 0, 0, 0, -1))
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - 2_000_000))
            for line in fh.read().decode(errors="replace").splitlines():
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("ts", 0) >= midnight and not e.get("dry") and _RULE_ID.fullmatch(e.get("rule", "")):
                    counts[e["rule"]] = counts.get(e["rule"], 0) + 1
        return counts

    def protected(self, kind: str, value: str) -> bool:
        if value in self.f.get("never_apply", []):
            return True
        key = self.cfg["redis"].get("customer_key")
        if kind in ("media", "host") and key and self.store.r.exists(key.format(ip=value)):
            return True  # never let the feed block one of our own customers
        return self.store.is_blocked(kind, value) and not self._is_feed(kind, value)

    def _is_feed(self, kind: str, value: str) -> bool:
        why = self.store.r.hget(f"{self.store.p}block:{kind}:why", value) or ""
        return why.startswith(FEED_PREFIX)

    def apply(self, indicators: list[dict]) -> tuple[int, int]:
        kinds = set(self.f.get("apply_kinds", SHARE_KINDS))
        min_rep = int(self.f.get("min_reporters", 1))
        ttl = int(self.f.get("block_ttl_s", 3 * 86400))
        want = {}
        for ind in indicators:
            k, v = ind.get("kind"), ind.get("value")
            if k in kinds and ind.get("reporters", 0) >= min_rep and not self.protected(k, v):
                want[(k, v)] = f"{FEED_PREFIX}{','.join(ind.get('rules', []))[:60]} x{ind.get('reporters', 1)}"
        added = removed = 0
        for kind in SHARE_KINDS:
            for b in self.store.list_blocks(kind):
                if b["reason"].startswith(FEED_PREFIX) and (kind, b["value"]) not in want:
                    self.store.unblock(kind, b["value"])
                    removed += 1
        for (k, v), why in want.items():
            if not self.store.is_blocked(k, v):
                added += 1
            self.store.block(k, v, ttl, why)  # refreshes the expiry of ones we already had
        return added, removed

    def sync(self) -> dict:
        if not self.f.get("url"):
            raise RuntimeError("no feed url configured")
        if not self.state.get("key"):
            self.register()
        result = {"ts": int(time.time())}
        if self.f.get("share", True):
            inds = self.local_indicators()
            now_set = {f"{i['kind']}|{i['value']}" for i in inds}
            withdraw = [dict(zip(("kind", "value"), x.split("|", 1))) for x in set(self.state.get("shared", [])) - now_set]
            _, _, data = self._req("POST", "/v1/report", {"indicators": inds, "withdraw": withdraw,
                                                         "rule_counts": self.rule_counts()})
            result["shared"] = json.loads(data).get("accepted", 0)
            result["withdrawn"] = len(withdraw)
            self.state["shared"] = sorted(now_set)
        if self.f.get("apply", True):
            hdr = {"If-None-Match": self.state["etag"]} if self.state.get("etag") and self.state.get("last_list") else {}
            code, headers, data = self._req("GET", "/v1/indicators", headers=hdr)
            if code == 304:
                inds = self.state["last_list"]
            else:
                inds = json.loads(data)["indicators"]
                self.state["etag"] = headers.get("ETag")
                self.state["last_list"] = inds
            result["received"] = len(inds)
            result["added"], result["removed"] = self.apply(inds)
            result["active"] = sum(1 for k in SHARE_KINDS for b in self.store.list_blocks(k)
                                   if b["reason"].startswith(FEED_PREFIX))
        self.state.update(last_sync=result, last_error=None)
        self._save()
        return result

    def sync_safe(self) -> dict | None:
        try:
            return self.sync()
        except Exception as e:
            self.state["last_error"] = {"ts": int(time.time()), "message": str(e)[:300]}
            try:
                self._save()
            except OSError:
                pass
            return None
