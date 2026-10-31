"""Strikes, block lists and customer lookup.

Block lists are plain Redis SETs (<prefix>block:<kind>) so the SIP proxy can do a
single SISMEMBER per INVITE. Expiry lives beside them in a ZSET
(<prefix>block:<kind>:exp, score = unix expiry, 0 = never) and sweep() removes
expired members from both. Strikes are per-center SETs of Call-IDs with a TTL,
so they survive restarts and age out on their own.
"""
from __future__ import annotations

import time

KINDS = ("media", "host", "tag", "cli", "src", "dnc")


class Store:
    def __init__(self, r, prefix: str = "sbc:", customer_key: str | None = "sbc:cust:{ip}",
                 customer_cache_s: int = 60):
        self.r, self.p = r, prefix
        self.customer_key, self.cache_s = customer_key, customer_cache_s
        self._cust: dict[str, tuple[bool, float]] = {}

    @classmethod
    def from_url(cls, url: str, **kw) -> "Store":
        import redis
        return cls(redis.Redis.from_url(url, decode_responses=True), **kw)

    # customers -------------------------------------------------------------
    def is_customer(self, ip: str) -> bool:
        if self.customer_key is None:  # monitor every call
            return True
        hit = self._cust.get(ip)
        now = time.time()
        if hit and now - hit[1] < self.cache_s:
            return hit[0]
        ok = bool(self.r.exists(self.customer_key.format(ip=ip)))
        self._cust[ip] = (ok, now)
        return ok

    # strikes ---------------------------------------------------------------
    def add_strike(self, kind: str, center: str, callid: str, window_s: int) -> int:
        k = f"{self.p}strike:{kind}:{center}"
        pipe = self.r.pipeline()
        pipe.sadd(k, callid)
        pipe.expire(k, window_s)
        pipe.scard(k)
        return int(pipe.execute()[-1])

    # blocks ----------------------------------------------------------------
    def block(self, kind: str, value: str, ttl_s: int = 0, reason: str = "") -> None:
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        pipe = self.r.pipeline()
        pipe.sadd(f"{self.p}block:{kind}", value)
        pipe.zadd(f"{self.p}block:{kind}:exp", {value: (time.time() + ttl_s) if ttl_s else 0})
        if reason:
            pipe.hset(f"{self.p}block:{kind}:why", value, reason)
        pipe.execute()

    def unblock(self, kind: str, value: str) -> bool:
        pipe = self.r.pipeline()
        pipe.srem(f"{self.p}block:{kind}", value)
        pipe.zrem(f"{self.p}block:{kind}:exp", value)
        pipe.hdel(f"{self.p}block:{kind}:why", value)
        return bool(pipe.execute()[0])

    def is_blocked(self, kind: str, value: str) -> bool:
        return bool(self.r.sismember(f"{self.p}block:{kind}", value))

    def list_blocks(self, kind: str) -> list[dict]:
        members = sorted(self.r.smembers(f"{self.p}block:{kind}"))
        out = []
        for m in members:
            exp = self.r.zscore(f"{self.p}block:{kind}:exp", m)
            out.append({"value": m, "expires": int(exp) if exp else 0,
                        "reason": self.r.hget(f"{self.p}block:{kind}:why", m) or ""})
        return out

    def sweep(self) -> int:
        """Remove expired blocks. Returns how many were removed."""
        n, now = 0, time.time()
        for kind in KINDS:
            z = f"{self.p}block:{kind}:exp"
            expired = [m for m in self.r.zrangebyscore(z, 0.001, now)]
            for m in expired:
                n += self.unblock(kind, m)
        return n
