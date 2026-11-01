"""Customer-level fraud state in the sbc:fraud:v1:* namespace (docs/carrier-integration-v1.md).

Keys (P = carrier.fraud_prefix, default "sbc:fraud:v1:"):
  P deny:customer:<id>   HASH state, reason_code, case_id, revision, updated_at, expires_at,
                         actor, request_id. state is blocked | quarantined. Times are integer
                         Unix epoch SECONDS (UTC); expires_at=0 means no automatic expiry.
  P rev                  STRING global monotonic revision counter (INCR)
  P epoch                STRING bumped on every deny change: active calls are re-checked
  P req:<request_id>     STRING the stored result of an already-processed request (idempotency)
  P audit                STREAM one entry per accepted or refused change
  P requests             STREAM enforcement requests from permitted writers (consumer group)
  P ack:<call-id>        HASH termination outcome for one call (TTL enforcement.ack_ttl_s)
  P ev:customer:<id>     ZSET escalation evidence (member "<call-id>\\t<kind>\\t<strength>", score = time)

Every change goes through one Lua script per operation, loaded with SCRIPT LOAD (redis-py
register_script). Untrusted values only ever travel as KEYS/ARGV, never inside script text.
ScamStop never touches the registry keys the carrier's portal owns (sbc:cust:*, sbc:entry:*).
"""
from __future__ import annotations

import json
import socket
import time

from .attribution import ACTOR, CASE_ID, REASON_CODE, REQUEST_ID, valid_callid, valid_customer_id

STATES = ("blocked", "quarantined")
OPS = ("block", "quarantine", "unblock")
REQ_TTL_S = 7 * 86400
MAX_EXPIRY_S = 10 * 365 * 86400

# KEYS: deny, rev, req, epoch, audit
# ARGV: state, reason_code, case_id, expires_at, request_id, actor, based_on_revision|'', force '0'|'1',
#       customer_id, audit_maxlen, req_ttl
_SET = """
local prev = redis.call('GET', KEYS[3])
if prev then return {'duplicate', prev} end
local t = redis.call('TIME')
local now = tonumber(t[1])
local cur = redis.call('HMGET', KEYS[1], 'state', 'revision', 'expires_at')
local cstate, crev, cexp = cur[1], tonumber(cur[2] or '0') or 0, tonumber(cur[3] or '0') or 0
if cstate and cexp > 0 and cexp <= now then cstate = false end
local result, rev = 'applied', crev
if ARGV[7] ~= '' and tonumber(ARGV[7]) < crev then
  result = 'stale'
elseif cstate == 'blocked' and ARGV[1] == 'quarantined' and ARGV[8] ~= '1' then
  result = 'kept_stronger'
else
  rev = redis.call('INCR', KEYS[2])
  redis.call('DEL', KEYS[1])
  redis.call('HSET', KEYS[1], 'state', ARGV[1], 'reason_code', ARGV[2], 'case_id', ARGV[3],
             'revision', rev, 'updated_at', now, 'expires_at', ARGV[4], 'actor', ARGV[6], 'request_id', ARGV[5])
  redis.call('INCR', KEYS[4])
end
redis.call('XADD', KEYS[5], 'MAXLEN', '~', ARGV[10], '*', 'op', 'set', 'customer_id', ARGV[9], 'state', ARGV[1],
           'reason_code', ARGV[2], 'case_id', ARGV[3], 'expires_at', ARGV[4], 'revision', rev,
           'actor', ARGV[6], 'request_id', ARGV[5], 'result', result, 'ts', now)
local out = result .. ':' .. rev
redis.call('SET', KEYS[3], out, 'EX', ARGV[11])
return {result, out}
"""

# KEYS: deny, rev, req, epoch, audit
# ARGV: expected_revision, case_id, request_id, actor, customer_id, audit_maxlen, req_ttl, reason_code
_CLEAR = """
local prev = redis.call('GET', KEYS[3])
if prev then return {'duplicate', prev} end
local t = redis.call('TIME')
local now = tonumber(t[1])
local cur = redis.call('HMGET', KEYS[1], 'state', 'revision')
local crev = tonumber(cur[2] or '0') or 0
local result, rev = 'applied', crev
if not cur[1] then
  result = 'absent'
elseif tonumber(ARGV[1]) ~= crev then
  result = 'conflict'
else
  rev = redis.call('INCR', KEYS[2])
  redis.call('DEL', KEYS[1])
  redis.call('INCR', KEYS[4])
end
redis.call('XADD', KEYS[5], 'MAXLEN', '~', ARGV[6], '*', 'op', 'clear', 'customer_id', ARGV[5], 'state', '',
           'reason_code', ARGV[8], 'case_id', ARGV[2], 'expires_at', '', 'revision', rev, 'actor', ARGV[4],
           'request_id', ARGV[3], 'result', result, 'ts', now, 'expected_revision', ARGV[1])
local out = result .. ':' .. rev .. ':' .. crev
redis.call('SET', KEYS[3], out, 'EX', ARGV[7])
return {result, out}
"""


class FraudError(ValueError):
    pass


def _check(cond: bool, what: str) -> None:
    if not cond:
        raise FraudError(f"invalid {what}")


def _s(v) -> str:
    return v.decode() if isinstance(v, bytes) else str(v)


class FraudStore:
    def __init__(self, r, prefix: str = "sbc:fraud:v1:", audit_maxlen: int = 100000, ack_ttl_s: int = 86400,
                 requests_maxlen: int = 10000):
        if not prefix.endswith(":") or prefix.startswith(("sbc:cust:", "sbc:entry:")):
            raise ValueError("fraud prefix must be its own namespace ending in ':'")
        self.r, self.p = r, prefix
        self.audit_maxlen, self.ack_ttl_s, self.requests_maxlen = int(audit_maxlen), int(ack_ttl_s), int(requests_maxlen)
        self._set = r.register_script(_SET)
        self._clear = r.register_script(_CLEAR)

    @classmethod
    def from_config(cls, r, cfg: dict) -> "FraudStore":
        c = cfg.get("carrier") or {}
        return cls(r, c.get("fraud_prefix", "sbc:fraud:v1:"), c.get("audit_maxlen", 100000),
                   (cfg.get("enforcement") or {}).get("ack_ttl_s", 86400), c.get("requests_stream_maxlen", 10000))

    # keys --------------------------------------------------------------------------------
    def deny_key(self, cid: str) -> str:
        return f"{self.p}deny:customer:{cid}"

    def _keys(self, cid: str, request_id: str) -> list[str]:
        return [self.deny_key(cid), f"{self.p}rev", f"{self.p}req:{request_id}", f"{self.p}epoch", f"{self.p}audit"]

    # writes ------------------------------------------------------------------------------
    def set_state(self, customer_id: str, state: str, reason_code: str, case_id: str, request_id: str,
                  actor: str, expires_at: int = 0, based_on_revision: int | None = None, force: bool = False) -> dict:
        """Block or quarantine a customer. Idempotent per request_id. A request computed from an
        older revision than the current one is refused as stale; a quarantine never silently
        downgrades an existing block unless force=True."""
        _check(valid_customer_id(customer_id), "customer_id")
        _check(state in STATES, "state")
        _check(bool(REASON_CODE.fullmatch(reason_code or "")), "reason_code")
        _check(bool(CASE_ID.fullmatch(case_id or "")), "case_id")
        _check(bool(REQUEST_ID.fullmatch(request_id or "")), "request_id")
        _check(bool(ACTOR.fullmatch(actor or "")), "actor")
        _check(isinstance(expires_at, int) and not isinstance(expires_at, bool)
               and (expires_at == 0 or time.time() < expires_at < time.time() + MAX_EXPIRY_S), "expires_at")
        _check(based_on_revision is None or (isinstance(based_on_revision, int) and based_on_revision >= 0),
               "based_on_revision")
        res = self._set(keys=self._keys(customer_id, request_id),
                        args=[state, reason_code, case_id, expires_at, request_id, actor,
                              "" if based_on_revision is None else based_on_revision, "1" if force else "0",
                              customer_id, self.audit_maxlen, REQ_TTL_S])
        return self._result(res)

    def clear(self, customer_id: str, expected_revision: int, case_id: str, request_id: str, actor: str,
              reason_code: str = "unblocked") -> dict:
        """Remove a block/quarantine, only if it is still the revision the caller reviewed."""
        _check(valid_customer_id(customer_id), "customer_id")
        _check(isinstance(expected_revision, int) and not isinstance(expected_revision, bool)
               and expected_revision > 0, "expected_revision")
        _check(bool(CASE_ID.fullmatch(case_id or "")), "case_id")
        _check(bool(REQUEST_ID.fullmatch(request_id or "")), "request_id")
        _check(bool(ACTOR.fullmatch(actor or "")), "actor")
        _check(bool(REASON_CODE.fullmatch(reason_code or "")), "reason_code")
        res = self._clear(keys=self._keys(customer_id, request_id),
                          args=[expected_revision, case_id, request_id, actor, customer_id, self.audit_maxlen,
                                REQ_TTL_S, reason_code])
        return self._result(res)

    @staticmethod
    def _result(res) -> dict:
        status, stored = _s(res[0]), _s(res[1])
        parts = stored.split(":")
        out = {"result": parts[0], "revision": int(parts[1])}
        if status == "duplicate":
            out["duplicate"] = True
        return out

    # reads -------------------------------------------------------------------------------
    def get(self, customer_id: str) -> dict | None:
        if not valid_customer_id(customer_id):
            return None
        h = self.r.hgetall(self.deny_key(customer_id))
        if not h:
            return None
        h = {_s(k): _s(v) for k, v in h.items()}
        for k in ("revision", "updated_at", "expires_at"):
            try:
                h[k] = int(h.get(k) or 0)
            except ValueError:
                h[k] = 0
        h["customer_id"] = customer_id
        h["active"] = h.get("state") in STATES and (h["expires_at"] == 0 or h["expires_at"] > time.time())
        return h

    def denied(self, customer_id: str | None) -> dict | None:
        """The active deny record for a customer, or None. Raises on Redis errors so the
        caller can count them instead of mistaking 'unavailable' for 'not denied'."""
        if not customer_id:
            return None
        d = self.get(customer_id)
        return d if d and d["active"] else None

    def list(self, limit: int = 1000) -> list[dict]:
        out = []
        for k in self.r.scan_iter(f"{self.p}deny:customer:*", count=500):
            cid = _s(k).rsplit(":", 1)[-1]
            d = self.get(cid)
            if d:
                out.append(d)
            if len(out) >= limit:
                break
        return sorted(out, key=lambda d: d["customer_id"])

    def epoch(self) -> int:
        return int(self.r.get(f"{self.p}epoch") or 0)

    def audit(self, count: int = 100) -> list[dict]:
        return [dict({_s(k): _s(v) for k, v in f.items()}, id=_s(i))
                for i, f in self.r.xrevrange(f"{self.p}audit", count=count)]

    def sweep_expired(self) -> int:
        """Clear deny records whose expires_at has passed (with an audit entry each)."""
        n = 0
        for d in self.list(100000):
            if d.get("state") in STATES and not d["active"]:
                r = self.clear(d["customer_id"], d["revision"], d.get("case_id") or "expiry",
                               f"expiry:{d['customer_id']}:{d['revision']}", "scamstop-expiry", "expired")
                n += r["result"] == "applied"
        return n

    # termination acknowledgements ----------------------------------------------------------
    def ack(self, callid: str, state: str, **fields) -> None:
        if not valid_callid(callid):
            return
        k = f"{self.p}ack:{callid}"
        m = {"state": state, "updated_at": int(time.time())}
        m.update({a: str(b)[:200] for a, b in fields.items() if b is not None})
        pipe = self.r.pipeline()
        pipe.hset(k, mapping=m)
        pipe.expire(k, self.ack_ttl_s)
        pipe.execute()

    def get_ack(self, callid: str) -> dict:
        return {_s(k): _s(v) for k, v in self.r.hgetall(f"{self.p}ack:{callid}").items()}

    # escalation evidence ---------------------------------------------------------------------
    def add_evidence(self, customer_id: str, callid: str, kind: str, strength: str, window_s: int,
                     now: float | None = None) -> list[tuple[str, str, str]]:
        """Record one call's evidence against an account and return the window's evidence."""
        if not valid_customer_id(customer_id) or not valid_callid(callid):
            return []
        now = now or time.time()
        k = f"{self.p}ev:customer:{customer_id}"
        pipe = self.r.pipeline()
        pipe.zadd(k, {f"{callid}\t{kind}\t{strength}": now})
        pipe.zremrangebyscore(k, 0, now - window_s)
        pipe.expire(k, int(window_s) + 60)
        pipe.zrange(k, 0, -1)
        members = pipe.execute()[-1]
        out = []
        for m in members:
            parts = _s(m).split("\t")
            if len(parts) == 3:
                out.append((parts[0], parts[1], parts[2]))
        return out

    # enforcement requests (permitted writers -> ScamStop) ------------------------------------
    GROUP = "scamstop"

    def submit_request(self, fields: dict) -> str:
        """Used by permitted writers (PVN fraud staff via CLI/portal) to queue a request."""
        req = validate_request(fields)
        return _s(self.r.xadd(f"{self.p}requests", {k: str(v) for k, v in req.items()},
                              maxlen=self.requests_maxlen, approximate=True))

    def process_requests(self, consumer: str | None = None, count: int = 50) -> list[dict]:
        """Consume queued requests at least once. Each is idempotent by request_id, so a crash
        between applying and XACK only replays a request that returns 'duplicate'."""
        stream, consumer = f"{self.p}requests", consumer or socket.gethostname()[:40] or "scamstop"
        try:
            self.r.xgroup_create(stream, self.GROUP, id="0", mkstream=True)
        except Exception as e:  # BUSYGROUP: already exists
            if "BUSYGROUP" not in str(e):
                raise
        out = []
        for start in ("0", ">"):  # first our own unacknowledged entries, then new ones
            resp = self.r.xreadgroup(self.GROUP, consumer, {stream: start}, count=count)
            for _, entries in resp or []:
                for eid, f in entries:
                    f = {_s(k): _s(v) for k, v in (f or {}).items()}
                    try:
                        res = self.apply_request(f)
                    except FraudError as e:
                        res = {"result": "rejected", "error": str(e)}
                        self.r.xadd(f"{self.p}audit", {"op": "request", "result": "rejected", "error": str(e)[:100],
                                                       "request_id": str(f.get("request_id", ""))[:80],
                                                       "ts": int(time.time())},
                                    maxlen=self.audit_maxlen, approximate=True)
                    self.r.xack(stream, self.GROUP, eid)
                    out.append(dict(res, request_id=f.get("request_id")))
        return out

    def apply_request(self, f: dict) -> dict:
        req = validate_request(f)
        if req["op"] == "unblock":
            return self.clear(req["customer_id"], req["expected_revision"], req["case_id"], req["request_id"],
                              req["actor"], req.get("reason_code") or "unblocked")
        return self.set_state(req["customer_id"], "blocked" if req["op"] == "block" else "quarantined",
                              req["reason_code"], req["case_id"], req["request_id"], req["actor"],
                              req.get("expires_at", 0), req.get("based_on_revision"))


def _int(v, what: str) -> int:
    if isinstance(v, bool):
        raise FraudError(f"invalid {what}")
    try:
        s = str(v).strip()
        if not s.isdigit() or len(s) > 12:
            raise ValueError
        return int(s)
    except (TypeError, ValueError):
        raise FraudError(f"invalid {what}") from None


def validate_request(f: dict) -> dict:
    if not isinstance(f, dict):
        raise FraudError("invalid request")
    op = f.get("op")
    _check(op in OPS, "op")
    out = {"op": op, "customer_id": str(f.get("customer_id", "")), "case_id": str(f.get("case_id", "")),
           "request_id": str(f.get("request_id", "")), "actor": str(f.get("actor", ""))}
    _check(valid_customer_id(out["customer_id"]), "customer_id")
    _check(bool(CASE_ID.fullmatch(out["case_id"])), "case_id")
    _check(bool(REQUEST_ID.fullmatch(out["request_id"])), "request_id")
    _check(bool(ACTOR.fullmatch(out["actor"])), "actor")
    reason = str(f.get("reason_code") or ("unblocked" if op == "unblock" else ""))
    _check(bool(REASON_CODE.fullmatch(reason)), "reason_code")
    out["reason_code"] = reason
    if op == "unblock":
        out["expected_revision"] = _int(f.get("expected_revision"), "expected_revision")
    else:
        out["expires_at"] = _int(f.get("expires_at", 0) or 0, "expires_at")
        if f.get("based_on_revision") not in (None, ""):
            out["based_on_revision"] = _int(f["based_on_revision"], "based_on_revision")
    return out


def dumps(d) -> str:
    return json.dumps(d, sort_keys=True)
