"""Hosted mode: companies (tenants) that send their calls through your ScamStop SBC.

A tenant signs up, adds the IPs its dialer/switch sends from and where calls should
go after checking (its own carrier, or your default termination). Nothing reaches
the SBC until you approve the tenant.

Redis layout (shared with the SBC config, which only reads two keys per call):
  sbc:cust:<ip>         -> tenant id   (the SBC accepts calls from this IP; active tenants only)
  sbc:route:<ip>        -> host:port   (where the SBC relays that tenant's calls)
  ss:tenant:<id>        hash: name, email, pw, status, created, dry_run, warn_mode, carrier_mode, carrier, last_call
  ss:tenant:<id>:ips    set of source IPs
  ss:tenants            set of tenant ids
  ss:email:<email>      -> tenant id
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import re
import secrets
import time

STATUSES = ("pending", "active", "suspended")
WARN_MODES = ("warn_then_hangup", "warn_only", "off")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
_HOST = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", re.I)


def hash_pw(pw: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${h}"


def check_pw(pw: str, stored: str) -> bool:
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(hash_pw(pw, salt), stored)


def valid_source_ip(ip: str) -> bool:
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_unspecified or a.is_multicast or a.is_reserved)


def parse_carrier(s: str) -> str:
    """'64.34.1.2', 'sip.carrier.com:5080', 'sip:1.2.3.4:5060' -> 'host:port'."""
    s = (s or "").strip().removeprefix("sip:").removeprefix("sips:").split(";")[0]
    host, _, port = s.partition(":")
    port = port or "5060"
    if not _HOST.fullmatch(host) or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError("enter the carrier as an IP or hostname, optionally with :port")
    return f"{host.lower()}:{int(port)}"


class Tenants:
    def __init__(self, store, hosted_cfg: dict):
        self.r, self.p, self.h = store.r, store.p, hosted_cfg
        self._cache: dict[str, tuple[float, dict | None]] = {}

    # keys ------------------------------------------------------------------------
    def _k(self, tid: str) -> str:
        return f"ss:tenant:{tid}"

    def _route_target(self, t: dict) -> str | None:
        if t.get("carrier_mode") == "default":
            return self.h.get("default_carrier") or None
        return t.get("carrier") or None

    # accounts ----------------------------------------------------------------------
    def create(self, name: str, email: str, password: str) -> dict:
        name, email = (name or "").strip()[:80], (email or "").strip().lower()
        if not name:
            raise ValueError("enter your company name")
        if not _EMAIL.fullmatch(email):
            raise ValueError("enter a valid email address")
        if len(password or "") < 10:
            raise ValueError("use a password of at least 10 characters")
        tid = "t_" + secrets.token_hex(6)
        if not self.r.set(f"ss:email:{email}", tid, nx=True):
            raise ValueError("an account with that email already exists")
        status = "active" if self.h.get("auto_approve") else "pending"
        self.r.hset(self._k(tid), mapping={
            "name": name, "email": email, "pw": hash_pw(password), "status": status, "created": int(time.time()),
            "dry_run": "1", "warn_mode": "warn_then_hangup",
            "carrier_mode": "default" if self.h.get("default_carrier") else "own", "carrier": ""})
        self.r.sadd("ss:tenants", tid)
        return self.get(tid)

    def authenticate(self, email: str, password: str) -> dict | None:
        tid = self.r.get(f"ss:email:{(email or '').strip().lower()}")
        if not tid:
            hash_pw(password or "x")  # same work either way, so timing doesn't reveal accounts
            return None
        t = self.r.hgetall(self._k(tid))
        return self.get(tid) if t and check_pw(password or "", t.get("pw", "")) else None

    def get(self, tid: str) -> dict | None:
        t = self.r.hgetall(self._k(tid))
        if not t:
            return None
        t.pop("pw", None)
        t["id"] = tid
        t["ips"] = sorted(self.r.smembers(f"{self._k(tid)}:ips"))
        t["dry_run"] = t.get("dry_run", "1") == "1"
        t["route"] = self._route_target(t)
        return t

    def list(self) -> list[dict]:
        return sorted((self.get(t) for t in self.r.smembers("ss:tenants")), key=lambda t: -int(t.get("created", 0)))

    def update(self, tid: str, **f) -> dict:
        t = self.get(tid)
        if not t:
            raise ValueError("no such company")
        out = {}
        if "name" in f:
            out["name"] = str(f["name"]).strip()[:80] or t["name"]
        if "dry_run" in f:
            out["dry_run"] = "1" if f["dry_run"] else "0"
        if "warn_mode" in f:
            if f["warn_mode"] not in WARN_MODES:
                raise ValueError("bad warning mode")
            out["warn_mode"] = f["warn_mode"]
        if "carrier_mode" in f:
            if f["carrier_mode"] not in ("own", "default"):
                raise ValueError("bad carrier choice")
            if f["carrier_mode"] == "default" and not self.h.get("default_carrier"):
                raise ValueError("no default termination is offered")
            out["carrier_mode"] = f["carrier_mode"]
        if "carrier" in f:
            out["carrier"] = parse_carrier(f["carrier"]) if f["carrier"] else ""
            sbc = (self.h.get("sbc_address") or "").split(":")[0]
            if sbc and out["carrier"].split(":")[0] == sbc:
                raise ValueError("that's the ScamStop SBC itself; enter your carrier's address")
        if out:
            self.r.hset(self._k(tid), mapping=out)
        self.sync(tid)
        return self.get(tid)

    def set_status(self, tid: str, status: str) -> dict:
        if status not in STATUSES or not self.r.exists(self._k(tid)):
            raise ValueError("bad status or company")
        self.r.hset(self._k(tid), mapping={"status": status, f"{status}_at": int(time.time())})
        self.sync(tid)
        return self.get(tid)

    def delete(self, tid: str) -> None:
        t = self.get(tid)
        if not t:
            return
        for ip in t["ips"]:
            self._unroute(ip, tid)
        self.r.delete(self._k(tid), f"{self._k(tid)}:ips", f"ss:email:{t['email']}")
        self.r.srem("ss:tenants", tid)

    # source IPs and routing ----------------------------------------------------------
    def add_ip(self, tid: str, ip: str) -> dict:
        ip = (ip or "").strip()
        if not valid_source_ip(ip):
            raise ValueError("enter the public IPv4 address your dialer or switch sends calls from")
        owner = self.r.get(f"ss:ipowner:{ip}")
        if owner and owner != tid:
            raise ValueError("that IP belongs to another account; contact support")
        self.r.set(f"ss:ipowner:{ip}", tid)
        self.r.sadd(f"{self._k(tid)}:ips", ip)
        self.sync(tid)
        return self.get(tid)

    def remove_ip(self, tid: str, ip: str) -> dict:
        self.r.srem(f"{self._k(tid)}:ips", ip)
        self._unroute(ip, tid)
        return self.get(tid)

    def _unroute(self, ip: str, tid: str) -> None:
        if self.r.get(f"ss:ipowner:{ip}") == tid:
            self.r.delete(f"ss:ipowner:{ip}")
        if self.r.get(f"{self.p}cust:{ip}") == tid:
            self.r.delete(f"{self.p}cust:{ip}", f"{self.p}route:{ip}")
        self._cache.pop(ip, None)

    def sync(self, tid: str) -> None:
        """Write (or remove) the two keys the SBC reads for each of the tenant's IPs."""
        t = self.get(tid)
        if not t:
            return
        target = t["route"]
        live = t["status"] == "active" and bool(target)
        for ip in t["ips"]:
            if live:
                self.r.set(f"{self.p}cust:{ip}", tid)
                self.r.set(f"{self.p}route:{ip}", target)
            elif self.r.get(f"{self.p}cust:{ip}") == tid:
                self.r.delete(f"{self.p}cust:{ip}", f"{self.p}route:{ip}")
            self._cache.pop(ip, None)

    def resync_all(self) -> None:
        for tid in self.r.smembers("ss:tenants"):
            self.sync(tid)

    # used by the daemon ----------------------------------------------------------------
    def for_ip(self, ip: str, ttl: float = 10.0) -> dict | None:
        now = time.time()
        hit = self._cache.get(ip)
        if hit and now - hit[0] < ttl:
            return hit[1]
        tid = self.r.get(f"{self.p}cust:{ip}") if ip else None
        t = self.get(tid) if tid else None
        self._cache[ip] = (now, t)
        return t

    def touch(self, tid: str) -> None:
        self.r.hset(self._k(tid), "last_call", int(time.time()))


# sessions ------------------------------------------------------------------------------
def make_token(secret: str, subject: str, hours: int = 24 * 14) -> str:
    exp = int(time.time()) + hours * 3600
    msg = f"{subject}|{exp}"
    sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()[:32]
    return base64.urlsafe_b64encode(f"{msg}|{sig}".encode()).decode()


def read_token(secret: str, token: str) -> str | None:
    try:
        subject, exp, sig = base64.urlsafe_b64decode(token.encode()).decode().rsplit("|", 2)
    except Exception:
        return None
    good = hmac.new(secret.encode(), f"{subject}|{exp}".encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, good) or int(exp) < time.time():
        return None
    return subject
