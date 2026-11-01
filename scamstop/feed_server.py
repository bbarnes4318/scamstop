"""Shared threat feed server: `scamstop feed-server`.

Installs that opt in report the call centers and spoofed caller IDs they block.
An indicator is published to everyone only when
  * reporters from at least `min_networks` different networks (/24) have seen it, or
  * any trusted install reported it,
and it was reported within `ttl_days`. A single install can't poison the feed alone.
Private and reserved IPs, server-side allowlisted values and banned installs are
never published. No transcripts, phone numbers of called parties, or customer data
are ever sent: only the indicator, its kind and the rule that caught it.

Standard library only (http.server + sqlite3).
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

KINDS = ("media", "host", "tag", "cli")
SCHEMA = """
CREATE TABLE IF NOT EXISTS installs (id TEXT PRIMARY KEY, key_hash TEXT NOT NULL, name TEXT, ip TEXT,
  created INTEGER, trusted INTEGER DEFAULT 0, banned INTEGER DEFAULT 0, last_seen INTEGER);
CREATE TABLE IF NOT EXISTS reports (kind TEXT, value TEXT, install_id TEXT, net TEXT, rule TEXT,
  first_seen INTEGER, last_seen INTEGER, PRIMARY KEY (kind, value, install_id));
CREATE INDEX IF NOT EXISTS reports_last ON reports(last_seen);
CREATE TABLE IF NOT EXISTS allowlist (kind TEXT, value TEXT, note TEXT, PRIMARY KEY (kind, value));
CREATE TABLE IF NOT EXISTS events (install_id TEXT, day TEXT, rule TEXT, n INTEGER, PRIMARY KEY (install_id, day, rule));
CREATE TABLE IF NOT EXISTS subscribers (email TEXT PRIMARY KEY, created INTEGER, ip TEXT);
"""
_CLI = re.compile(r"^[2-9]\d{9}$")
_TAG = re.compile(r"^CNX\d+$")
_RULE = re.compile(r"^[a-z0-9_:. x-]{0,80}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid(kind: str, value: str) -> bool:
    if kind in ("media", "host"):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        return ip.version == 4 and ip.is_global
    if kind == "cli":
        return bool(_CLI.fullmatch(value))
    if kind == "tag":
        return bool(_TAG.fullmatch(value))
    return False


def network_of(ip: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False)) if ":" not in ip else str(ipaddress.ip_network(f"{ip}/48", strict=False))
    except ValueError:
        return ip


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class Feed:
    def __init__(self, db: str, min_networks: int = 2, ttl_days: int = 14,
                 max_reports_per_day: int = 5000, max_registrations_per_ip: int = 5):
        self.db, self.min_networks, self.ttl = db, min_networks, ttl_days * 86400
        self.max_reports, self.max_regs = max_reports_per_day, max_registrations_per_ip
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(db, check_same_thread=False)
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._regs: dict[str, list[float]] = {}
        self._subs: dict[str, list[float]] = {}
        self._quota: dict[tuple[str, str], int] = {}
        self._cache: tuple[float, str, bytes] | None = None

    # installs ----------------------------------------------------------------
    def register(self, name: str, ip: str) -> dict:
        now = time.time()
        recent = [t for t in self._regs.get(ip, []) if now - t < 86400]
        if len(recent) >= self.max_regs:
            raise PermissionError("too many registrations from this address today")
        self._regs[ip] = recent + [now]
        iid, key = "ss_" + secrets.token_hex(8), secrets.token_urlsafe(24)
        with self.lock:
            self.conn.execute("INSERT INTO installs (id, key_hash, name, ip, created) VALUES (?,?,?,?,?)",
                              (iid, _hash(key), (name or "")[:80], ip, int(now)))
            self.conn.commit()
        return {"install_id": iid, "key": key}

    def subscribe(self, email: str, website: str, ip: str) -> dict:
        if website:  # honeypot filled in: a bot
            return {"ok": True}
        email = (email or "").strip().lower()
        if len(email) > 254 or not _EMAIL.fullmatch(email):
            raise ValueError("invalid email")
        now = time.time()
        recent = [t for t in self._subs.get(ip, []) if now - t < 86400]
        if len(recent) >= self.max_regs:
            raise PermissionError("too many subscribes from this address today")
        self._subs[ip] = recent + [now]
        with self.lock:
            self.conn.execute("INSERT OR IGNORE INTO subscribers VALUES (?,?,?)", (email, int(now), ip))
            self.conn.commit()
        return {"ok": True}

    def auth(self, header: str) -> str | None:
        if not header.startswith("Bearer "):
            return None
        tok = header[7:]
        if ":" not in tok:
            return None
        iid, key = tok.split(":", 1)
        row = self.conn.execute("SELECT key_hash, banned FROM installs WHERE id=?", (iid,)).fetchone()
        if not row or row[1] or not hmac.compare_digest(row[0], _hash(key)):
            return None
        return iid

    # reports -----------------------------------------------------------------
    def report(self, iid: str, ip: str, body: dict) -> dict:
        day = time.strftime("%Y-%m-%d", time.gmtime())
        inds = body.get("indicators", [])[:1000]
        used = self._quota.get((iid, day), 0)
        accepted = rejected = 0
        now = int(time.time())
        net = network_of(ip)
        with self.lock:
            for ind in inds:
                kind, value = str(ind.get("kind", "")), str(ind.get("value", "")).strip()
                rule = str(ind.get("rule", ""))[:80].lower()
                if used >= self.max_reports or kind not in KINDS or not valid(kind, value) or not _RULE.fullmatch(rule):
                    rejected += 1
                    continue
                self.conn.execute(
                    "INSERT INTO reports (kind, value, install_id, net, rule, first_seen, last_seen) VALUES (?,?,?,?,?,?,?) "
                    "ON CONFLICT(kind, value, install_id) DO UPDATE SET last_seen=excluded.last_seen, rule=excluded.rule, net=excluded.net",
                    (kind, value, iid, net, rule, now, now))
                used += 1
                accepted += 1
            for w in (body.get("withdraw") or [])[:1000]:  # this install unblocked it
                self.conn.execute("DELETE FROM reports WHERE kind=? AND value=? AND install_id=?",
                                  (str(w.get("kind")), str(w.get("value")), iid))
            for rule, n in (body.get("rule_counts") or {}).items():
                if _RULE.fullmatch(str(rule)) and isinstance(n, int) and 0 < n < 1_000_000:
                    self.conn.execute("INSERT INTO events VALUES (?,?,?,?) ON CONFLICT DO UPDATE SET n=excluded.n",
                                      (iid, day, rule, n))
            self.conn.execute("UPDATE installs SET last_seen=?, ip=? WHERE id=?", (now, ip, iid))
            self.conn.commit()
        self._quota[(iid, day)] = used
        self._cache = None
        return {"accepted": accepted, "rejected": rejected}

    def published(self) -> list[dict]:
        since = int(time.time()) - self.ttl
        rows = self.conn.execute("""
            SELECT r.kind, r.value, COUNT(DISTINCT r.install_id), COUNT(DISTINCT r.net), MAX(i.trusted),
                   MIN(r.first_seen), MAX(r.last_seen), GROUP_CONCAT(DISTINCT r.rule)
            FROM reports r JOIN installs i ON i.id = r.install_id
            WHERE r.last_seen >= ? AND i.banned = 0
              AND NOT EXISTS (SELECT 1 FROM allowlist a WHERE a.kind = r.kind AND a.value = r.value)
            GROUP BY r.kind, r.value""", (since,)).fetchall()
        out = []
        for kind, value, reporters, nets, trusted, first, last, rules in rows:
            if nets >= self.min_networks or trusted:
                out.append({"kind": kind, "value": value, "reporters": reporters, "networks": nets,
                            "trusted": bool(trusted), "first_seen": first, "last_seen": last,
                            "rules": sorted({r for r in (rules or "").split(",") if r})[:5]})
        return sorted(out, key=lambda x: (x["kind"], x["value"]))

    def indicators_json(self) -> tuple[str, bytes]:
        if self._cache and time.time() - self._cache[0] < 30:
            return self._cache[1], self._cache[2]
        body = json.dumps({"generated": int(time.time()), "indicators": self.published()}).encode()
        etag = '"' + hashlib.sha256(body).hexdigest()[:16] + '"'
        self._cache = (time.time(), etag, body)
        return etag, body

    def stats(self) -> dict:
        week = int(time.time()) - 7 * 86400
        c = self.conn
        return {
            "installs_active_7d": c.execute("SELECT COUNT(*) FROM installs WHERE last_seen>=? AND banned=0", (week,)).fetchone()[0],
            "indicators_published": len(self.published()),
            "scams_stopped_7d": c.execute("SELECT COALESCE(SUM(n),0) FROM events WHERE day>=?",
                                          (time.strftime("%Y-%m-%d", time.gmtime(week)),)).fetchone()[0],
        }

    # admin -------------------------------------------------------------------
    def admin(self, action: str, *args) -> str:
        c = self.conn
        with self.lock:
            if action == "installs":
                rows = c.execute("SELECT id, name, ip, trusted, banned, datetime(last_seen,'unixepoch') FROM installs ORDER BY last_seen DESC").fetchall()
                return "\n".join(f"{r[0]}  trusted={r[3]} banned={r[4]}  last={r[5]}  {r[2]}  {r[1]}" for r in rows) or "no installs"
            if action == "subscribers":
                rows = c.execute("SELECT email, datetime(created,'unixepoch'), ip FROM subscribers ORDER BY created DESC").fetchall()
                return "\n".join(f"{r[0]}  {r[1]}  {r[2]}" for r in rows) or "no subscribers"
            if action in ("trust", "untrust", "ban", "unban"):
                col, val = ("trusted", 1) if action == "trust" else ("trusted", 0) if action == "untrust" else ("banned", int(action == "ban"))
                n = c.execute(f"UPDATE installs SET {col}=? WHERE id=?", (val, args[0])).rowcount
            elif action == "allow":
                c.execute("INSERT OR REPLACE INTO allowlist VALUES (?,?,?)", (args[0], args[1], " ".join(args[2:])))
                n = 1
            elif action == "unallow":
                n = c.execute("DELETE FROM allowlist WHERE kind=? AND value=?", (args[0], args[1])).rowcount
            elif action == "delete":
                n = c.execute("DELETE FROM reports WHERE kind=? AND value=?", (args[0], args[1])).rowcount
            else:
                raise ValueError(f"unknown action {action}")
            c.commit()
        self._cache = None
        return f"{action}: {n} changed"


PUBLIC_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>ScamStop shared feed</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><style>
body{margin:0;background:#0a0f1c;color:#e8edf7;font:15px/1.5 -apple-system,Segoe UI,Inter,sans-serif;display:grid;place-items:center;min-height:100vh}
.w{max-width:720px;padding:32px;text-align:center}h1{font-size:28px;margin:0 0 6px}p{color:#8a97b3}
.g{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:28px 0}.c{background:#111829;border:1px solid #22304d;border-radius:14px;padding:20px}
.n{font-size:32px;font-weight:700}.l{color:#8a97b3;font-size:13px}</style></head><body><div class="w">
<h1>ScamStop shared feed</h1><p>Carriers running ScamStop share the scam call centers they catch, so a center caught on one network is blocked on all of them.</p>
<div class="g"><div class="c"><div class="n">%(installs_active_7d)s</div><div class="l">networks sharing this week</div></div>
<div class="c"><div class="n">%(indicators_published)s</div><div class="l">scam sources blocked everywhere</div></div>
<div class="c"><div class="n">%(scams_stopped_7d)s</div><div class="l">scam calls stopped this week</div></div></div>
<p>Join by turning on the shared feed in your ScamStop panel.</p></div></body></html>"""


WEB = Path(__file__).parent / "web"
SITE_PAGE = WEB / "site.html"
PRIVACY_PAGE = WEB / "privacy.html"
ASSETS = WEB / "assets"
ASSET_TYPES = {".webp": "image/webp", ".png": "image/png", ".svg": "image/svg+xml", ".wav": "audio/wav"}
WARNING_WAV = Path(__file__).parent / "audio_files" / "warning-en.wav"
LATEST = "scamstop-installer-linux-x86_64.run"
_SAFE = re.compile(r"^[A-Za-z0-9._-]+$")

INSTALL_SH = """#!/bin/sh
# ScamStop: download the installer from {url} and run it.
set -e
if [ "$(id -u)" -ne 0 ]; then echo "Run as root: curl -fsSL {url}/install | sudo bash"; exit 1; fi
case "$(uname -m)" in x86_64|amd64) ;; *) echo "ScamStop needs a 64-bit Intel/AMD (x86_64) server."; exit 1;; esac
command -v curl >/dev/null || {{ echo "curl is required"; exit 1; }}
TMP=$(mktemp -d /tmp/scamstop.XXXXXX)
trap 'rm -rf "$TMP"' EXIT INT TERM
echo "Downloading ScamStop (about 230 MB)..."
curl -fL --progress-bar -o "$TMP/{latest}" "{url}/download/{latest}"
curl -fsSL -o "$TMP/SHA256SUMS" "{url}/download/SHA256SUMS"
( cd "$TMP" && grep " {latest}$" SHA256SUMS | sha256sum -c - >/dev/null ) || {{ echo "Download is corrupted; try again."; exit 1; }}
sh "$TMP/{latest}" "$@"
"""


class Downloads:
    """Files offered at /download/, plus a SHA256SUMS computed once per file version."""

    def __init__(self, folder: str | None):
        self.dir = Path(folder) if folder else None
        self._sums: dict[str, tuple[float, str]] = {}

    def path(self, name: str) -> Path | None:
        if not self.dir or not _SAFE.fullmatch(name):
            return None
        p = self.dir / name
        return p if p.is_file() else None

    def sha256(self, p: Path) -> str:
        m = p.stat().st_mtime
        hit = self._sums.get(p.name)
        if hit and hit[0] == m:
            return hit[1]
        h = hashlib.sha256()
        with open(p, "rb") as f:
            while b := f.read(1 << 20):
                h.update(b)
        self._sums[p.name] = (m, h.hexdigest())
        return h.hexdigest()

    def latest(self) -> Path | None:
        """The real installer file behind the LATEST symlink."""
        p = self.path(LATEST)
        return p.resolve() if p else None

    def sums(self) -> str:
        if not self.dir or not self.dir.is_dir():
            return ""
        files = sorted(p for p in self.dir.iterdir() if p.is_file() and p.suffix == ".run")
        return "".join(f"{self.sha256(p)}  {p.name}\n" for p in files)


def render_site(downloads: Downloads) -> bytes:
    from . import __version__
    p = downloads.latest()
    released = size = ""
    if p:
        st = p.stat()
        t = time.localtime(st.st_mtime)
        released = f"{time.strftime('%b', t)} {t.tm_mday}, {t.tm_year}"
        size = f"{round(st.st_size / 1e6)} MB"
    page = SITE_PAGE.read_text(encoding="utf-8")
    if not released:
        page = page.replace(" · Released {{RELEASED}}", "")
    return (page.replace("{{VERSION}}", __version__).replace("{{RELEASED}}", released)
            .replace("{{SIZE}}", size or "about 230 MB").encode())


def make_handler(feed: Feed, trust_proxy: bool, downloads: Downloads | None = None, public_url: str = ""):
    site_cache: list = [0.0, b""]  # rendered page, refreshed every 60 s

    class H(BaseHTTPRequestHandler):
        server_version = "ScamStopFeed"

        def log_message(self, *a):
            pass

        def ip(self) -> str:
            if trust_proxy and self.headers.get("X-Forwarded-For"):
                return self.headers["X-Forwarded-For"].split(",")[0].strip()
            return self.client_address[0]

        def send(self, code, body, ctype="application/json", extra=None):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if not getattr(self, "_head_only", False):
                self.wfile.write(data)

        def body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2_000_000:
                raise ValueError("body too large")
            return json.loads(self.rfile.read(n) or b"{}") if n else {}

        def do_HEAD(self):
            self._head_only = True
            self.do_GET()

        def write_body(self, data: bytes):
            if not getattr(self, "_head_only", False):
                self.wfile.write(data)

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/":
                if downloads is not None and SITE_PAGE.exists():
                    if time.time() - site_cache[0] > 60:
                        site_cache[:] = [time.time(), render_site(downloads)]
                    return self.send(200, site_cache[1], "text/html; charset=utf-8",
                                     {"Cache-Control": "public, max-age=300"})
                return self.send(200, (PUBLIC_PAGE % feed.stats()).encode(), "text/html; charset=utf-8")
            if u.path == "/privacy" and PRIVACY_PAGE.exists():
                return self.send(200, PRIVACY_PAGE.read_bytes(), "text/html; charset=utf-8")
            if u.path.startswith("/assets/"):
                name = u.path[len("/assets/"):]
                p = WARNING_WAV if name == WARNING_WAV.name else ASSETS / name
                ctype = ASSET_TYPES.get(p.suffix)
                if not _SAFE.fullmatch(name) or not ctype or not p.is_file():
                    return self.send(404, {"error": "not found"})
                return self.send(200, p.read_bytes(), ctype, {"Cache-Control": "public, max-age=86400"})
            if u.path == "/install" and downloads is not None:
                url = public_url or f"https://{self.headers.get('Host', 'localhost')}"
                return self.send(200, INSTALL_SH.format(url=url.rstrip("/"), latest=LATEST).encode(), "text/x-shellscript")
            if u.path == "/download/SHA256SUMS" and downloads is not None:
                return self.send(200, downloads.sums().encode(), "text/plain")
            if u.path.startswith("/download/") and downloads is not None:
                p = downloads.path(u.path[len("/download/"):])
                if not p:
                    return self.send(404, {"error": "not found"})
                size = p.stat().st_size
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(size))
                self.send_header("Content-Disposition", f'attachment; filename="{p.name}"')
                self.end_headers()
                if not getattr(self, "_head_only", False):
                    with open(p, "rb") as f:
                        while b := f.read(1 << 20):
                            self.wfile.write(b)
                return
            if u.path == "/v1/stats":
                return self.send(200, feed.stats())
            if u.path == "/v1/indicators":
                if not feed.auth(self.headers.get("Authorization", "")):
                    return self.send(401, {"error": "register first"})
                etag, data = feed.indicators_json()
                if self.headers.get("If-None-Match") == etag:
                    return self.send(304, b"", extra={"ETag": etag})
                return self.send(200, data, extra={"ETag": etag})
            return self.send(404, {"error": "not found"})

        def do_POST(self):
            u = urlparse(self.path)
            try:
                if u.path == "/v1/register":
                    return self.send(200, feed.register(self.body().get("name", ""), self.ip()))
                if u.path == "/v1/subscribe":
                    b = self.body()
                    return self.send(200, feed.subscribe(str(b.get("email", "")), str(b.get("website", "")), self.ip()))
                if u.path == "/v1/report":
                    iid = feed.auth(self.headers.get("Authorization", ""))
                    if not iid:
                        return self.send(401, {"error": "bad key"})
                    return self.send(200, feed.report(iid, self.ip(), self.body()))
                return self.send(404, {"error": "not found"})
            except PermissionError as e:
                return self.send(429, {"error": str(e)})
            except (ValueError, KeyError) as e:
                return self.send(400, {"error": str(e)})

    return H


def serve(db: str, host: str, port: int, min_networks: int, ttl_days: int, trust_proxy: bool,
          downloads: str | None = None, public_url: str = ""):
    os.makedirs(os.path.dirname(os.path.abspath(db)), exist_ok=True)
    feed = Feed(db, min_networks, ttl_days)
    httpd = ThreadingHTTPServer((host, port), make_handler(feed, trust_proxy, Downloads(downloads) if downloads else None,
                                                          public_url))
    print(f"ScamStop feed on http://{host}:{port}  db={db}  min_networks={min_networks}  ttl={ttl_days}d")
    httpd.serve_forever()
