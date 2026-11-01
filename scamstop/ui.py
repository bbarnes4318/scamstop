"""Web control panel: `scamstop ui`. Standard library only.

Serves one page (web/index.html) and a small JSON API. Every /api call needs the
panel password as a Bearer token. Binds to 127.0.0.1 by default; put it behind
an SSH tunnel or a TLS reverse proxy before exposing it.
"""
from __future__ import annotations

import copy
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import yaml

from . import __version__, block603, config as cfgmod, control, policy
from .rtpengine import RtpEngine
from .rules import load_rules, normalize
from .store import KINDS, Store

HERE = Path(__file__).parent
PAGE = (HERE / "web" / "index.html").read_bytes
SNIPPETS = {"opensips": HERE / "snippets" / "opensips.cfg", "kamailio": HERE / "snippets" / "kamailio.cfg"}
AUDIO_MAGIC = (b"RIFF", b"ID3", b"\xff\xfb", b"\xff\xf3", b"OggS", b"fLaC")
RESTART_SECTIONS = ("platform", "proxy", "rtpengine", "asterisk", "freeswitch", "asr", "redis")
EDITABLE = ("hosted", "platform", "asterisk", "freeswitch", "gate", "warn", "feed", "smart", "dry_run", "redis", "proxy", "rtpengine", "monitor", "asr", "rules", "campaigns", "centers",
            "evidence", "metrics")

VALIDATORS = {
    "media": "ip", "host": "ip", "src": "ip",
    "tag": re.compile(r"^CNX\d+$"),
    "cli": re.compile(r"^[2-9]\d{9}$"),
    "dnc": re.compile(r"^[2-9]\d{9}$"),
}


def valid_value(kind: str, value: str) -> bool:
    v = VALIDATORS.get(kind)
    if v == "ip":
        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            return False
    return bool(v and v.fullmatch(value))


def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in over.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def tail_jsonl(path: str | None, limit: int, max_bytes: int = 512_000) -> list[dict]:
    if not path or not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - max_bytes))
        lines = f.read().decode(errors="replace").splitlines()
    if size > max_bytes:
        lines = lines[1:]  # first line is probably cut
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def read_metrics(path: str | None) -> dict:
    out = {}
    if path and os.path.exists(path):
        for line in Path(path).read_text().splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0].startswith("scamstop_"):
                try:
                    out[parts[0][9:]] = float(parts[1])
                except ValueError:
                    pass
    return out


class Panel:
    def __init__(self, config_path: str, password: str, allow_restart: bool, service: str = "scamstop"):
        self.config_path, self.password = config_path, password
        self.allow_restart, self.service = allow_restart, service
        self.last_restart: list[str] = []
        self.secret = secrets.token_hex(32)
        self.dl_status: dict | None = None

    # config ------------------------------------------------------------------
    def user_cfg(self) -> dict:
        p = Path(self.config_path)
        return (yaml.safe_load(p.read_text()) or {}) if p.exists() else {}

    def cfg(self) -> dict:
        return cfgmod._merge(cfgmod.DEFAULTS, self.user_cfg())

    def save_cfg(self, patch: dict, replace: tuple = ()) -> dict:
        """Deep-merge patch into the user's config. Sections in `replace` are swapped whole."""
        patch = {k: v for k, v in patch.items() if k in EDITABLE}
        new = _merge(self.user_cfg(), {k: v for k, v in patch.items() if k not in replace})
        new.update({k: v for k, v in patch.items() if k in replace})
        p = Path(self.config_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text("# Written by the ScamStop panel. Most changes apply live; the panel says when a restart is needed.\n"
                       + yaml.safe_dump(new, sort_keys=False))
        os.replace(tmp, p)
        self.last_restart = sorted(k for k in patch if k in RESTART_SECTIONS)
        if "hosted" in patch:
            try:
                self.tenants().resync_all()  # e.g. a new default termination
            except Exception:
                pass
        return self.cfg()

    def store(self, cfg=None) -> Store:
        r = (cfg or self.cfg())["redis"]
        return Store.from_url(r["url"], prefix=r["prefix"], customer_key=r["customer_key"])

    # status ------------------------------------------------------------------
    def status(self, who: str = "admin") -> dict:
        cfg = self.cfg()
        m = read_metrics(cfg["metrics"].get("textfile"))
        last = m.get("last_poll_seconds", 0)
        running = bool(last) and time.time() - last < 15
        midnight = time.mktime(time.localtime()[:3] + (0, 0, 0, 0, 0, -1))
        kills = tail_jsonl(cfg["evidence"]["kill_log"], 5000)
        flags = tail_jsonl(cfg["evidence"]["flag_log"], 5000)
        if who != "admin":
            return self.tenant_status(who, running, midnight, kills, flags)
        today_k = [k for k in kills if k.get("ts", 0) >= midnight]
        blocks = 0
        redis_ok = True
        try:
            st = self.store(cfg)
            blocks = sum(len(st.r.smembers(f"{st.p}block:{k}")) for k in ("media", "host", "tag", "src"))
        except Exception:
            redis_ok = False
        dstat = {}
        try:
            dstat = json.loads(Path(cfg["status_file"]).read_text())
        except (OSError, ValueError, KeyError):
            pass
        if self.dl_status:
            dstat["model"] = self.dl_status
        pol = policy.effective(cfg)
        cov = dstat.get("coverage") or {}
        return {
            "daemon": dstat, "platform": (cfg.get("platform") or {}).get("type") or cfg["proxy"]["type"],
            "version": __version__, "configured": Path(self.config_path).exists(),
            "running": running, "dry_run": pol.dry_run, "redis_ok": redis_ok,
            "carrier": policy.carrier_mode(cfg), "policy": pol.source, "warn_mode": pol.warn_mode,
            "mode": "offline" if not running else ("watching" if pol.dry_run else "protecting"),
            # never "complete" unless the daemon says nothing was skipped, dropped or unconfirmed
            "coverage": cov.get("status", "unknown") if running else "offline",
            "coverage_reasons": cov.get("reasons", []),
            "eligible": int(m.get("eligible", 0)), "skipped_cap": int(m.get("skipped_cap", 0)),
            "listener_failures": int(m.get("listener_failures", 0)),
            "enforce_failed": int(m.get("enforce_failed", 0)) + int(m.get("enforce_unknown", 0)),
            "queue_delay_seconds_max": m.get("queue_delay_seconds_max", 0),
            "active_calls": int(m.get("active", 0)), "listened": int(m.get("listened", 0)),
            "dropped_chunks": int(m.get("dropped_chunks", 0)), "errors": int(m.get("errors", 0)),
            "stopped_today": len([k for k in today_k if not k.get("dry")]),
            "would_stop_today": len([k for k in today_k if k.get("dry")]),
            "flags_today": len([f for f in flags if f.get("ts", 0) >= midnight]),
            "centers_blocked": blocks,
            "top_rules": self._top(today_k, "rule_name"),
            "hourly": self._hourly(today_k, midnight),
            "allow_restart": self.allow_restart,
        }

    @staticmethod
    def _top(events, key, n=5):
        counts = {}
        for e in events:
            counts[e.get(key) or e.get("rule")] = counts.get(e.get(key) or e.get("rule"), 0) + 1
        return sorted(({"name": k, "count": v} for k, v in counts.items()), key=lambda x: -x["count"])[:n]

    @staticmethod
    def _hourly(events, midnight):
        h = [0] * 24
        for e in events:
            i = int((e.get("ts", midnight) - midnight) // 3600)
            if 0 <= i < 24:
                h[i] += 1
        return h

    def events(self, limit: int, who: str = "admin") -> list[dict]:
        cfg = self.cfg()
        n = limit if who == "admin" else 20000  # a company sees only its own calls
        ev = [dict(e, kind="kill") for e in tail_jsonl(cfg["evidence"]["kill_log"], n)]
        ev += [dict(e, kind="flag") for e in tail_jsonl(cfg["evidence"]["flag_log"], n)]
        if who != "admin":
            ev = [e for e in ev if e.get("tenant") == who]
        labels = self.labels()
        for e in ev:
            e["label"] = labels.get(f"{e.get('callid')}|{e.get('rule')}")
        return sorted(ev, key=lambda e: -e.get("ts", 0))[:limit]

    # hosted: companies -----------------------------------------------------------
    def tenants(self):
        from .tenants import Tenants
        cfg = self.cfg()
        c = cfg.get("carrier") or {}
        return Tenants(self.store(cfg), cfg["hosted"], carrier=bool(c.get("enabled")), operator=c.get("operator") or "the carrier")

    def carrier(self) -> bool:
        return policy.carrier_mode(self.cfg())

    def public(self) -> dict:
        cfg = self.cfg()
        h = cfg["hosted"]
        carrier = policy.carrier_mode(cfg)
        return {"hosted": bool(h["enabled"]), "brand": h.get("brand") or "ScamStop",
                # carrier mode: accounts are created in the carrier's own portal, never here
                "signup_open": bool(h["enabled"] and h.get("signup_open") and not carrier),
                "support_email": h.get("support_email", ""), "carrier": carrier,
                "operator": (cfg.get("carrier") or {}).get("operator") if carrier else None}

    # carrier mode: customer deny records (sbc:fraud:v1:*) -------------------------------
    def fraud(self):
        from .fraud import FraudStore
        cfg = self.cfg()
        if not policy.carrier_mode(cfg):
            raise ValueError("carrier integration mode is off")
        return FraudStore.from_config(self.store(cfg).r, cfg)

    def fraud_status(self) -> dict:
        f = self.fraud()
        return {"denied": f.list(500), "audit": f.audit(100), "epoch": f.epoch()}

    def fraud_request(self, body: dict) -> dict:
        req = {k: body.get(k) for k in ("op", "customer_id", "reason_code", "case_id", "request_id",
                                        "expires_at", "expected_revision", "based_on_revision")}
        req["actor"] = "panel-admin"
        return self.fraud().apply_request(req)

    def connect_info(self) -> dict:
        h = self.cfg()["hosted"]
        return {"sbc_address": h.get("sbc_address", ""), "sbc_port": h.get("sbc_port", 5060),
                "sbc_transport": h.get("sbc_transport", "UDP"), "default_available": bool(h.get("default_carrier")),
                "default_label": h.get("default_carrier_label") or "Our termination",
                "brand": h.get("brand") or "ScamStop", "support_email": h.get("support_email", "")}

    def me(self, tid: str) -> dict:
        t = self.tenants().get(tid)
        if not t:
            raise PermissionError("account not found")
        return {"tenant": t, "connect": self.connect_info()}

    def tenant_status(self, tid, running, midnight, kills, flags) -> dict:
        t = self.tenants().get(tid) or {}
        pol = policy.effective(self.cfg(), t or None)
        mine_k = [k for k in kills if k.get("tenant") == tid and k.get("ts", 0) >= midnight]
        mine_f = [f for f in flags if f.get("tenant") == tid and f.get("ts", 0) >= midnight]
        ready = t.get("status") == "active" and t.get("ips") and t.get("route")
        mode = ("pending" if t.get("status") == "pending" else "suspended" if t.get("status") == "suspended"
                else "setup" if not ready else "offline" if not running
                else "watching" if pol.dry_run else "protecting")
        return {"role": "tenant", "tenant": t, "running": running, "mode": mode, "dry_run": pol.dry_run, "redis_ok": True,
                "policy_locked": pol.source == "carrier",
                "version": __version__, "configured": True, "daemon": {},
                "stopped_today": len([k for k in mine_k if not k.get("dry")]),
                "would_stop_today": len([k for k in mine_k if k.get("dry")]),
                "flags_today": len(mine_f), "centers_blocked": len({k.get("center") for k in mine_k if k.get("center_blocked")}),
                "active_calls": None, "last_call": int(t.get("last_call") or 0),
                "top_rules": self._top(mine_k, "rule_name"), "hourly": self._hourly(mine_k, midnight)}

    # review labels -------------------------------------------------------------
    def labels(self) -> dict:
        out = {}
        for r in tail_jsonl(self.cfg()["smart"]["labels_file"], 100000, max_bytes=20_000_000):
            out[f"{r.get('callid')}|{r.get('rule')}"] = r.get("label")
        return out

    def add_label(self, callid: str, rule: str, label: str, who: str = "admin") -> dict:
        if label not in ("scam", "not_scam"):
            raise ValueError("label must be scam or not_scam")
        cfg = self.cfg()
        match = next((e for e in tail_jsonl(cfg["evidence"]["kill_log"], 20000) + tail_jsonl(cfg["evidence"]["flag_log"], 20000)
                      if e.get("callid") == callid and e.get("rule") == rule and (who == "admin" or e.get("tenant") == who)), None)
        if not match:
            raise ValueError("no such event")
        path = cfg["smart"]["labels_file"]
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps({"ts": int(time.time()), "callid": callid, "rule": rule, "label": label,
                                "side": match.get("side", "caller"), "transcript": match.get("transcript") or ""}) + "\n")
        return {"ok": True}

    def smart_status(self) -> dict:
        cfg = self.cfg()
        sm = cfg["smart"]
        ev = [e for e in tail_jsonl(cfg["evidence"]["kill_log"], 50000) + tail_jsonl(cfg["evidence"]["flag_log"], 50000)
              if e.get("rule") == "smart_check"]
        labels = self.labels()
        reviewed = [labels.get(f"{e['callid']}|smart_check") for e in ev if labels.get(f"{e['callid']}|smart_check")]
        correct = sum(1 for l in reviewed if l == "scam")
        precision = correct / len(reviewed) if reviewed else None
        need = sm["proven"]
        proven = len(reviewed) >= need["min_reviewed"] and (precision or 0) >= need["min_precision"]
        return {"config": sm, "flags": len(ev), "reviewed": len(reviewed), "correct": correct,
                "precision": precision, "proven": proven, "need": need}

    def set_smart(self, patch: dict) -> dict:
        st = self.smart_status()
        if patch.get("mode") == "kill" and not st["proven"]:
            n = st["need"]
            raise ValueError(f"The smart check can hang up after {n['min_reviewed']} reviewed flags with at least "
                             f"{int(n['min_precision'] * 100)}% correct. So far: {st['reviewed']} reviewed"
                             + (f", {round(st['precision'] * 100)}% correct." if st["precision"] is not None else "."))
        allowed = {k: v for k, v in patch.items() if k in ("enabled", "mode", "threshold", "llm")}
        if "mode" in allowed and allowed["mode"] not in ("flag", "kill"):
            raise ValueError("mode must be flag or kill")
        self.save_cfg({"smart": allowed})
        return self.smart_status()

    def test_llm(self, llm_cfg: dict) -> dict:
        from .smart import LLMJudge
        cfg = _merge(self.cfg()["smart"]["llm"], llm_cfg or {})
        t0 = time.time()
        try:
            v = LLMJudge(cfg).judge("this is officer miller with the social security administration there is a warrant "
                                    "for your arrest you need to buy google play cards right now and do not tell anyone")
            ok = v["scam"]
            return {"ok": ok, "message": (f"Model answered in {time.time() - t0:.1f}s: "
                                          f"{'scam' if v['scam'] else 'not a scam'} ({v['confidence']:.2f}) {v['reason']}"
                                          + ("" if ok else " (it missed an obvious scam; try a bigger model)"))}
        except Exception as e:
            msg = str(e)
            if "refused" in msg:
                msg = f"Nothing is answering at {cfg['url']}. Is Ollama or your model server running?"
            elif "timed out" in msg:
                msg = "The model took too long to answer. Try a smaller model or raise timeout_s."
            elif "404" in msg:
                msg = f"The server answered but has no model called {cfg['model']}. For Ollama: ollama pull {cfg['model']}"
            return {"ok": False, "message": msg}

    # connection tests ---------------------------------------------------------
    def test(self, what: str, body: dict) -> dict:
        cfg = _merge(self.cfg(), {k: v for k, v in body.items() if k in EDITABLE})
        t0 = time.time()
        try:
            if what == "redis":
                Store.from_url(cfg["redis"]["url"]).r.ping()
                msg = "Redis answered."
            elif what == "rtpengine":
                r = RtpEngine(cfg["rtpengine"]["host"], int(cfg["rtpengine"]["port"]), timeout=2).ng({"command": "ping"})
                if r.get("result") != "pong":
                    raise RuntimeError(f"unexpected reply {r}")
                msg = "rtpengine answered."
            elif what in ("proxy", "platform"):
                from . import platforms
                msg = platforms.make(cfg).check()
            else:
                return {"ok": False, "message": "unknown test"}
            return {"ok": True, "message": msg, "ms": int((time.time() - t0) * 1000)}
        except ConnectionRefusedError:
            return {"ok": False, "message": "Connection refused. Is the service running and listening on that address?"}
        except (TimeoutError, OSError) as e:
            if "timed out" in str(e) or isinstance(e, TimeoutError):
                return {"ok": False, "message": "No answer. Check the host, port and firewall."}
            return {"ok": False, "message": str(e)}
        except Exception as e:
            return {"ok": False, "message": f"{type(e).__name__}: {e}"}

    # rules -------------------------------------------------------------------
    def rules(self) -> list[dict]:
        cfg = self.cfg()
        r = cfg["rules"]
        out = []
        for rule in load_rules(r["packs"]):
            state = "off" if rule.id in r["disabled"] else r["actions"].get(rule.id, rule.action)
            out.append({"id": rule.id, "name": rule.name, "category": rule.category, "default": rule.action,
                        "state": state, "example": rule.examples["hit"][0]})
        return out

    def set_rule(self, rid: str, state: str) -> dict:
        cfg = self.cfg()
        known = {r.id: r.action for r in load_rules(cfg["rules"]["packs"])}
        if rid not in known or state not in ("off", "kill", "flag"):
            raise ValueError("bad rule or state")
        r = copy.deepcopy(cfg["rules"])
        r["disabled"] = [x for x in r["disabled"] if x != rid] + ([rid] if state == "off" else [])
        r["actions"] = {k: v for k, v in r["actions"].items() if k != rid}
        if state != "off" and state != known[rid]:
            r["actions"][rid] = state
        self.save_cfg({"rules": r}, replace=("rules",))
        return {"ok": True}

    def scan(self, text: str) -> dict:
        cfg = self.cfg()
        r = cfg["rules"]
        heard = normalize(text)
        hits = []
        for rule in load_rules(r["packs"], r["disabled"], r["actions"]):  # every match, not just the first
            m = rule.search(heard)
            if m:
                hits.append({"rule_id": rule.id, "name": rule.name, "action": rule.action, "matched": m.group(0)})
        hits.sort(key=lambda h: h["action"] != "kill")
        return {"hits": hits, "killed": any(h["action"] == "kill" for h in hits), "heard": heard}

    # customers ---------------------------------------------------------------
    def customers(self) -> dict:
        cfg = self.cfg()
        key = cfg["redis"]["customer_key"]
        if not key:
            return {"mode": "all", "ips": []}
        st = self.store(cfg)
        pre, post = key.split("{ip}")
        ips = sorted(k[len(pre):len(k) - len(post)] for k in st.r.scan_iter(f"{pre}*{post}", count=500))
        return {"mode": "listed", "ips": ips}

    def set_customer(self, ip: str, add: bool) -> dict:
        ipaddress.IPv4Address(ip)
        cfg = self.cfg()
        if policy.carrier_mode(cfg):
            raise PermissionError("in carrier mode the customer registry belongs to the carrier's portal")
        key = cfg["redis"]["customer_key"]
        if not key:
            raise ValueError("monitoring every call; switch to listed customers first")
        r = self.store(cfg).r
        if add:
            r.set(key.format(ip=ip), 1)
        else:
            r.delete(key.format(ip=ip))
        return {"ok": True}

    # warning audio -----------------------------------------------------------
    def warning_path(self) -> str:
        from .daemon import ensure_warning_file
        path = self.cfg()["warn"]["file"]
        ensure_warning_file(path)
        return path

    def set_warning(self, data: bytes | None) -> dict:
        from .daemon import DEFAULT_WARNING
        path = self.warning_path()
        if data is None:
            data = Path(DEFAULT_WARNING).read_bytes()
        elif not data.startswith(AUDIO_MAGIC):
            raise ValueError("upload a WAV, MP3, OGG or FLAC file")
        tmp = path + ".tmp"
        Path(tmp).write_bytes(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        return {"ok": True, "bytes": len(data)}

    # feed ----------------------------------------------------------------------
    def feed_client(self):
        from .feed import FeedClient
        cfg = self.cfg()
        return FeedClient(cfg, self.store(cfg))

    def feed_status(self) -> dict:
        cfg = self.cfg()
        try:
            c = self.feed_client()
            st = c.public_state()
            active = sum(1 for k in ("media", "host", "tag", "cli") for b in c.store.list_blocks(k)
                         if b["reason"].startswith("feed:"))
        except Exception as e:
            st, active = {"last_error": {"message": str(e)}}, 0
        return {"config": cfg["feed"], "state": st, "active": active}

    def feed_sync(self) -> dict:
        c = self.feed_client()
        r = c.sync_safe()
        return {"ok": r is not None, "result": r, "error": c.state.get("last_error")}

    # system check ------------------------------------------------------------
    def syscheck(self) -> dict:
        from . import syscheck
        det = syscheck.detect()
        cfg = self.cfg()
        st = self.status().get("daemon", {})
        return {"detect": det, "checks": syscheck.checks(cfg, det, st)}

    def apply_detected(self) -> dict:
        from . import syscheck
        det = syscheck.detect()
        if det["settings"]:
            self.save_cfg(det["settings"])
        return {"ok": True, "platform": det["platform"], "label": det["label"], "config": self.cfg()}

    def fix(self, action: str) -> dict:
        from . import syscheck
        if action == "fix_ari":
            r = syscheck.fix_ari()
            self.save_cfg({"platform": {"type": "asterisk"}, "asterisk": {"user": r["user"], "password": r["password"]}})
            return {"ok": True, "message": "ARI is on and the scamstop user was created"
                    + (" and Asterisk reloaded." if r["reloaded"] else ". Reload Asterisk to apply.")}
        if action == "download_model":
            from . import model
            d = self.cfg()["asr"]["model_dir"]
            if model.present(d):
                return {"ok": True, "message": "Already downloaded."}

            def run():
                try:
                    model.ensure(d, self.cfg()["asr"].get("model_url"),
                                 progress=lambda pct: setattr(self, "dl_status", {"state": "downloading", "percent": pct}))
                    self.dl_status = {"state": "ready"}
                except Exception as e:
                    self.dl_status = {"state": "error", "message": str(e)}
            self.dl_status = {"state": "downloading", "percent": 0}
            threading.Thread(target=run, daemon=True).start()
            return {"ok": True, "message": "Downloading the speech model in the background."}
        raise ValueError("unknown fix")

    def channel_names(self) -> dict:
        from . import platforms
        cfg = self.cfg()
        plat = platforms.make(cfg)
        names = plat.channel_names() if hasattr(plat, "channel_names") else []
        rx = re.compile((cfg.get(plat.name) or {}).get("external_regex") or "^$") if plat.name in ("asterisk", "freeswitch") else None
        return {"channels": [{"name": n, "matched": bool(rx and rx.search(n))} for n in names[:200]]}

    def restart(self) -> dict:
        """Ask the daemon to restart itself (it exits; systemd or docker starts it again).
        If it isn't running yet and we're allowed, start it with systemctl."""
        cfg = self.cfg()
        state = os.path.dirname(cfg.get("status_file") or "/var/lib/scamstop/status.json")
        os.makedirs(state, exist_ok=True)
        running = self.status().get("running")
        if running:
            Path(state, "restart-request").write_text(str(int(time.time())))
            return {"ok": True, "message": "Restarting ScamStop with the new settings…"}
        if self.allow_restart and shutil.which("systemctl"):
            p = subprocess.run(["systemctl", "restart", self.service], capture_output=True, text=True, timeout=30)
            return {"ok": p.returncode == 0, "message": "ScamStop started." if p.returncode == 0 else p.stderr.strip()}
        return {"ok": False, "message": f"ScamStop isn't running. Start it: sudo systemctl start {self.service} "
                                        f"(or docker compose up -d)"}


FAILS: dict[str, list[float]] = {}


def secret_for(config_path: str) -> str:
    f = Path(config_path).parent / "panel-secret"
    if f.exists():
        return f.read_text().strip()
    s = secrets.token_hex(32)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(s + "\n")
    os.chmod(f, 0o600)
    return s


TENANT_ROUTES = {("GET", "status"), ("GET", "events"), ("POST", "label"), ("GET", "me"), ("POST", "me"),
                 ("POST", "me/ips"), ("DELETE", "me/ips"), ("GET", "public")}


def make_handler(panel: Panel):
    class H(BaseHTTPRequestHandler):
        server_version = "ScamStop"

        def log_message(self, *a):
            pass

        def _send(self, code: int, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; media-src 'self' blob:")
            self.end_headers()
            self.wfile.write(data)

        def _who(self) -> str | None:
            """'admin', a tenant id, or None. Counts failures for the lockout."""
            from .tenants import read_token
            ip = self.client_address[0]
            now = time.time()
            fails = [t for t in FAILS.get(ip, []) if now - t < 600]
            if len(fails) >= 10:
                return None
            h = self.headers.get("Authorization", "")
            tok = h[7:] if h.startswith("Bearer ") else ""
            who = None
            if tok and hmac.compare_digest(tok, panel.password):
                who = "admin"
            elif tok:
                who = read_token(panel.secret, tok)
            if not who:
                FAILS[ip] = fails + [now]
            return who

        def _authed(self) -> bool:
            self.who = self._who()
            return self.who is not None

        def _locked(self) -> bool:
            return len([t for t in FAILS.get(self.client_address[0], []) if time.time() - t < 600]) >= 10

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}") if n else {}

        def _route(self, method: str):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path in ("/", "/index.html"):
                return self._send(200, PAGE(), "text/html; charset=utf-8")
            if not u.path.startswith("/api/"):
                return self._send(404, {"error": "not found"})
            pub = u.path[5:]
            if method == "GET" and pub == "public":
                return self._send(200, panel.public())
            if method == "POST" and pub in ("login", "signup"):
                from .tenants import make_token
                if self._locked():
                    return self._send(429, {"error": "too many wrong passwords, try again in 10 minutes"})
                try:
                    b = self._body()
                except ValueError:
                    return self._send(400, {"error": "bad request"})
                if pub == "login" and b.get("password") and not b.get("email"):
                    if hmac.compare_digest(str(b["password"]), panel.password):
                        return self._send(200, {"token": make_token(panel.secret, "admin"), "role": "admin"})
                    FAILS.setdefault(self.client_address[0], []).append(time.time())
                    return self._send(401, {"error": "wrong password"})
                if not panel.public()["hosted"]:
                    return self._send(404, {"error": "accounts are not enabled"})
                try:
                    if pub == "signup":
                        if not panel.public()["signup_open"]:
                            return self._send(403, {"error": "sign-ups are closed"})
                        t = panel.tenants().create(b.get("name", ""), b.get("email", ""), b.get("password", ""))
                    else:
                        t = panel.tenants().authenticate(b.get("email", ""), b.get("password", ""))
                        if not t:
                            FAILS.setdefault(self.client_address[0], []).append(time.time())
                            return self._send(401, {"error": "wrong email or password"})
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
                return self._send(200, {"token": make_token(panel.secret, t["id"]), "role": "tenant"})
            if not self._authed():
                locked = len([t for t in FAILS.get(self.client_address[0], []) if time.time() - t < 600]) >= 10
                return self._send(429 if locked else 401,
                                  {"error": "too many wrong passwords, try again in 10 minutes" if locked else "password required"})
            p = u.path[5:]
            who = self.who
            if who != "admin":
                if (method, p) not in TENANT_ROUTES:
                    return self._send(403, {"error": "not allowed"})
                if not panel.tenants().get(who):
                    return self._send(401, {"error": "account not found"})
            try:
                if method == "GET" and p == "me":
                    return self._send(200, panel.me(who))
                if method == "POST" and p == "me":
                    b = self._body()
                    allowed = {k: b[k] for k in ("name", "dry_run", "warn_mode", "carrier_mode", "carrier") if k in b}
                    return self._send(200, {"tenant": panel.tenants().update(who, **allowed)})
                if method == "POST" and p == "me/ips":
                    return self._send(200, {"tenant": panel.tenants().add_ip(who, str(self._body().get("ip", "")))})
                if method == "DELETE" and p == "me/ips":
                    return self._send(200, {"tenant": panel.tenants().remove_ip(who, q.get("ip", ""))})
                if method == "GET" and p == "tenants":
                    return self._send(200, {"tenants": panel.tenants().list(), "connect": panel.connect_info()})
                if method == "POST" and p.startswith("tenants/"):
                    tid, b = p.split("/", 1)[1], self._body()
                    T = panel.tenants()
                    if "status" in b:
                        T.set_status(tid, b["status"])
                    rest = {k: b[k] for k in ("name", "dry_run", "warn_mode", "carrier_mode", "carrier") if k in b}
                    if rest:
                        T.update(tid, **rest)
                    return self._send(200, {"tenant": T.get(tid)})
                if method == "DELETE" and p.startswith("tenants/"):
                    panel.tenants().delete(p.split("/", 1)[1])
                    return self._send(200, {"ok": True})
                if method == "GET" and p == "status":
                    return self._send(200, dict(panel.status(who), role="admin" if who == "admin" else "tenant"))
                if method == "GET" and p == "events":
                    return self._send(200, panel.events(min(int(q.get("limit", 100)), 1000), who))
                if method == "GET" and p == "config":
                    return self._send(200, {"path": panel.config_path, "config": panel.cfg()})
                if method == "POST" and p == "config":
                    c = panel.save_cfg(self._body())
                    return self._send(200, {"config": c, "restart": panel.last_restart})
                if method == "GET" and p == "syscheck":
                    return self._send(200, panel.syscheck())
                if method == "POST" and p == "syscheck/apply":
                    return self._send(200, panel.apply_detected())
                if method == "POST" and p == "syscheck/fix":
                    return self._send(200, panel.fix(self._body().get("action", "")))
                if method == "POST" and p == "platform/channels":
                    return self._send(200, panel.channel_names())
                if method == "POST" and p.startswith("test/"):
                    return self._send(200, panel.test(p[5:], self._body()))
                if method == "GET" and p == "rules":
                    return self._send(200, panel.rules())
                if method == "POST" and p == "rules":
                    b = self._body()
                    return self._send(200, panel.set_rule(b["id"], b["state"]))
                if method == "POST" and p == "scan":
                    return self._send(200, panel.scan(self._body().get("text", "")[:20000]))
                if method == "GET" and p == "blocks":
                    st = panel.store()
                    return self._send(200, {k: st.list_blocks(k) for k in KINDS})
                if method == "POST" and p == "blocks":
                    b = self._body()
                    kind, value = b.get("kind"), str(b.get("value", "")).strip()
                    if kind not in KINDS or not valid_value(kind, value):
                        return self._send(400, {"error": f"not a valid {kind} value"})
                    panel.store().block(kind, value, int(b.get("ttl") or 0), b.get("reason") or "added in panel")
                    return self._send(200, {"ok": True})
                if method == "DELETE" and p == "blocks":
                    return self._send(200, {"ok": panel.store().unblock(q["kind"], q["value"])})
                if method == "GET" and p == "customers":
                    return self._send(200, panel.customers())
                if method in ("POST", "DELETE") and p == "customers":
                    ip = (self._body().get("ip") if method == "POST" else q.get("ip", "")).strip()
                    return self._send(200, panel.set_customer(ip, method == "POST"))
                if method == "GET" and p == "snippet":
                    path = SNIPPETS.get(q.get("type", "opensips"))
                    return self._send(200, {"text": block603.fill(path.read_text(), panel.cfg().get("gate", {})) if path else "",
                                            "problems": block603.problems(panel.cfg().get("gate", {}))})
                if method == "GET" and p == "warning":
                    data = Path(panel.warning_path()).read_bytes()
                    ctype = "audio/wav" if data[:4] == b"RIFF" else "audio/mpeg"
                    return self._send(200, data, ctype)
                if method == "POST" and p == "warning":
                    n = int(self.headers.get("Content-Length") or 0)
                    if not 0 < n <= 5_000_000:
                        return self._send(400, {"error": "audio must be under 5 MB"})
                    return self._send(200, panel.set_warning(self.rfile.read(n)))
                if method == "DELETE" and p == "warning":
                    return self._send(200, panel.set_warning(None))
                if method == "POST" and p == "label":
                    b = self._body()
                    return self._send(200, panel.add_label(str(b.get("callid", "")), str(b.get("rule", "")), b.get("label"), who))
                if method == "GET" and p == "smart":
                    return self._send(200, panel.smart_status())
                if method == "POST" and p == "smart":
                    return self._send(200, panel.set_smart(self._body()))
                if method == "POST" and p == "smart/test-llm":
                    return self._send(200, panel.test_llm(self._body()))
                if method == "GET" and p == "fraud":
                    return self._send(200, panel.fraud_status())
                if method == "POST" and p == "fraud":
                    return self._send(200, panel.fraud_request(self._body()))
                if method == "GET" and p == "feed":
                    return self._send(200, panel.feed_status())
                if method == "POST" and p == "feed/sync":
                    return self._send(200, panel.feed_sync())
                if method == "POST" and p == "restart":
                    return self._send(200, panel.restart())
                return self._send(404, {"error": "not found"})
            except PermissionError as e:
                return self._send(403, {"error": str(e)})
            except (ValueError, KeyError) as e:
                return self._send(400, {"error": str(e)})
            except Exception as e:
                return self._send(500, {"error": f"{type(e).__name__}: {e}"})

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")

        def do_DELETE(self):
            self._route("DELETE")

    return H


def password_for(config_path: str) -> str:
    """Panel password: $SCAMSTOP_PANEL_PASSWORD, else a file beside the config, created on first run."""
    env = os.environ.get("SCAMSTOP_PANEL_PASSWORD")
    if env:
        return env
    pw_file = Path(config_path).parent / "panel-password"
    if pw_file.exists():
        return pw_file.read_text().strip()
    pw = secrets.token_urlsafe(12)
    pw_file.parent.mkdir(parents=True, exist_ok=True)
    pw_file.write_text(pw + "\n")
    os.chmod(pw_file, 0o600)
    return pw


def self_signed(cert: str, key: str) -> None:
    """Make a self-signed certificate with openssl if none exists."""
    if os.path.exists(cert) and os.path.exists(key):
        return
    import shutil as _sh
    if not _sh.which("openssl"):
        raise SystemExit("openssl not found: install it, or pass --tls-cert/--tls-key")
    os.makedirs(os.path.dirname(cert) or ".", exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                    "-subj", "/CN=scamstop", "-keyout", key, "-out", cert], check=True, capture_output=True)
    os.chmod(key, 0o600)


def serve(config_path: str, host: str = "127.0.0.1", port: int = 8090, allow_restart: bool = False,
          tls_cert: str | None = None, tls_key: str | None = None):
    pw = password_for(config_path)
    panel = Panel(config_path, pw, allow_restart)
    panel.secret = secret_for(config_path)
    httpd = ThreadingHTTPServer((host, port), make_handler(panel))
    scheme = "http"
    if tls_cert:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls_cert, tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    print(f"ScamStop panel on {scheme}://{host}:{port}\n  password: {pw}\n  config:   {config_path}")
    httpd.serve_forever()
