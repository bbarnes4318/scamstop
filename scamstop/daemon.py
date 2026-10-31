"""The live daemon.

Threads:
  main      every poll_s: reload config if it changed, end calls from blocked
            sources (the gatekeeper, so no switch config edits are needed),
            start listeners for new answered calls
  Listener  streams one side of one call from the platform, pushes 0.5 s chunks
  worker    (asr.workers of them) owns one recognizer, batch-decodes its calls,
            runs the matcher, calls Enforcer on hits
Queues are bounded: if a decoder falls behind, audio is dropped and counted
(dropped_chunks), never piled up in RAM.
"""
from __future__ import annotations

import json
import os
import queue
import re
import syslog
import threading
import time
import wave

import numpy as np

from . import audio, config as cfgmod, evidence
from .control import Dialog
from .platforms import Platform, number_of
from .rules import CallMatcher, CampaignGate, Hit, load_rules
from .store import Store

_IPV4 = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
DEFAULT_WARNING = os.path.join(os.path.dirname(__file__), "audio_files", "warning-en.wav")
# changing these sections needs a restart; everything else applies live
RESTART_SECTIONS = ("platform", "proxy", "rtpengine", "asterisk", "freeswitch", "asr", "redis")
GATE_LABELS = {"host": "call center (Call-ID IP)", "tag": "hosted dialer account", "cli": "spoofed caller ID",
               "dnc": "do-not-call number", "src": "source IP", "media": "call center (media IP)"}


def ensure_warning_file(path: str | None) -> None:
    """Install the bundled English warning if no recording is at the configured path."""
    if not path or os.path.exists(path):
        return
    try:
        import shutil
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        shutil.copyfile(DEFAULT_WARNING, path)
        os.chmod(path, 0o644)  # rtpengine / asterisk run as their own users and must read it
    except OSError as e:
        evidence.log(syslog.LOG_WARNING, f"SCAMSTOP could not install warning audio at {path}: {e}")


def wav_seconds(path: str) -> float | None:
    try:
        with wave.open(path) as w:
            return w.getnframes() / float(w.getframerate())
    except Exception:
        return None


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.v = {"listened": 0, "kills": 0, "flags": 0, "blocks": 0, "skipped_cap": 0, "rejected": 0,
                  "errors": 0, "dropped_chunks": 0, "cpu_seconds": 0.0, "active": 0, "warnings": 0}

    def inc(self, k, n=1):
        with self.lock:
            self.v[k] = self.v.get(k, 0) + n


class Enforcer:
    """Decides what a hit does. Separated from audio so it can be tested with fakes."""

    def __init__(self, cfg: dict, platform: Platform, store: Store, stats: Stats, tenants=None):
        self.cfg, self.platform, self.store, self.stats, self.tenants = cfg, platform, store, stats, tenants

    @property
    def dry(self) -> bool:
        return bool(self.cfg["dry_run"])

    def tenant(self, dlg: Dialog) -> dict | None:
        return self.tenants.for_ip(dlg.caller_ip) if self.tenants and dlg.caller_ip else None

    def settings(self, dlg: Dialog) -> tuple[bool, str, str | None]:
        """(dry_run, warn_mode, tenant_id) for this call: a tenant's own choices win in hosted mode."""
        t = self.tenant(dlg)
        if t:
            return t["dry_run"], t.get("warn_mode") or self.cfg["warn"]["mode"], t["id"]
        return self.dry, self.cfg["warn"]["mode"], None

    def center_of(self, dlg: Dialog) -> tuple[str | None, str | None]:
        """Who is really behind this call. Tries strategies in order."""
        c = self.cfg["centers"]
        for s in c["strategies"]:
            if s == "callid_host":
                host = dlg.callid.split("@")[-1].split("-")[0].split(":")[0] if "@" in dlg.callid else ""
                if _IPV4.fullmatch(host):
                    return "host", host
            elif s == "media_ip" and re.search(c["media_ip_callid_regex"], dlg.callid):
                ip = self.platform.media_ip(dlg)
                if ip:
                    return "media", ip
            elif s == "source_ip" and dlg.caller_ip:
                return "src", dlg.caller_ip
        if self.platform.name in ("asterisk", "freeswitch"):
            num = number_of(dlg.from_uri)  # no IPs to go on: strike the caller ID instead
            if len(num) == 10:
                return "cli", num
        return None, None

    def warn(self, dlg: Dialog) -> float | None:
        """Play the warning to the called party. Returns seconds to wait before hanging up."""
        w = self.cfg["warn"]
        try:
            secs = self.platform.warn(dlg, w.get("file"), w.get("play_to", "victim"))
        except Exception as e:
            evidence.log(syslog.LOG_WARNING, f"SCAMSTOP warn failed callid={dlg.callid} {e}")
            return None
        if secs is None:
            return None
        if not secs:
            secs = wav_seconds(w.get("file") or "") or float(w["max_wait_s"])
        return min(secs + 0.5, float(w["max_wait_s"]))

    def end(self, dlg: Dialog) -> None:
        try:
            self.platform.end(dlg)
        except Exception as e:
            evidence.log(syslog.LOG_ERR, f"SCAMSTOP kill failed callid={dlg.callid} {e}")

    def _unmute(self, dlg: Dialog) -> None:
        try:
            self.platform.unmute(dlg)
        except Exception as e:
            evidence.log(syslog.LOG_WARNING, f"SCAMSTOP unmute failed callid={dlg.callid} {e}")

    def end_later(self, dlg: Dialog, secs: float) -> None:
        t = threading.Timer(secs, self.end, args=(dlg,))
        t.daemon = True
        t.start()

    def gate(self, dlg: Dialog, kind: str, value: str) -> None:
        """A call from a blocked source: end it (no warning; nothing was said yet)."""
        ev = self.cfg["evidence"]
        dry, _, tid = self.settings(dlg)
        if not dry:
            self.end(dlg)
            self.stats.inc("rejected")
        reason = self.store.r.hget(f"{self.store.p}block:{kind}:why", value) or ""
        evidence.write(ev["kill_log"], {"dry": dry, "tenant": tid, "rule": f"blocked_{kind}", "rule_name": f"Blocked {GATE_LABELS[kind]}",
                                        "category": "blocked", "action": "kill", "matched": value, "side": "gate",
                                        "callid": dlg.callid, "src": dlg.caller_ip, "from": dlg.from_uri, "to": dlg.to_uri,
                                        "center_kind": kind, "center": value, "block_reason": reason,
                                        "hung_up": not dry, "ringing": dlg.state != "up"})
        evidence.log(syslog.LOG_WARNING, f"SCAMSTOP-GATE dry={int(dry)} tenant={tid} {kind}={value} callid={dlg.callid} to={dlg.to_uri}")

    def handle(self, dlg: Dialog, hit: Hit, text: str, side: str = "caller") -> None:
        ev = self.cfg["evidence"]
        dry, mode, tid = self.settings(dlg)
        record = {"dry": dry, "tenant": tid, "rule": hit.rule_id, "rule_name": hit.name, "category": hit.category,
                  "action": hit.action, "matched": hit.matched, "side": side, "callid": dlg.callid, "src": dlg.caller_ip,
                  "from": dlg.from_uri, "to": dlg.to_uri,
                  "transcript": evidence.trim(text, ev["transcript"], self.cfg["rules"]["window"])}
        if hit.action == "flag":
            self.stats.inc("flags")
            if not dry and self.cfg["warn"]["on_flag"] and mode != "off":
                record["warned"] = self.warn(dlg) is not None
            evidence.write(ev["flag_log"], record)
            evidence.log(syslog.LOG_NOTICE, f"SCAMSTOP-FLAG rule={hit.rule_id} callid={dlg.callid} matched=\"{hit.matched}\"")
            return

        kind, center = self.center_of(dlg)
        blocked, strikes, warned, hung_up = False, 0, False, False
        if not dry:
            wait = self.warn(dlg) if mode in ("warn_then_hangup", "warn_only") else None
            warned = wait is not None
            if warned:
                self.stats.inc("warnings")
            if mode == "warn_only" and warned:
                t = threading.Timer(wait, self._unmute, args=(dlg,))  # the person heard it; the call goes on
                t.daemon = True
                t.start()
            elif warned:
                self.end_later(dlg, wait)
                hung_up = True
            else:
                self.end(dlg)  # hang up now (mode off, or the warning couldn't play)
                hung_up = True
            if hung_up:
                self.stats.inc("kills")
            c = self.cfg["centers"]
            protected = c["never_block_customer_ip"] and center == dlg.caller_ip
            if center and not protected:
                strikes = self.store.add_strike(kind, center, dlg.callid, c["strike_window_s"])
                if strikes >= c["strikes_to_block"] and not self.store.is_blocked(kind, center):
                    self.store.block(kind, center, c["block_ttl_s"], f"{hit.rule_id} x{strikes}")
                    self.stats.inc("blocks")
                    blocked = True
        record.update({"center_kind": kind, "center": center, "strikes": strikes, "center_blocked": blocked,
                       "warned": warned, "hung_up": hung_up})
        evidence.write(ev["kill_log"], record)
        evidence.log(syslog.LOG_WARNING,
                     f"SCAMSTOP-KILL dry={int(dry)} tenant={tid} rule={hit.rule_id} warned={int(warned)} hung_up={int(hung_up)} "
                     f"center={center} blocked={int(blocked)} src={dlg.caller_ip} to={dlg.to_uri} callid={dlg.callid} "
                     f"matched=\"{hit.matched}\"")


class Listener(threading.Thread):
    """Streams one party's audio. side: caller (the dialer) or victim (the called party)."""

    def __init__(self, dlg: Dialog, q: queue.Queue, platform: Platform, quiet_rms: int, stats: Stats,
                 side: str = "caller"):
        super().__init__(daemon=True)
        self.dlg, self.q, self.platform, self.quiet_rms, self.stats = dlg, q, platform, quiet_rms, stats
        self.side = side
        self.key = (dlg.callid, side)
        self.stop = False
        self.t0 = int(time.time())

    def run(self):
        try:
            buf, n, was_quiet = [], 0, False
            for frame in self.platform.audio(self.dlg, self.side, lambda: self.stop):
                buf.append(frame)
                n += len(frame)
                if n >= 4000:  # 0.5 s at 8 kHz
                    pcm = np.concatenate(buf)
                    buf, n = [], 0
                    # skip silence (each side is quiet while the other talks); one quiet
                    # chunk still goes through so the recognizer can close the utterance
                    quiet = audio.rms(pcm) < self.quiet_rms
                    if not (quiet and was_quiet):
                        try:
                            self.q.put_nowait((self, audio.upsample_8k_16k(pcm) / 32768.0))
                        except queue.Full:
                            self.stats.inc("dropped_chunks")
                    was_quiet = quiet
        except Exception as e:
            self.stats.inc("errors")
            evidence.log(syslog.LOG_WARNING, f"SCAMSTOP listen error side={self.side} callid={self.dlg.callid} {e}")
        finally:
            self.q.put((self, None))  # blocking: the worker must free this call's state


class Daemon:
    def __init__(self, cfg: dict, config_path: str | None = None, platform: Platform | None = None):
        self.cfg, self.config_path = cfg, config_path
        self.cfg_mtime = os.path.getmtime(config_path) if config_path and os.path.exists(config_path) else 0
        self.stats = Stats()
        self.status: dict = {"started": int(time.time()), "restart_needed": [], "model": {"state": "ready"}}
        r = cfg["redis"]
        self.store = Store.from_url(r["url"], prefix=r["prefix"], customer_key=r["customer_key"],
                                    customer_cache_s=r["customer_cache_s"])
        from . import platforms
        self.platform = platform or platforms.make(cfg)
        self.tenants = None
        if cfg.get("hosted", {}).get("enabled"):
            from .tenants import Tenants
            self.tenants = Tenants(self.store, cfg["hosted"])
        self.enf = Enforcer(cfg, self.platform, self.store, self.stats, self.tenants)
        self.listeners: dict[str, list[Listener]] = {}  # callid -> caller (+ victim) listeners
        self.killed: set[str] = set()
        self.klock = threading.Lock()
        self.gated: set[str] = set()      # calls the gatekeeper has checked
        self.gate_hits: set[str] = set()  # ...and the ones it ended
        self.feed_thread = None
        self.recs, self.queues = [], []
        self.apply_live(cfg)

    # config ------------------------------------------------------------------
    def apply_live(self, cfg: dict) -> None:
        """(Re)build everything that can change without a restart."""
        self.cfg = cfg
        self.enf.cfg = cfg
        if self.tenants:
            self.tenants.h = cfg.get("hosted", {})
        self.rules = load_rules(cfg["rules"]["packs"], cfg["rules"]["disabled"], cfg["rules"]["actions"])
        self.gate = CampaignGate.from_config(cfg["campaigns"])
        ensure_warning_file(cfg["warn"].get("file"))
        w = cfg["evidence"].get("watch_regex")
        self.watch = re.compile(w) if w else None
        self.on_text, self.smart = None, None
        if cfg["smart"]["enabled"]:
            from .smart import SmartCheck
            self.smart = SmartCheck(cfg["smart"], self.smart_hit)
            self.on_text = self.smart.observe
        if cfg["feed"]["enabled"] and not (self.feed_thread and self.feed_thread.is_alive()):
            self.feed_thread = threading.Thread(target=self.feed_loop, daemon=True)
            self.feed_thread.start()

    def check_reload(self) -> None:
        if not self.config_path or not os.path.exists(self.config_path):
            return
        mtime = os.path.getmtime(self.config_path)
        if mtime == self.cfg_mtime:
            return
        self.cfg_mtime = mtime
        try:
            new = cfgmod.load(self.config_path)
        except Exception as e:
            evidence.log(syslog.LOG_ERR, f"SCAMSTOP config not reloaded, it has an error: {e}")
            self.status["config_error"] = str(e)
            return
        self.status.pop("config_error", None)
        pending = sorted({k for k in RESTART_SECTIONS if new.get(k) != self.cfg.get(k)} | set(self.status["restart_needed"]))
        keep = {k: self.cfg[k] for k in RESTART_SECTIONS if k in self.cfg}
        self.apply_live({**new, **keep})
        self.status["restart_needed"] = pending
        self.status["reloaded"] = int(time.time())
        evidence.log(syslog.LOG_INFO, "SCAMSTOP config reloaded" + (f"; restart needed for {pending}" if pending else ""))

    def write_status(self) -> None:
        path = self.cfg.get("status_file")
        if not path:
            return
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path + ".tmp", "w") as f:
                json.dump(dict(self.status, ts=int(time.time()), platform=self.platform.name), f)
            os.replace(path + ".tmp", path)
        except OSError:
            pass

    def load_model(self) -> None:
        from . import model
        from .asr import make_recognizer
        a = self.cfg["asr"]
        if not model.present(a["model_dir"]):
            self.status["model"] = {"state": "downloading", "percent": 0}
            self.write_status()

            def progress(p):
                self.status["model"] = {"state": "downloading", "percent": p}
                if p % 5 == 0:
                    self.write_status()
            try:
                model.ensure(a["model_dir"], a.get("model_url"), progress)
            except Exception as e:
                self.status["model"] = {"state": "error", "message": str(e)}
                self.write_status()
                raise SystemExit(f"could not download the speech model: {e}")
        self.recs = [make_recognizer(a["model_dir"]) for _ in range(a["workers"])]
        self.queues = [queue.Queue(maxsize=a["queue_max"]) for _ in range(a["workers"])]
        self.status["model"] = {"state": "ready"}

    # worker ------------------------------------------------------------------
    def smart_hit(self, lst, hit, text: str) -> None:
        if hit.action == "kill" and not self.stop_call(lst.dlg.callid):
            return
        self.enf.handle(lst.dlg, hit, text, "caller")

    def stop_call(self, cid: str) -> bool:
        """Mark a call killed and stop all its listeners. False if it was already killed."""
        with self.klock:
            if cid in self.killed:
                return False
            self.killed.add(cid)
        for lst in self.listeners.get(cid, []):
            lst.stop = True
        return True

    def worker(self, rec, q: queue.Queue):
        calls: dict[tuple, tuple] = {}  # (callid, side) -> (stream, matcher)
        while True:
            items = [q.get()]
            while len(items) < 5000:
                try:
                    items.append(q.get_nowait())
                except queue.Empty:
                    break
            try:
                ev = self.cfg["evidence"]
                touched = set()
                for lst, samples in items:
                    key, cid = lst.key, lst.dlg.callid
                    if samples is None:
                        st = calls.pop(key, None)
                        touched.discard(lst)
                        if not st:
                            continue
                        s, m = st
                        tail = rec.get_result(s)
                        if lst.side == "caller" and m.needs_review(tail):
                            evidence.write(ev["review_log"], {"callid": cid, "start": lst.t0, "src": lst.dlg.caller_ip,
                                                              "off_word": m.off and m.off[1], "from": lst.dlg.from_uri,
                                                              "to": lst.dlg.to_uri, "transcript": m.text(tail)})
                        if self.watch and self.watch.search(cid):
                            evidence.write(ev["watch_log"], {"callid": cid, "side": lst.side, "start": lst.t0,
                                                             "killed": cid in self.killed, "transcript": m.text(tail)})
                        continue
                    if key not in calls:
                        calls[key] = (rec.create_stream(),
                                      CallMatcher(self.rules, self.gate, self.cfg["rules"]["window"], lst.side))
                    s, m = calls[key]
                    if not m.killed and cid not in self.killed:
                        s.accept_waveform(16000, samples.astype(np.float32))
                        touched.add(lst)
                t0 = time.thread_time()
                while ready := [calls[l.key][0] for l in touched if rec.is_ready(calls[l.key][0])]:
                    rec.decode_streams(ready)
                self.stats.inc("cpu_seconds", time.thread_time() - t0)
                for lst in touched:
                    s, m = calls[lst.key]
                    said = rec.get_result(s)
                    for hit in m.update(said):
                        if hit.action == "kill" and not self.stop_call(lst.dlg.callid):
                            continue  # the other side already got this call killed
                        self.enf.handle(lst.dlg, hit, m.text(said), lst.side)
                    if m.killed or lst.dlg.callid in self.killed:
                        lst.stop = True
                    if self.on_text:
                        self.on_text(lst, m, said)
                    if rec.is_endpoint(s):
                        m.commit(said)
                        rec.reset(s)
            except Exception as e:
                self.stats.inc("errors")
                evidence.log(syslog.LOG_ERR, f"SCAMSTOP worker error {e!r}")

    def feed_loop(self):
        from .feed import FeedClient
        while self.cfg["feed"]["enabled"]:
            client = FeedClient(self.cfg, self.store)
            r = client.sync_safe()
            if r is None:
                evidence.log(syslog.LOG_WARNING, f"SCAMSTOP feed sync failed: {client.state.get('last_error')}")
            elif r.get("added") or r.get("removed"):
                evidence.log(syslog.LOG_INFO, f"SCAMSTOP feed +{r.get('added', 0)} -{r.get('removed', 0)} "
                                              f"active={r.get('active')} shared={r.get('shared')}")
            time.sleep(max(60, int(self.cfg["feed"]["sync_s"])))

    # gatekeeper ----------------------------------------------------------------
    def blocked_source(self, d: Dialog) -> tuple[str, str] | None:
        """Is this call from something on a block list? Checked once per call, no switch edits needed."""
        checks = []
        if "@" in d.callid:
            host = d.callid.split("@")[-1].split("-")[0].split(":")[0]
            if _IPV4.fullmatch(host):
                checks.append(("host", host))
        m = re.match(r"(CNX\d+)_", d.callid)
        if m:
            checks.append(("tag", m.group(1)))
        fnum, tnum = number_of(d.from_uri), number_of(d.to_uri)
        if len(fnum) == 10:
            checks.append(("cli", fnum))
        if len(tnum) == 10:
            checks.append(("dnc", tnum))
        if d.caller_ip:
            checks.append(("src", d.caller_ip))
        for kind, value in checks:
            if kind in self.platform.gate_kinds and self.store.is_blocked(kind, value):
                return kind, value
        return None

    def gatekeep(self, calls: list[Dialog]) -> set[str]:
        """End calls from blocked sources. Returns the Call-IDs that were ended."""
        ended = set()
        if not self.cfg.get("gate", {}).get("enabled", True):
            return ended
        for d in calls:
            if d.callid in self.gated:          # checked before: only blocked ones count as ended
                if d.callid in self.gate_hits:
                    ended.add(d.callid)
                continue
            if d.state != "up" and not self.platform.can_end_ringing:
                continue  # check again once it's answered
            hit = self.blocked_source(d)
            if not hit and d.state == "up" and self.store.r.scard(f"{self.store.p}block:media"):
                ip = self.platform.media_ip(d)
                if ip and self.store.is_blocked("media", ip):
                    hit = ("media", ip)
            self.gated.add(d.callid)
            if hit:
                self.gate_hits.add(d.callid)
                self.enf.gate(d, *hit)
                ended.add(d.callid)
        return ended

    # main loop -----------------------------------------------------------------
    def monitored(self, d: Dialog) -> bool:
        mon = self.cfg["monitor"]
        if d.caller_ip in mon["exclude_ips"]:
            return False
        if any(d.bind_addr.endswith(s) for s in mon["exclude_bind_suffix"]):
            return False
        if not d.caller_ip:
            return True  # Asterisk / FreeSWITCH: calls are chosen by the trunk pattern, not by source IP
        return self.store.is_customer(d.caller_ip)

    def write_metrics(self):
        path = self.cfg["metrics"].get("textfile")
        if not path:
            return
        with self.stats.lock:
            v = dict(self.stats.v, active=len(self.listeners))
        lines = [f"scamstop_{k} {val}" for k, val in v.items()] + [f"scamstop_last_poll_seconds {int(time.time())}"]
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path + ".tmp", "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(path + ".tmp", path)

    def poll_once(self, finished: set[str]) -> None:
        mon = self.cfg["monitor"]
        allc = self.platform.all_calls()
        seen = {d.callid for d in allc}
        ended = self.gatekeep([d for d in allc if self.monitored(d)])
        self.gated &= seen
        self.gate_hits &= seen
        live = set()
        for d in allc:
            if d.state != "up" or d.callid in ended or not self.monitored(d):
                continue
            live.add(d.callid)
            if d.callid in self.listeners or d.callid in finished:
                continue  # one listen per call, never re-subscribe
            if len(self.listeners) >= mon["max_streams"]:
                self.stats.inc("skipped_cap")
                continue
            q = self.queues[hash(d.callid) % len(self.queues)]
            group = [Listener(d, q, self.platform, self.cfg["asr"]["quiet_rms"], self.stats, "caller")]
            if mon.get("listen_victim") and self.platform.victim_available(d):
                group.append(Listener(d, q, self.platform, self.cfg["asr"]["quiet_rms"], self.stats, "victim"))
            self.listeners[d.callid] = group
            self.stats.inc("listened")
            if self.tenants:
                t = self.tenants.for_ip(d.caller_ip)
                if t:
                    self.tenants.touch(t["id"])
            for lst in group:
                lst.start()
        for cid in list(self.listeners):
            if cid not in live or not any(l.is_alive() for l in self.listeners[cid]):
                for l in self.listeners.pop(cid):
                    l.stop = True
                finished.add(cid)
                if self.smart:
                    self.smart.forget(cid)
                with self.klock:
                    self.killed.discard(cid)
        finished &= live

    def run(self):
        syslog.openlog("scamstop")
        self.load_model()
        evidence.log(syslog.LOG_INFO, f"SCAMSTOP start platform={self.platform.name} dry={int(self.cfg['dry_run'])} "
                                      f"rules={len(self.rules)} campaign_gate={int(self.gate.enabled)}")
        workers = [threading.Thread(target=self.worker, args=a, daemon=True) for a in zip(self.recs, self.queues)]
        for w in workers:
            w.start()
        finished, last_sweep = set(), 0.0
        while True:
            if not all(w.is_alive() for w in workers):
                raise SystemExit("decode worker died")  # systemd restarts us
            flag = os.path.join(os.path.dirname(self.cfg.get("status_file") or "/var/lib/scamstop/x"), "restart-request")
            if os.path.exists(flag):
                os.remove(flag)
                evidence.log(syslog.LOG_INFO, "SCAMSTOP restarting on request from the panel")
                raise SystemExit(0)  # systemd / docker start us again with the new settings
            try:
                self.check_reload()
                self.poll_once(finished)
                if time.time() - last_sweep > 60:
                    n = self.store.sweep()
                    if n:
                        evidence.log(syslog.LOG_INFO, f"SCAMSTOP expired {n} blocks")
                    last_sweep = time.time()
                self.status.pop("platform_error", None)
            except Exception as e:
                self.stats.inc("errors")
                self.status["platform_error"] = str(e)[:300]
                evidence.log(syslog.LOG_ERR, f"SCAMSTOP poll error {e}")
            self.write_metrics()
            self.write_status()
            time.sleep(self.cfg["monitor"]["poll_s"])
