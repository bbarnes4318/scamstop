"""The live daemon.

Threads:
  main       every poll_s: reload config if it changed, re-check active calls against block
             lists and customer deny records (the gatekeeper, so no switch config edits are
             needed), start listeners for new answered calls
  Listener   streams one side of one call from the platform, pushes 0.5 s chunks
  worker     (asr.workers of them) owns one recognizer, batch-decodes its calls, runs the
             matcher, calls Enforcer on hits
  scheduler  delayed hang-ups (after a warning) and termination confirmation, on a small
             bounded worker pool (enforcement.workers)
Queues are bounded: if a decoder falls behind, audio is dropped and counted
(dropped_chunks), never piled up in RAM, and the protection status says "degraded".
"""
from __future__ import annotations

import collections
import json
import os
import queue
import re
import syslog
import threading
import time
import wave

import numpy as np

from . import attribution as attrmod
from . import audio, block603, config as cfgmod, enforcement, evidence, policy
from .control import Dialog
from .platforms import Platform, number_of
from .rules import CallEvidence, CallMatcher, CampaignGate, Hit, load_rules
from .store import Store

_IPV4 = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
DEFAULT_WARNING = os.path.join(os.path.dirname(__file__), "audio_files", "warning-en.wav")
# changing these sections needs a restart; everything else applies live
RESTART_SECTIONS = ("platform", "proxy", "rtpengine", "asterisk", "freeswitch", "asr", "redis", "carrier")
GATE_LABELS = {"host": "call center (Call-ID IP)", "tag": "hosted dialer account", "cli": "spoofed caller ID",
               "dnc": "do-not-call number", "src": "source IP", "media": "call center (media IP)"}
# what makes protection "degraded" in the status (each counted inside monitor.coverage_window_s)
DEGRADING = ("skipped_cap", "dropped_chunks", "listener_failures", "enforce_failed", "enforce_unknown",
             "fraud_store_errors", "victim_shed", "smart_llm_skipped_overload")


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
    """Counters (monotonic) and gauges, plus a rolling window of degrading events."""

    COUNTERS = ("eligible", "listened", "kills", "flags", "blocks", "skipped_cap", "skipped_excluded",
                "victim_shed", "rejected", "errors", "dropped_chunks", "listener_failures", "warnings",
                "enforce_requested", "enforce_confirmed", "enforce_failed", "enforce_unknown",
                "rechecks", "recheck_terminations", "denied_calls", "attribution_untrusted",
                "fraud_store_errors", "escalations", "cpu_seconds")

    def __init__(self, window_s: int = 300):
        self.lock = threading.Lock()
        self.v = {k: 0 for k in self.COUNTERS}
        self.v.update(active=0, cpu_seconds=0.0, queue_delay_seconds=0.0, queue_delay_seconds_max=0.0)
        self.window_s = window_s
        self.recent: collections.deque = collections.deque(maxlen=10000)

    def inc(self, k, n=1):
        with self.lock:
            self.v[k] = self.v.get(k, 0) + n
            if k in DEGRADING and n:
                self.recent.append((time.time(), k, n))

    def gauge(self, k, val):
        with self.lock:
            self.v[k] = val

    def queue_delay(self, secs: float):
        with self.lock:
            self.v["queue_delay_seconds"] = round(secs, 3)
            self.recent.append((time.time(), "queue_delay", secs))

    def coverage(self, warn_delay_s: float = 3.0) -> dict:
        """Is protection complete right now? Never claims so while anything was skipped,
        dropped or unconfirmed inside the window."""
        now = time.time()
        with self.lock:
            while self.recent and now - self.recent[0][0] > self.window_s:
                self.recent.popleft()
            counts: dict[str, float] = {}
            max_delay = 0.0
            for _, k, n in self.recent:
                if k == "queue_delay":
                    max_delay = max(max_delay, n)
                else:
                    counts[k] = counts.get(k, 0) + n
            self.v["queue_delay_seconds_max"] = round(max_delay, 3)
        reasons = sorted(k for k, n in counts.items() if n)
        if max_delay > warn_delay_s:
            reasons.append("queue_delay")
        return {"status": "degraded" if reasons else "complete", "reasons": reasons,
                "window_s": self.window_s, "counts": counts, "queue_delay_seconds_max": round(max_delay, 3)}


class Enforcer:
    """Decides what a hit does. Separated from audio so it can be tested with fakes."""

    def __init__(self, cfg: dict, platform: Platform, store: Store, stats: Stats, tenants=None,
                 fraud=None, scheduler: enforcement.Scheduler | None = None):
        self.cfg, self.platform, self.store, self.stats, self.tenants = cfg, platform, store, stats, tenants
        self.fraud = fraud
        if scheduler is None:
            scheduler = enforcement.Scheduler(int(cfg.get("enforcement", {}).get("workers", 4)))
            scheduler.start()
        self.scheduler = scheduler
        self.tracker = enforcement.Tracker(platform, cfg.get("enforcement", {}), scheduler, self._outcome)
        self.escalator = None
        if fraud is not None and policy.carrier_mode(cfg):
            from .escalation import Escalator
            self.escalator = Escalator(cfg, fraud, self._escalated)
        self.attr: dict[str, attrmod.Attribution] = {}  # callid -> attribution (set by the daemon)

    @property
    def dry(self) -> bool:
        return bool(self.cfg["dry_run"])

    def tenant(self, dlg: Dialog) -> dict | None:
        if policy.carrier_mode(self.cfg):
            return None  # carrier mode: identity comes from the switch, policy from the carrier
        return self.tenants.for_ip(dlg.caller_ip) if self.tenants and dlg.caller_ip else None

    def policy(self, dlg: Dialog) -> policy.Policy:
        return policy.effective(self.cfg, self.tenant(dlg))

    def settings(self, dlg: Dialog) -> tuple[bool, str, str | None]:
        """(dry_run, warn_mode, tenant_id) for this call."""
        p = self.policy(dlg)
        return p.dry_run, p.warn_mode, p.tenant_id

    def attribution(self, dlg: Dialog) -> attrmod.Attribution:
        return self.attr.get(dlg.callid) or attrmod.untrusted(dlg)

    def _ids(self, dlg: Dialog, tid: str | None) -> dict:
        a = self.attribution(dlg)
        out = {"tenant": tid}
        if policy.carrier_mode(self.cfg):
            out.update(tenant=a.customer_id if a.trusted else None, customer_id=a.customer_id, parent_id=a.parent_id,
                       endpoint=a.endpoint, attribution="trusted" if a.trusted else f"untrusted:{a.problem}")
        return out

    def center_of(self, dlg: Dialog) -> tuple[str | None, str | None]:
        """Who is really behind this call (a supporting indicator, never account identity)."""
        c = self.cfg["centers"]
        carrier = policy.carrier_mode(self.cfg)
        for s in c["strategies"]:
            if s == "callid_host":
                host = dlg.callid.split("@")[-1].split("-")[0].split(":")[0] if "@" in dlg.callid else ""
                if _IPV4.fullmatch(host):
                    return "host", host
            elif s == "media_ip" and re.search(c["media_ip_callid_regex"], dlg.callid):
                ip = self.platform.media_ip(dlg)
                if ip:
                    return "media", ip
            elif s == "source_ip" and dlg.caller_ip and not carrier:
                return "src", dlg.caller_ip  # carrier mode: accounts are escalated separately, not by IP
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

    # termination ----------------------------------------------------------------------------
    def end(self, dlg: Dialog, reason: str = "kill") -> bool:
        """Request termination and verify it (see enforcement.Tracker)."""
        return self.tracker.terminate(dlg, reason)

    def end_later(self, dlg: Dialog, secs: float, reason: str = "kill") -> None:
        self.tracker.terminate(dlg, reason, delay=secs)

    def _outcome(self, rec: enforcement.Record, dlg: Dialog) -> None:
        k = {enforcement.TERMINATION_REQUESTED: "enforce_requested", enforcement.TERMINATION_CONFIRMED: "enforce_confirmed",
             enforcement.FAILED: "enforce_failed", enforcement.UNKNOWN: "enforce_unknown"}.get(rec.state)
        if k and not (k == "enforce_requested" and rec.attempts > 1):
            self.stats.inc(k)
        a = self.attribution(dlg)
        evidence.write(self.cfg["evidence"].get("enforcement_log"),
                       {"callid": dlg.callid, "dialog_id": str(dlg.id), "state": rec.state, "reason": rec.reason,
                        "attempts": rec.attempts, "checks": rec.checks, "error": rec.error or None,
                        "customer_id": a.customer_id})
        if rec.state in (enforcement.FAILED, enforcement.UNKNOWN):
            evidence.log(syslog.LOG_ERR, f"SCAMSTOP-ENFORCE {rec.state} callid={dlg.callid} attempts={rec.attempts} {rec.error}")
        if self.fraud is not None:
            try:
                self.fraud.ack(dlg.callid, rec.state, dialog_id=dlg.id, reason=rec.reason, attempts=rec.attempts,
                               customer_id=a.customer_id, error=rec.error or None)
            except Exception:
                self.stats.inc("fraud_store_errors")

    def _unmute(self, dlg: Dialog) -> None:
        try:
            self.platform.unmute(dlg)
        except Exception as e:
            evidence.log(syslog.LOG_WARNING, f"SCAMSTOP unmute failed callid={dlg.callid} {e}")

    def _escalated(self, res: dict) -> None:
        self.stats.inc("escalations")
        evidence.write(self.cfg["evidence"].get("escalation_log"), res)
        evidence.log(syslog.LOG_WARNING, f"SCAMSTOP-ESCALATE customer={res.get('customer_id')} result={res.get('result')} "
                                         f"revision={res.get('revision')} kinds={res.get('kinds')}")

    # gate: blocked sources and denied customers ------------------------------------------------
    def gate(self, dlg: Dialog, kind: str, value: str) -> bool:
        """A call from a blocked source: end it (no warning; nothing was said yet). Returns
        True if termination was requested."""
        ev = self.cfg["evidence"]
        pol = self.policy(dlg)
        if not pol.dry_run:
            if dlg.state != "up" and self.platform.can_end_ringing:
                try:
                    self.platform.reject(dlg, block603.reason(self.cfg.get("gate", {})))
                    self.tracker.confirm(dlg, f"blocked_{kind}")
                except Exception as e:
                    evidence.log(syslog.LOG_WARNING, f"SCAMSTOP-GATE 603+ reject failed callid={dlg.callid}: {e}; ending the call")
                    self.end(dlg, f"blocked_{kind}")
            else:
                self.end(dlg, f"blocked_{kind}")
            self.stats.inc("rejected")
        reason = self.store.r.hget(f"{self.store.p}block:{kind}:why", value) or ""
        evidence.write(ev["kill_log"], {"dry": pol.dry_run, **self._ids(dlg, pol.tenant_id), "rule": f"blocked_{kind}",
                                        "rule_name": f"Blocked {GATE_LABELS[kind]}",
                                        "category": "blocked", "action": "kill", "matched": value, "side": "gate",
                                        "callid": dlg.callid, "src": dlg.caller_ip, "from": dlg.from_uri, "to": dlg.to_uri,
                                        "center_kind": kind, "center": value, "block_reason": reason,
                                        "origin": self.store.block_origin(kind, value),
                                        "hung_up": not pol.dry_run, "termination_requested": not pol.dry_run,
                                        "ringing": dlg.state != "up"})
        evidence.log(syslog.LOG_WARNING, f"SCAMSTOP-GATE dry={int(pol.dry_run)} tenant={pol.tenant_id} {kind}={value} callid={dlg.callid} to={dlg.to_uri}")
        return not pol.dry_run

    def deny(self, dlg: Dialog, who: str, record: dict) -> bool:
        """An active call from a quarantined/blocked customer account: end it."""
        pol = self.policy(dlg)
        if not pol.dry_run:
            self.end(dlg, f"customer_{record.get('state')}")
            self.stats.inc("denied_calls")
        evidence.write(self.cfg["evidence"]["kill_log"], {
            "dry": pol.dry_run, **self._ids(dlg, pol.tenant_id), "rule": "customer_denied", "rule_name": "Customer account denied",
            "category": "account", "action": "kill", "matched": f"{who} {record.get('state')}", "side": "gate",
            "callid": dlg.callid, "src": dlg.caller_ip, "from": dlg.from_uri, "to": dlg.to_uri,
            "deny_customer": record.get("customer_id"), "deny_state": record.get("state"),
            "deny_revision": record.get("revision"), "case_id": record.get("case_id"),
            "termination_requested": not pol.dry_run, "hung_up": not pol.dry_run})
        evidence.log(syslog.LOG_WARNING, f"SCAMSTOP-DENY dry={int(pol.dry_run)} customer={record.get('customer_id')} "
                                         f"state={record.get('state')} callid={dlg.callid}")
        return not pol.dry_run

    # hits ---------------------------------------------------------------------------------
    def more_evidence(self, dlg: Dialog, hit: Hit, side: str) -> None:
        if self.escalator is None or self.policy(dlg).dry_run:
            return
        try:
            self.escalator.record(self.attribution(dlg), hit, side)
        except Exception as e:
            self.stats.inc("fraud_store_errors")
            evidence.log(syslog.LOG_ERR, f"SCAMSTOP escalation failed callid={dlg.callid} {e}")

    def handle(self, dlg: Dialog, hit: Hit, text: str, side: str = "caller") -> bool:
        """Act on a hit. Returns True when termination of the call was requested (the daemon
        then stops listening). Dry-run and warn-only decisions return False: the call keeps
        being monitored."""
        ev = self.cfg["evidence"]
        pol = self.policy(dlg)
        record = {"dry": pol.dry_run, **self._ids(dlg, pol.tenant_id), "policy": pol.source, "rule": hit.rule_id,
                  "rule_name": hit.name, "category": hit.category, "action": hit.action, "strength": hit.strength,
                  "matched": hit.matched, "side": side, "callid": dlg.callid, "src": dlg.caller_ip,
                  "from": dlg.from_uri, "to": dlg.to_uri,
                  "transcript": evidence.trim(text, ev["transcript"], self.cfg["rules"]["window"])}
        if hit.note:
            record["note"] = hit.note
        if hit.action == "flag":
            self.stats.inc("flags")
            if not pol.dry_run and self.cfg["warn"]["on_flag"] and pol.warn_mode != "off":
                record["warned"] = self.warn(dlg) is not None
            evidence.write(ev["flag_log"], record)
            evidence.log(syslog.LOG_NOTICE, f"SCAMSTOP-FLAG rule={hit.rule_id} callid={dlg.callid} matched=\"{hit.matched}\"")
            return False

        kind, center = self.center_of(dlg)
        blocked, strikes, warned, terminate = False, 0, False, False
        escalation = None
        if not pol.dry_run:
            self.tracker.requested(dlg, hit.rule_id)
            wait = self.warn(dlg) if pol.warn_mode in ("warn_then_hangup", "warn_only") else None
            warned = wait is not None
            if warned:
                self.stats.inc("warnings")
                self.tracker.warning_started(dlg, hit.rule_id)
            if pol.warn_mode == "warn_only" and warned:
                self.scheduler.call_later(wait, self._unmute, dlg)  # the person heard it; the call goes on
            elif warned:
                self.end_later(dlg, wait, hit.rule_id)
                terminate = True
            else:
                self.end(dlg, hit.rule_id)  # hang up now (mode off, or the warning couldn't play)
                terminate = True
            if terminate:
                self.stats.inc("kills")
            c = self.cfg["centers"]
            protected = c["never_block_customer_ip"] and center == dlg.caller_ip
            if center and not protected:
                strikes = self.store.add_strike(kind, center, dlg.callid, c["strike_window_s"])
                if strikes >= c["strikes_to_block"] and not self.store.is_blocked(kind, center):
                    self.store.block(kind, center, c["block_ttl_s"], f"{hit.rule_id} x{strikes}")
                    self.stats.inc("blocks")
                    blocked = True
            if self.escalator is not None:
                try:
                    escalation = self.escalator.record(self.attribution(dlg), hit, side)
                except Exception as e:
                    self.stats.inc("fraud_store_errors")
                    evidence.log(syslog.LOG_ERR, f"SCAMSTOP escalation failed callid={dlg.callid} {e}")
        record.update({"center_kind": kind, "center": center, "strikes": strikes, "center_blocked": blocked,
                       "warned": warned, "hung_up": terminate, "termination_requested": terminate,
                       "enforcement": "pending_confirmation" if terminate else ("warning_only" if warned else "none")})
        if escalation:
            record["escalation"] = {k: escalation.get(k) for k in ("customer_id", "result", "revision")}
        evidence.write(ev["kill_log"], record)
        evidence.log(syslog.LOG_WARNING,
                     f"SCAMSTOP-KILL dry={int(pol.dry_run)} policy={pol.source} tenant={record.get('tenant')} rule={hit.rule_id} "
                     f"warned={int(warned)} termination_requested={int(terminate)} center={center} blocked={int(blocked)} "
                     f"src={dlg.caller_ip} to={dlg.to_uri} callid={dlg.callid} matched=\"{hit.matched}\"")
        return terminate


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
        self.failed = False

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
                            self.q.put_nowait((self, audio.upsample_8k_16k(pcm) / 32768.0, time.monotonic()))
                        except queue.Full:
                            self.stats.inc("dropped_chunks")
                    was_quiet = quiet
        except Exception as e:
            self.failed = True
            self.stats.inc("errors")
            self.stats.inc("listener_failures")
            evidence.log(syslog.LOG_WARNING, f"SCAMSTOP listen error side={self.side} callid={self.dlg.callid} {e}")
        finally:
            self.q.put((self, None))  # blocking: the worker must free this call's state


class Daemon:
    def __init__(self, cfg: dict, config_path: str | None = None, platform: Platform | None = None):
        self.cfg, self.config_path = cfg, config_path
        self.cfg_mtime = os.path.getmtime(config_path) if config_path and os.path.exists(config_path) else 0
        self.stats = Stats(int(cfg["monitor"].get("coverage_window_s", 300)))
        self.status: dict = {"started": int(time.time()), "restart_needed": [], "model": {"state": "ready"}}
        r = cfg["redis"]
        carrier = policy.carrier_mode(cfg)
        # carrier mode: who a call belongs to comes from the switch, not from sbc:cust:<contact host>
        self.store = Store.from_url(r["url"], prefix=r["prefix"], customer_key=None if carrier else r["customer_key"],
                                    customer_cache_s=r["customer_cache_s"])
        from . import platforms
        self.platform = platform or platforms.make(cfg)
        self.tenants = None
        if cfg.get("hosted", {}).get("enabled"):
            from .tenants import Tenants
            self.tenants = Tenants(self.store, cfg["hosted"], carrier=carrier)
        self.fraud = None
        if carrier:
            from .fraud import FraudStore
            self.fraud = FraudStore.from_config(self.store.r, cfg)
        self.enf = Enforcer(cfg, self.platform, self.store, self.stats, self.tenants, self.fraud)
        self.listeners: dict[str, list[Listener]] = {}  # callid -> caller (+ victim) listeners
        self.killed: set[str] = set()      # calls with a kill decision (one kill record per call)
        self.terminated: set[str] = set()  # ...and the ones whose termination was requested
        self.klock = threading.Lock()
        self.evidence_by_call: dict[str, CallEvidence] = {}
        self.gated: dict[str, tuple] = {}  # callid -> (epochs, checked_at) of the last gate check
        self.gate_hits: set[str] = set()   # calls the gatekeeper ended
        self.counted: set[str] = set()     # calls already counted as eligible
        self.feed_thread = None
        self.recs, self.queues = [], []
        self.apply_live(cfg)

    # config ------------------------------------------------------------------
    def apply_live(self, cfg: dict) -> None:
        """(Re)build everything that can change without a restart."""
        self.cfg = cfg
        self.enf.cfg = cfg
        self.stats.window_s = int(cfg["monitor"].get("coverage_window_s", 300))
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
            self.smart = SmartCheck(cfg["smart"], self.smart_hit, self.is_live)
            self.on_text = self.smart.observe
        self.gated.clear()  # policy may have changed: re-check every active call
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
                json.dump(dict(self.status, ts=int(time.time()), platform=self.platform.name,
                               coverage=self.coverage(), carrier=policy.carrier_mode(self.cfg),
                               policy=self.enf.policy(Dialog(None, "", "", "")).__dict__), f)
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

    # decisions ----------------------------------------------------------------
    def is_live(self, callid: str, gen: tuple) -> bool:
        """Is this exact call (same dialog, same listener start) still being monitored?"""
        group = self.listeners.get(callid)
        if not group or callid in self.terminated:
            return False
        return any((str(l.dlg.id), l.t0) == (gen[1], gen[2]) for l in group)

    def act(self, lst, hit: Hit, text: str, side: str) -> None:
        """One place for every hit: dedupe kill records per call, corroborate context hits
        across both sides, and stop listening only when termination was actually requested."""
        cid = lst.dlg.callid
        hits = [hit]
        ev = self.evidence_by_call.get(cid)
        if ev is not None:
            c = ev.add(hit)
            if c:
                hits.append(c)
        for h in hits:
            if h.action == "kill":
                with self.klock:
                    dup = cid in self.killed
                    self.killed.add(cid)
                if dup:
                    # one kill record and one enforcement per call, but further strong
                    # evidence from the same call still counts toward account escalation
                    self.enf.more_evidence(lst.dlg, h, side)
                    continue
            if self.enf.handle(lst.dlg, h, text, side):
                self.stop_call(cid)

    def smart_hit(self, lst, hit, text: str) -> None:
        self.act(lst, hit, text, "caller")

    def stop_call(self, cid: str) -> bool:
        """Stop all of a call's listeners once its termination was requested."""
        with self.klock:
            if cid in self.terminated:
                return False
            self.terminated.add(cid)
            self.killed.add(cid)
        for lst in self.listeners.get(cid, []):
            lst.stop = True
        return True

    # worker ------------------------------------------------------------------
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
                now = time.monotonic()
                worst = 0.0
                for item in items:
                    lst, samples = item[0], item[1]
                    if len(item) > 2:
                        worst = max(worst, now - item[2])
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
                        self.evidence_by_call.setdefault(cid, CallEvidence(self.rules))
                    s, m = calls[key]
                    if cid not in self.terminated:
                        s.accept_waveform(16000, samples.astype(np.float32))
                        touched.add(lst)
                if worst:
                    self.stats.queue_delay(worst)
                t0 = time.thread_time()
                while ready := [calls[l.key][0] for l in touched if rec.is_ready(calls[l.key][0])]:
                    rec.decode_streams(ready)
                self.stats.inc("cpu_seconds", time.thread_time() - t0)
                for lst in touched:
                    s, m = calls[lst.key]
                    said = rec.get_result(s)
                    for hit in m.update(said):
                        self.act(lst, hit, m.text(said), lst.side)
                    if lst.dlg.callid in self.terminated:
                        lst.stop = True
                    elif self.on_text:
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
        """Is this call from something on a block list? No switch edits needed."""
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
        if d.caller_ip and not policy.carrier_mode(self.cfg):
            checks.append(("src", d.caller_ip))
        for kind, value in checks:
            if kind in self.platform.gate_kinds and self.store.is_blocked(kind, value):
                return kind, value
        return None

    def denied_customer(self, d: Dialog) -> tuple[str, dict] | None:
        """Carrier mode: is the account this call belongs to (or its reseller) quarantined or blocked?"""
        if self.fraud is None:
            return None
        a = self.enf.attribution(d)
        if not a.trusted:
            return None
        for who, cid in (("customer", a.customer_id), ("parent", a.parent_id)):
            if not cid:
                continue
            try:
                rec = self.fraud.denied(cid)
            except Exception as e:
                self.stats.inc("fraud_store_errors")
                evidence.log(syslog.LOG_ERR, f"SCAMSTOP fraud store unavailable: {e}")
                return None
            if rec:
                return who, rec
        return None

    def _epochs(self) -> tuple:
        try:
            return (self.store.epoch(), self.fraud.epoch() if self.fraud else 0)
        except Exception:
            self.stats.inc("fraud_store_errors")
            return (None, None)

    def gatekeep(self, calls: list[Dialog]) -> set[str]:
        """End calls from blocked sources and denied customers. Re-checks active calls whenever a
        block list or deny record changes (and every monitor.recheck_s regardless), so a call
        that was clean when it started does not survive a new block. Returns the Call-IDs ended."""
        ended = set()
        if not self.cfg.get("gate", {}).get("enabled", True):
            return ended
        epochs, now = self._epochs(), time.monotonic()
        recheck_s = float(self.cfg["monitor"].get("recheck_s", 30))
        for d in calls:
            if d.callid in self.gate_hits:
                rec = self.enf.tracker.get(d.callid)
                if rec is None or rec.state not in (enforcement.FAILED, enforcement.UNKNOWN):
                    ended.add(d.callid)
                    continue
                if now - self.gated.get(d.callid, ((), 0))[1] < recheck_s:
                    ended.add(d.callid)
                    continue  # termination failed: try again, but not on every poll
            elif d.callid in self.gated:
                last_epochs, at = self.gated[d.callid]
                if last_epochs == epochs and None not in epochs and now - at < recheck_s:
                    continue
            if d.state != "up" and not self.platform.can_end_ringing:
                continue  # check again once it's answered
            first = d.callid not in self.gated
            hit = self.blocked_source(d)
            if not hit and d.state == "up" and self.store.r.scard(f"{self.store.p}block:media"):
                ip = self.platform.media_ip(d)
                if ip and self.store.is_blocked("media", ip):
                    hit = ("media", ip)
            deny = None if hit else self.denied_customer(d)
            self.gated[d.callid] = (epochs, now)
            if not first:
                self.stats.inc("rechecks")
            if hit or deny:
                self.gate_hits.add(d.callid)
                terminated = self.enf.gate(d, *hit) if hit else self.enf.deny(d, *deny)
                if terminated:
                    ended.add(d.callid)
                    self.stop_call(d.callid)
                    if not first:
                        self.stats.inc("recheck_terminations")
                else:
                    self.gate_hits.discard(d.callid)  # dry run: logged, the call goes on
        return ended

    # main loop -----------------------------------------------------------------
    def attribute(self, d: Dialog) -> attrmod.Attribution:
        if not policy.carrier_mode(self.cfg):
            return attrmod.untrusted(d)
        cached = self.enf.attr.get(d.callid)
        if cached and cached.dialog_id == (str(d.id) if d.id is not None else None) and cached.trusted:
            return cached
        a = attrmod.from_dialog(d, self.cfg["carrier"]["attribution"]["values"])
        if not a.trusted and (cached is None or cached.dialog_id != a.dialog_id):
            self.stats.inc("attribution_untrusted")
        self.enf.attr[d.callid] = a
        return a

    def monitored(self, d: Dialog) -> bool:
        mon = self.cfg["monitor"]
        if d.caller_ip in mon["exclude_ips"]:
            return False
        if any(d.bind_addr.endswith(s) for s in mon["exclude_bind_suffix"]):
            return False
        if policy.carrier_mode(self.cfg):
            return True  # every call on the carrier's switch; attribution only gates account actions
        if not d.caller_ip:
            return True  # Asterisk / FreeSWITCH: calls are chosen by the trunk pattern, not by source IP
        return self.store.is_customer(d.caller_ip)

    def coverage(self) -> dict:
        c = self.stats.coverage(float(self.cfg["monitor"].get("queue_delay_warn_s", 3.0)))
        with self.stats.lock:
            v = dict(self.stats.v)
        c.update(eligible=v.get("eligible", 0), monitored=v.get("listened", 0), skipped_cap=v.get("skipped_cap", 0),
                 dropped_chunks=v.get("dropped_chunks", 0), listener_failures=v.get("listener_failures", 0),
                 enforce_failed=v.get("enforce_failed", 0), enforce_unknown=v.get("enforce_unknown", 0),
                 active=len(self.listeners), max_streams=self.cfg["monitor"]["max_streams"],
                 overload=self.cfg["monitor"].get("overload", "skip_new"))
        return c

    def write_metrics(self):
        path = self.cfg["metrics"].get("textfile")
        if not path:
            return
        cov = self.coverage()
        with self.stats.lock:
            v = dict(self.stats.v, active=len(self.listeners))
        if self.smart:
            v.update(self.smart.counters)
            v["smart_llm_outstanding"] = self.smart.outstanding
        v["enforce_unresolved"] = self.enf.tracker.unresolved()
        v["protection_complete"] = int(cov["status"] == "complete")
        v["max_streams"] = self.cfg["monitor"]["max_streams"]
        lines = [f"scamstop_{k} {val}" for k, val in v.items()] + [f"scamstop_last_poll_seconds {int(time.time())}"]
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path + ".tmp", "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(path + ".tmp", path)

    def _start_group(self, d: Dialog, finished: set[str]) -> None:
        mon = self.cfg["monitor"]
        cap = int(mon["max_streams"])
        want_victim = bool(mon.get("listen_victim")) and self.platform.victim_available(d)
        streams = sum(len(g) for g in self.listeners.values())
        if mon.get("overload") == "shed_victim":
            if streams + 1 > cap:
                self.stats.inc("skipped_cap")
                return
            if want_victim and streams + 2 > cap:
                want_victim = False
                self.stats.inc("victim_shed")
        elif len(self.listeners) >= cap:
            self.stats.inc("skipped_cap")
            return
        q = self.queues[hash(d.callid) % len(self.queues)]
        group = [Listener(d, q, self.platform, self.cfg["asr"]["quiet_rms"], self.stats, "caller")]
        if want_victim:
            group.append(Listener(d, q, self.platform, self.cfg["asr"]["quiet_rms"], self.stats, "victim"))
        self.listeners[d.callid] = group
        self.stats.inc("listened")
        if self.tenants and not policy.carrier_mode(self.cfg):
            t = self.tenants.for_ip(d.caller_ip)
            if t:
                self.tenants.touch(t["id"])
        for lst in group:
            lst.start()

    def poll_once(self, finished: set[str]) -> None:
        allc = self.platform.all_calls()
        seen = {d.callid for d in allc}
        for d in allc:
            self.attribute(d)
        eligible = [d for d in allc if self.monitored(d)]
        ended = self.gatekeep(eligible)
        for k in [k for k in self.gated if k not in seen]:
            self.gated.pop(k, None)
        self.gate_hits &= seen
        live = set()
        for d in allc:
            if d.state != "up":
                continue
            if d.callid in ended:
                continue
            if not self.monitored(d):
                if d.callid not in self.counted:
                    self.counted.add(d.callid)
                    self.stats.inc("skipped_excluded")
                continue
            live.add(d.callid)
            if d.callid not in self.counted:
                self.counted.add(d.callid)
                self.stats.inc("eligible")
            if d.callid in self.listeners or d.callid in finished:
                continue  # one listen per call, never re-subscribe
            if d.callid in self.terminated:
                continue
            self._start_group(d, finished)
        for cid in list(self.listeners):
            if cid not in live or not any(l.is_alive() for l in self.listeners[cid]):
                for l in self.listeners.pop(cid):
                    l.stop = True
                finished.add(cid)
                if self.smart:
                    self.smart.forget(cid)
                self.evidence_by_call.pop(cid, None)
        for cid in [c for c in list(self.killed | self.terminated) if c not in seen]:
            with self.klock:
                self.killed.discard(cid)
                self.terminated.discard(cid)
        for cid in [c for c in list(self.enf.attr) if c not in seen]:
            self.enf.attr.pop(cid, None)
            self.enf.tracker.forget(cid)
        self.counted &= seen
        finished &= live

    def run(self):
        syslog.openlog("scamstop")
        self.load_model()
        pol = self.enf.policy(Dialog(None, "", "", ""))
        evidence.log(syslog.LOG_INFO, f"SCAMSTOP start platform={self.platform.name} carrier={int(policy.carrier_mode(self.cfg))} "
                                      f"policy={pol.source} dry={int(pol.dry_run)} warn_mode={pol.warn_mode} "
                                      f"rules={len(self.rules)} campaign_gate={int(self.gate.enabled)}")
        workers = [threading.Thread(target=self.worker, args=a, daemon=True) for a in zip(self.recs, self.queues)]
        for w in workers:
            w.start()
        finished, last_sweep, last_req = set(), 0.0, 0.0
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
                if self.fraud is not None and time.time() - last_req > 2:
                    for res in self.fraud.process_requests():
                        evidence.write(self.cfg["evidence"].get("escalation_log"), dict(res, source="request"))
                    last_req = time.time()
                self.poll_once(finished)
                if time.time() - last_sweep > 60:
                    n = self.store.sweep()
                    if self.fraud is not None:
                        n += self.fraud.sweep_expired()
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
