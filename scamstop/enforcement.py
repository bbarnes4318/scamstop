"""Enforcement outcomes that are verified, not assumed.

A hang-up request (or a timer that will send one) is not proof that a call ended. Each
enforced call moves through explicit states:

  requested               a kill/deny decision was made for this call
  warning_started         the warning began playing (warn modes)
  termination_requested   the switch was asked to end the dialog (attempt n)
  termination_confirmed   the dialog is no longer listed by the switch
  failed                  still listed after every retry: the call may still be live
  unknown                 the switch could not tell us either way (MI errors/timeouts)

Termination is checked with bounded retries (enforcement.confirm_delays_s, end_retries).
Platform calls run on a small bounded worker pool driven by one scheduler thread, instead
of one timer thread per call.
"""
from __future__ import annotations

import heapq
import itertools
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

REQUESTED = "requested"
WARNING_STARTED = "warning_started"
TERMINATION_REQUESTED = "termination_requested"
TERMINATION_CONFIRMED = "termination_confirmed"
FAILED = "failed"
UNKNOWN = "unknown"
FINAL = (TERMINATION_CONFIRMED, FAILED, UNKNOWN)


class Scheduler:
    """Runs callables at a time. run_due() is also called directly by tests (no sleeping)."""

    def __init__(self, workers: int = 4, clock=time.monotonic):
        self.clock = clock
        self.heap: list = []
        self.seq = itertools.count()
        self.cv = threading.Condition()
        self.pool = ThreadPoolExecutor(max_workers=max(1, int(workers)), thread_name_prefix="scamstop-enf")
        self.thread: threading.Thread | None = None
        self.inline = False  # tests: run jobs on the calling thread

    def call_at(self, t: float, fn, *args) -> None:
        with self.cv:
            heapq.heappush(self.heap, (t, next(self.seq), fn, args))
            self.cv.notify()

    def call_later(self, delay: float, fn, *args) -> None:
        self.call_at(self.clock() + max(0.0, delay), fn, *args)

    def pending(self) -> int:
        with self.cv:
            return len(self.heap)

    def run_due(self, now: float | None = None) -> int:
        now = self.clock() if now is None else now
        due = []
        with self.cv:
            while self.heap and self.heap[0][0] <= now:
                due.append(heapq.heappop(self.heap))
        for _, _, fn, args in due:
            if self.inline:
                fn(*args)
            else:
                self.pool.submit(fn, *args)
        return len(due)

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._loop, daemon=True, name="scamstop-scheduler")
        self.thread.start()

    def _loop(self) -> None:
        while True:
            with self.cv:
                wait = (self.heap[0][0] - self.clock()) if self.heap else 1.0
                if wait > 0:
                    self.cv.wait(min(wait, 1.0))
            self.run_due()


@dataclass
class Record:
    callid: str
    reason: str
    state: str = REQUESTED
    attempts: int = 0
    checks: int = 0
    error: str = ""
    scheduled: bool = False      # a termination is pending or under way
    history: list = field(default_factory=list)
    started: float = field(default_factory=time.time)


class Tracker:
    """Drives termination of one dialog to a verified outcome.

    on_change(record, dlg) is called on every state transition (evidence log, metrics,
    sbc:fraud:v1:ack:<call-id>)."""

    def __init__(self, platform, cfg: dict, scheduler: Scheduler, on_change=None):
        self.platform, self.scheduler, self.on_change = platform, scheduler, on_change
        e = cfg or {}
        self.delays = [float(x) for x in (e.get("confirm_delays_s") or [0.5, 1.0, 2.0])][:10] or [1.0]
        self.retries = max(0, min(5, int(e.get("end_retries", 2))))
        self.records: dict[str, Record] = {}
        self.lock = threading.Lock()

    def get(self, callid: str) -> Record | None:
        with self.lock:
            return self.records.get(callid)

    def _set(self, rec: Record, dlg, state: str, error: str = "") -> None:
        rec.state, rec.error = state, error or rec.error
        rec.history.append((round(time.time(), 3), state))
        if self.on_change:
            try:
                self.on_change(rec, dlg)
            except Exception:
                pass

    def _begin(self, dlg, reason: str) -> Record | None:
        with self.lock:
            cur = self.records.get(dlg.callid)
            if cur and cur.state not in (FAILED, UNKNOWN) and (cur.scheduled or cur.state == TERMINATION_CONFIRMED):
                return None  # already being ended / ended: one termination per call
            if cur and cur.state in (WARNING_STARTED, REQUESTED):
                rec = cur
            else:
                rec = Record(dlg.callid, reason)
                self.records[dlg.callid] = rec
            rec.scheduled = True
        return rec

    def requested(self, dlg, reason: str) -> Record:
        with self.lock:
            rec = self.records.get(dlg.callid)
            if rec is None or rec.state in FINAL:
                rec = Record(dlg.callid, reason)
                self.records[dlg.callid] = rec
            else:
                return rec
        self._set(rec, dlg, REQUESTED)
        return rec

    def warning_started(self, dlg, reason: str) -> None:
        rec = self.requested(dlg, reason)
        self._set(rec, dlg, WARNING_STARTED)

    def terminate(self, dlg, reason: str, delay: float = 0.0) -> bool:
        """Ask for this dialog to be ended after `delay` seconds and verify it. False if a
        termination for the call is already under way or confirmed."""
        rec = self._begin(dlg, reason)
        if rec is None:
            return False
        if delay > 0:
            self.scheduler.call_later(delay, self._attempt, rec, dlg)
        else:
            self._attempt(rec, dlg)
        return True

    def confirm(self, dlg, reason: str) -> bool:
        """The call was already told to go away some other way (a 603+ reject): only verify."""
        rec = self._begin(dlg, reason)
        if rec is None:
            return False
        rec.attempts += 1
        self._set(rec, dlg, TERMINATION_REQUESTED)
        self.scheduler.call_later(self.delays[0], self._verify, rec, dlg, 0)
        return True

    def _attempt(self, rec: Record, dlg) -> None:
        rec.attempts += 1
        err = ""
        try:
            self.platform.end(dlg)
        except Exception as e:
            err = f"end: {e}"[:200]
        self._set(rec, dlg, TERMINATION_REQUESTED, err)
        self.scheduler.call_later(self.delays[0], self._verify, rec, dlg, 0)

    def _verify(self, rec: Record, dlg, idx: int) -> None:
        rec.checks += 1
        try:
            exists = self.platform.call_exists(dlg)
        except Exception as e:
            exists, rec.error = None, f"check: {e}"[:200]
        if exists is False:
            return self._set(rec, dlg, TERMINATION_CONFIRMED)
        if idx + 1 < len(self.delays):
            return self.scheduler.call_later(self.delays[idx + 1], self._verify, rec, dlg, idx + 1)
        if exists is True and rec.attempts <= self.retries:
            return self._attempt(rec, dlg)
        self._set(rec, dlg, FAILED if exists is True else UNKNOWN,
                  "dialog still listed after every retry" if exists is True else (rec.error or "switch did not answer"))

    def forget(self, callid: str) -> None:
        with self.lock:
            rec = self.records.get(callid)
            if rec and (rec.state in FINAL or time.time() - rec.started > 3600):
                self.records.pop(callid, None)

    def unresolved(self) -> int:
        with self.lock:
            return sum(1 for r in self.records.values() if r.state in (FAILED, UNKNOWN))
