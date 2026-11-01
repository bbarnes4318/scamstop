"""Termination outcomes are verified, with bounded retries."""
from scamstop import enforcement
from scamstop.control import Dialog


class Switch:
    def __init__(self, ends_after=1, check_fails=False, end_raises=False):
        self.up, self.ends, self.ends_after = True, 0, ends_after
        self.check_fails, self.end_raises = check_fails, end_raises

    def end(self, d):
        self.ends += 1
        if self.end_raises:
            raise RuntimeError("MI write failed")
        if self.ends >= self.ends_after:
            self.up = False

    def call_exists(self, d):
        if self.check_fails:
            raise TimeoutError("no answer")
        return self.up


def tracker(sw, **cfg):
    sch = enforcement.Scheduler(1)
    sch.inline = True
    seen = []
    t = enforcement.Tracker(sw, {"confirm_delays_s": [0.5, 1.0], "end_retries": 2, **cfg}, sch,
                            lambda rec, d: seen.append(rec.state))
    return t, sch, seen


def run(sch):
    while sch.run_due(float("inf")):
        pass


D = Dialog("6ae.1", "c@x", "a", "")


def test_confirmed():
    t, sch, seen = tracker(Switch())
    assert t.terminate(D, "rule")
    run(sch)
    assert seen == ["termination_requested", "termination_confirmed"]


def test_retried_then_confirmed():
    sw = Switch(ends_after=2)
    t, sch, seen = tracker(sw)
    t.terminate(D, "rule")
    run(sch)
    assert sw.ends == 2 and seen[-1] == enforcement.TERMINATION_CONFIRMED


def test_failed_after_bounded_retries():
    sw = Switch(ends_after=99)
    t, sch, seen = tracker(sw)
    t.terminate(D, "rule")
    run(sch)
    assert sw.ends == 3 and seen[-1] == enforcement.FAILED and t.unresolved() == 1
    assert t.get("c@x").checks == 6     # 2 checks per attempt, never unbounded


def test_unknown_when_the_switch_cannot_answer():
    t, sch, seen = tracker(Switch(check_fails=True))
    t.terminate(D, "rule")
    run(sch)
    assert seen[-1] == enforcement.UNKNOWN and "no answer" in t.get("c@x").error


def test_end_error_is_recorded_and_still_verified():
    t, sch, seen = tracker(Switch(end_raises=True))
    t.terminate(D, "rule")
    run(sch)
    assert seen[-1] == enforcement.FAILED and t.get("c@x").attempts == 3


def test_warning_then_delayed_termination_and_one_termination_per_call():
    t, sch, seen = tracker(Switch())
    t.requested(D, "rule")
    t.warning_started(D, "rule")
    assert t.terminate(D, "rule", delay=5)
    assert not t.terminate(D, "rule")          # already scheduled
    assert seen == ["requested", "warning_started"]
    run(sch)
    assert seen == ["requested", "warning_started", "termination_requested", "termination_confirmed"]
    assert not t.terminate(D, "again")         # confirmed: nothing more to do


def test_failed_call_can_be_tried_again_later():
    sw = Switch(ends_after=99)
    t, sch, seen = tracker(sw, end_retries=0)
    t.terminate(D, "rule")
    run(sch)
    assert seen[-1] == enforcement.FAILED
    sw.ends_after = 0
    assert t.terminate(D, "recheck")
    run(sch)
    assert seen[-1] == enforcement.TERMINATION_CONFIRMED
