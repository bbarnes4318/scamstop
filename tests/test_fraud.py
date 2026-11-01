"""sbc:fraud:v1:* deny records: idempotency, stale/concurrent changes, expiry, validation."""
import threading
import time

import fakeredis
import pytest

from scamstop import config
from scamstop.attribution import Attribution
from scamstop.escalation import Escalator
from scamstop.fraud import FraudError, FraudStore, validate_request
from scamstop.rules import Hit


def store():
    return FraudStore(fakeredis.FakeRedis(decode_responses=True))


def test_hash_fields_and_units():
    f = store()
    f.set_state("42", "blocked", "confirmed_fraud", "case-1", "req-000001", "ops", expires_at=int(time.time()) + 600)
    h = f.r.hgetall("sbc:fraud:v1:deny:customer:42")
    assert set(h) >= {"state", "reason_code", "case_id", "revision", "updated_at", "expires_at"}
    assert h["state"] == "blocked" and int(h["revision"]) == 1
    assert abs(int(h["updated_at"]) - time.time()) < 5          # epoch seconds, not ms
    assert int(h["expires_at"]) > time.time()


def test_idempotent_retry_returns_the_first_result():
    f = store()
    a = f.set_state("42", "quarantined", "auto_escalation", "c", "req-000001", "scamstop")
    b = f.set_state("42", "quarantined", "auto_escalation", "c", "req-000001", "scamstop")
    assert a["revision"] == b["revision"] == 1 and b.get("duplicate")
    assert len(f.audit()) == 1


def test_stale_request_refused_and_quarantine_never_downgrades_a_block():
    f = store()
    f.set_state("42", "quarantined", "auto_escalation", "c", "req-000001", "scamstop")
    f.set_state("42", "blocked", "confirmed_fraud", "c", "req-000002", "ops")
    assert f.set_state("42", "quarantined", "auto_escalation", "c", "req-000003", "scamstop")["result"] == "kept_stronger"
    assert f.set_state("42", "blocked", "x", "c", "req-000004", "ops", based_on_revision=1)["result"] == "stale"
    assert f.get("42")["state"] == "blocked" and f.get("42")["revision"] == 2


def test_unblock_requires_the_reviewed_revision():
    f = store()
    f.set_state("42", "blocked", "confirmed_fraud", "c", "req-000001", "ops")
    f.set_state("42", "blocked", "more_evidence", "c", "req-000002", "ops")   # revision 2 arrives meanwhile
    assert f.clear("42", 1, "c", "req-000003", "ops")["result"] == "conflict"
    assert f.denied("42")
    assert f.clear("42", 2, "c", "req-000004", "ops")["result"] == "applied"
    assert f.denied("42") is None
    assert f.clear("42", 2, "c", "req-000005", "ops")["result"] == "absent"


def test_concurrent_block_and_unblock_never_lose_a_newer_block():
    f = store()
    f.set_state("42", "blocked", "first", "c", "req-base0001", "ops")
    errors = []

    def blocker(i):
        try:
            f.set_state("42", "blocked", "again", "c", f"req-blk-{i:05d}", "ops")
        except Exception as e:
            errors.append(e)

    def unblocker(i):
        try:
            f.clear("42", 1, "c", f"req-unb-{i:05d}", "ops")   # everyone reviewed revision 1
        except Exception as e:
            errors.append(e)
    ts = [threading.Thread(target=blocker if i % 2 else unblocker, args=(i,)) for i in range(40)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors
    results = [e["result"] for e in f.audit(200) if e["op"] == "clear"]
    assert results.count("applied") <= 1   # at most one unblock can match revision 1
    # if any block came after the one unblock, the account is still blocked
    audit = list(reversed(f.audit(200)))
    last_set = max((i for i, e in enumerate(audit) if e["op"] == "set" and e["result"] == "applied"), default=-1)
    last_clear = max((i for i, e in enumerate(audit) if e["op"] == "clear" and e["result"] == "applied"), default=-1)
    assert bool(f.denied("42")) == (last_set > last_clear)


def test_expiry_is_honoured_and_swept_with_audit():
    f = store()
    f.set_state("42", "quarantined", "auto", "c", "req-000001", "scamstop", expires_at=int(time.time()) + 100)
    assert f.denied("42")
    f.r.hset("sbc:fraud:v1:deny:customer:42", "expires_at", int(time.time()) - 1)
    assert f.denied("42") is None              # inactive immediately, even before the sweep
    assert f.sweep_expired() == 1 and f.get("42") is None
    assert f.audit(1)[0]["reason_code"] == "expired"


def test_expires_at_zero_means_never():
    f = store()
    f.set_state("42", "blocked", "x", "c", "req-000001", "ops", expires_at=0)
    assert f.denied("42")["expires_at"] == 0 and f.sweep_expired() == 0


@pytest.mark.parametrize("kw", [
    {"customer_id": "1 2"}, {"customer_id": "abc"}, {"customer_id": "0"}, {"state": "suspended"},
    {"reason_code": "Bad Reason"}, {"case_id": "a b"}, {"request_id": "short"}, {"actor": "a b"},
    {"expires_at": 5}, {"expires_at": "0"}, {"expires_at": True}, {"based_on_revision": -1},
])
def test_every_value_is_validated(kw):
    args = dict(customer_id="42", state="blocked", reason_code="x", case_id="c", request_id="req-000001", actor="ops")
    args.update(kw)
    with pytest.raises(FraudError):
        store().set_state(**args)


def test_untrusted_strings_are_data_not_script():
    f = store()
    with pytest.raises(FraudError):
        f.set_state("42", "blocked", "x", "c'); redis.call('FLUSHALL", "req-000001", "ops")
    f.r.set("canary", "1")
    f.set_state("42", "blocked", "x", "c:1.2", "req-000002", "ops")
    assert f.r.get("canary") == "1"


def test_request_validation():
    with pytest.raises(FraudError):
        validate_request({"op": "delete", "customer_id": "1"})
    with pytest.raises(FraudError):
        validate_request({"op": "unblock", "customer_id": "1", "case_id": "c", "request_id": "req-000001",
                          "actor": "a"})  # no expected_revision
    r = validate_request({"op": "block", "customer_id": "1", "case_id": "c", "request_id": "req-000001",
                          "actor": "a", "reason_code": "x", "expires_at": "0"})
    assert r["expires_at"] == 0


def test_prefix_cannot_alias_the_registry():
    with pytest.raises(ValueError):
        FraudStore(fakeredis.FakeRedis(), prefix="sbc:cust:")


# ---- escalation -----------------------------------------------------------------------------------

def esc(**e):
    cfg = config.load(None)
    cfg["carrier"]["enabled"] = True
    cfg["carrier"]["escalation"].update(e)
    f = store()
    return Escalator(cfg, f), f


def attr(cid, parent=None, n=0, trusted=True):
    return Attribution(callid=f"call{n}@x", customer_id=cid if trusted else None, parent_id=parent, trusted=trusted)


STRONG = Hit("gift_card_payment", "g", "kill", "x", "payment_method")
SMART = Hit("smart_check", "s", "kill", "score", "smart")
CONTEXT = Hit("custody_claim", "c", "flag", "public defender", "family_emergency", "context", "custody")


def test_quarantine_needs_enough_calls_and_kinds():
    e, f = esc(quarantine_after=3, min_evidence_kinds=2)
    for n in range(5):
        assert e.record(attr("77", n=n), STRONG, "caller") is None   # one kind only, however many calls
    r = e.record(attr("77", n=9), SMART, "caller")
    assert r and r["result"] == "applied" and f.denied("77")["state"] == "quarantined"
    assert f.denied("77")["actor"] == "scamstop"


def test_context_hits_never_count():
    e, f = esc(quarantine_after=1, min_evidence_kinds=1)
    for n in range(10):
        e.record(attr("77", n=n), CONTEXT, "caller")
    assert f.list() == []


def test_child_is_quarantined_not_the_reseller():
    e, f = esc(quarantine_after=2, min_evidence_kinds=1)
    e.record(attr("2077", "1500", 0), STRONG, "caller")
    r = e.record(attr("2077", "1500", 1), STRONG, "caller")
    assert r["customer_id"] == "2077" and f.denied("2077") and f.denied("1500") is None
    assert r["parent"] == {"children_quarantined": 1, "escalated": False, "review": False}


def test_reseller_escalation_is_opt_in_and_needs_several_children():
    e, f = esc(quarantine_after=1, min_evidence_kinds=1, parent={"enabled": True, "children_quarantined": 2})
    e.record(attr("2001", "1500", 0), STRONG, "caller")
    assert f.denied("1500") is None
    r = e.record(attr("2002", "1500", 1), STRONG, "caller")
    assert r["parent"]["escalated"] and f.denied("1500")["reason_code"] == "children_quarantined"


def test_untrusted_attribution_never_escalates():
    e, f = esc(quarantine_after=1, min_evidence_kinds=1)
    e.record(Attribution(callid="c@x", customer_id="77", trusted=False), STRONG, "caller")
    assert f.list() == []


def test_operator_unblock_is_respected_within_the_window():
    e, f = esc(quarantine_after=1, min_evidence_kinds=1)
    e.record(attr("77", n=0), STRONG, "caller")
    rev = f.denied("77")["revision"]
    f.clear("77", rev, "review", "ops-unblock-1", "ops")
    e.record(attr("77", n=1), STRONG, "caller")   # same window: the idempotent auto request is not replayed
    assert f.denied("77") is None
