"""The daemon in carrier integration mode, end to end with fakes (no switch, no audio)."""
import json
import queue
import threading
import time

import fakeredis
import numpy as np
import yaml

from scamstop import config, enforcement
from scamstop.control import Dialog
from scamstop.daemon import Daemon
from scamstop.fraud import FraudStore
from scamstop.platforms.base import Platform
from scamstop.rules import Hit
from scamstop.store import Store

REGISTRY = {  # what voip-portal's sync writes (sbc/opensips-portal-sync.sh); ScamStop must never touch it
    "sbc:cust:203.0.113.10": "1042|91.98.108.76|1|50|100|-|-",
    "sbc:cust:203.0.113.20": "1500|91.98.101.159|1|100|300|-|futures",
    "sbc:cust:pfx:1500:101": "2077|91.98.101.159|1|20|40|-|futures",
    "sbc:entry:91.98.101.159": "1500,2077",
    "sbc:cust:synced_at": "1793500000",
}


def vals(cust, parent=None, ep=None, src="203.0.113.10"):
    v = [{"fa_v": "1"}, {"fa_cust": cust}, {"fa_src": src}]
    if parent:
        v += [{"fa_parent": parent}, {"fa_ep": ep}]
    return {"values": v}


class FakeSwitch(Platform):
    """Lists dialogs; end() removes them unless told to ignore hang-ups (a failing switch)."""
    name = "fake"

    def __init__(self, calls):
        self.calls, self.ended, self.ignore_end, self.check_error = list(calls), [], False, False

    def all_calls(self):
        return list(self.calls)

    def audio(self, dlg, side, stop):
        while not stop():
            time.sleep(0.02)
            yield np.zeros(400, np.int16)

    def end(self, dlg):
        self.ended.append(dlg.callid)
        if not self.ignore_end:
            self.calls = [c for c in self.calls if c.callid != dlg.callid]

    def call_exists(self, dlg):
        if self.check_error:
            raise TimeoutError("MI timeout")
        return any(c.callid == dlg.callid and c.id == dlg.id for c in self.calls)


def daemon(tmp_path, calls, extra=None, fr=None):
    cfgp = tmp_path / "config.yaml"
    user = {"carrier": {"enabled": True}, "dry_run": True,  # dry_run must not matter in carrier mode
            "hosted": {"enabled": True},
            "evidence": {k: str(tmp_path / f"{k}.jsonl") for k in
                         ("kill_log", "flag_log", "enforcement_log", "escalation_log", "review_log", "watch_log")},
            "warn": {"file": str(tmp_path / "w.wav"), "mode": "off"}, "smart": {"enabled": False},
            "feed": {"enabled": False}, "status_file": str(tmp_path / "status.json"),
            "metrics": {"textfile": str(tmp_path / "m.prom")},
            "enforcement": {"confirm_delays_s": [0.1, 0.1], "end_retries": 1},
            "monitor": {"listen_victim": False, "recheck_s": 3600}}
    for k, v in (extra or {}).items():
        user[k] = {**user.get(k, {}), **v} if isinstance(v, dict) else v
    cfgp.write_text(yaml.safe_dump(user))
    fr = fr or fakeredis.FakeRedis(decode_responses=True)
    for k, v in REGISTRY.items():
        fr.set(k, v)
    orig = Store.from_url
    Store.from_url = classmethod(lambda cls, url, **kw: cls(fr, **kw))
    try:
        d = Daemon(config.load(str(cfgp)), str(cfgp), FakeSwitch(calls))
    finally:
        Store.from_url = orig
    d.queues = [queue.Queue()]
    d.enf.scheduler.inline = True
    return d, fr


def flush(d):
    for _ in range(50):
        if not d.enf.scheduler.run_due(float("inf")):
            break


def registry(fr):
    return {k: fr.get(k) for k in sorted(fr.scan_iter("sbc:cust:*"))} | {k: fr.get(k) for k in fr.scan_iter("sbc:entry:*")}


def kill(cid, dlg_id="1"):
    return Dialog(dlg_id, cid, "ft", "198.51.100.1", raw=vals("1042"))


GIFT = Hit("gift_card_payment", "Gift card", "kill", "google play cards", "payment_method")
GRANDMA = Hit("grandparent_opener", "Grandparent opener", "flag", "hi grandma", "family_emergency", "context", "family")


class L:
    def __init__(self, d, side="caller"):
        self.dlg, self.side, self.key, self.t0, self.stop = d, side, (d.callid, side), 0, False


def test_registry_is_never_written_and_dry_run_does_not_disable_carrier_policy(tmp_path):
    calls = [Dialog(str(i), f"c{i}@74.81.33.58", "t", "198.51.100.1", raw=vals("1042")) for i in range(3)]
    d, fr = daemon(tmp_path, calls)
    before = registry(fr)
    d.poll_once(set())
    for c in calls:  # three strong kills from the same account -> escalation writes deny records
        d.act(L(c), GIFT, "t", "caller")
        d.act(L(c), Hit("victim_gift_cards", "v", "kill", "x", "victim_says", side="victim"), "t", "victim")
    flush(d)
    t = d.tenants
    tid = t.create("Acme", "a@acme.example", "longpassword1")["id"]
    t.add_ip(tid, "203.0.113.10")
    t.set_status(tid, "active")
    t.remove_ip(tid, "203.0.113.10")
    t.delete(tid)
    t.resync_all()
    d.poll_once(set())
    assert registry(fr) == before
    assert sorted(d.platform.ended) == sorted(c.callid for c in calls)   # enforced although dry_run: true
    assert FraudStore(fr).denied("1042")["state"] == "quarantined"


def test_portal_sync_cannot_clear_fraud_blocks(tmp_path):
    d, fr = daemon(tmp_path, [])
    f = FraudStore(fr)
    f.set_state("2077", "blocked", "confirmed_fraud", "case-9", "ops-req-0001", "ops")
    # what sbc/opensips-portal-sync.sh does: delete every sbc:cust:* / sbc:entry:* not in its list
    for pattern in ("sbc:cust:*", "sbc:entry:*", "sbc:portal:*"):
        for k in list(fr.scan_iter(pattern)):
            if k not in ("sbc:cust:synced_at", "sbc:cust:disabled"):
                fr.delete(k)
    assert f.denied("2077")["state"] == "blocked"


def test_active_call_is_terminated_when_its_customer_is_blocked_later(tmp_path):
    child = Dialog("9", "child@1.2.3.4", "ft", "198.51.100.1", raw=vals("2077", "1500", "pfx:1500:101"))
    other = Dialog("8", "other@1.2.3.4", "ft", "198.51.100.1", raw=vals("1042"))
    d, fr = daemon(tmp_path, [child, other])
    d.poll_once(set())
    assert set(d.listeners) == {"child@1.2.3.4", "other@1.2.3.4"}        # clean when they started
    FraudStore(fr).set_state("2077", "quarantined", "manual_review", "case-1", "ops-req-0002", "ops")
    d.poll_once(set())
    flush(d)
    assert d.platform.ended == ["child@1.2.3.4"]                          # only the denied account's call
    assert d.stats.v["recheck_terminations"] == 1 and d.stats.v["denied_calls"] == 1
    assert FraudStore(fr).get_ack("child@1.2.3.4")["state"] == enforcement.TERMINATION_CONFIRMED
    log = (tmp_path / "kill_log.jsonl").read_text()
    assert '"rule": "customer_denied"' in log and '"deny_customer": "2077"' in log


def test_blocked_reseller_denies_its_children_but_child_block_spares_reseller(tmp_path):
    child = Dialog("9", "child@x", "ft", "198.51.100.1", raw=vals("2077", "1500", "pfx:1500:101"))
    reseller = Dialog("7", "res@x", "ft", "198.51.100.1", raw=vals("1500", src="203.0.113.20"))
    d, fr = daemon(tmp_path, [child, reseller])
    FraudStore(fr).set_state("2077", "blocked", "confirmed_fraud", "c", "ops-req-0003", "ops")
    d.poll_once(set())
    assert d.platform.ended == ["child@x"]
    FraudStore(fr).set_state("1500", "blocked", "confirmed_fraud", "c", "ops-req-0004", "ops")
    child2 = Dialog("10", "child2@x", "ft", "198.51.100.1", raw=vals("2078", "1500", "pfx:1500:102"))
    d.platform.calls.append(child2)
    d.poll_once(set())
    assert sorted(d.platform.ended) == ["child2@x", "child@x", "res@x"]


def test_new_block_list_entry_terminates_an_already_checked_call(tmp_path):
    c = Dialog("1", "abc@74.81.33.58", "ft", "198.51.100.1", raw=vals("1042"))
    d, fr = daemon(tmp_path, [c])
    d.poll_once(set())
    assert d.platform.ended == []
    d.store.block("host", "74.81.33.58", 0, "manual")
    d.poll_once(set())
    assert d.platform.ended == ["abc@74.81.33.58"]


def test_failed_termination_is_retried_and_reported(tmp_path):
    c = Dialog("1", "stuck@x", "ft", "198.51.100.1", raw=vals("1042"))
    d, fr = daemon(tmp_path, [c])
    d.platform.ignore_end = True                      # the switch accepts the request but the call stays up
    d.poll_once(set())
    d.act(L(c), GIFT, "t", "caller")
    flush(d)
    assert d.platform.ended == ["stuck@x", "stuck@x"]  # first request + end_retries=1
    assert d.stats.v["enforce_failed"] == 1 and d.stats.v["enforce_confirmed"] == 0
    assert FraudStore(fr).get_ack("stuck@x")["state"] == enforcement.FAILED
    states = [json.loads(l)["state"] for l in (tmp_path / "enforcement_log.jsonl").read_text().splitlines()]
    assert states == ["requested", "termination_requested", "termination_requested", "failed"]
    d.write_metrics()
    m = (tmp_path / "m.prom").read_text()
    assert "scamstop_enforce_failed 1" in m and "scamstop_protection_complete 0" in m
    assert "enforce_failed" in d.coverage()["reasons"]


def test_unknown_outcome_when_switch_cannot_answer(tmp_path):
    c = Dialog("1", "q@x", "ft", "198.51.100.1", raw=vals("1042"))
    d, fr = daemon(tmp_path, [c])
    d.platform.check_error = True
    d.poll_once(set())
    d.act(L(c), GIFT, "t", "caller")
    flush(d)
    assert d.enf.tracker.get("q@x").state == enforcement.UNKNOWN and d.stats.v["enforce_unknown"] == 1


def test_untrusted_attribution_still_monitored_and_killed_but_never_escalated(tmp_path):
    calls = [Dialog(str(i), f"u{i}@x", "ft", "198.51.100.1", raw={}) for i in range(4)]
    d, fr = daemon(tmp_path, calls)
    d.poll_once(set())
    assert len(d.listeners) == 4 and d.stats.v["attribution_untrusted"] == 4
    for c in calls:
        d.act(L(c), GIFT, "t", "caller")
    assert len(d.platform.ended) == 4 and FraudStore(fr).list() == []


def test_weak_phrase_matches_never_quarantine_an_account(tmp_path):
    calls = [Dialog(str(i), f"w{i}@x", "ft", "198.51.100.1", raw=vals("1042")) for i in range(10)]
    d, fr = daemon(tmp_path, calls)
    d.poll_once(set())
    for c in calls:
        d.act(L(c), GRANDMA, "t", "caller")
        d.act(L(c), Hit("off_campaign", "Off campaign", "kill", "solar", "campaign", "weak"), "t", "caller")
    assert FraudStore(fr).list() == []


def test_feed_indicator_matches_never_quarantine_an_account(tmp_path):
    calls = [Dialog(str(i), f"f{i}@74.81.33.58", "ft", "198.51.100.1", raw=vals("1042")) for i in range(5)]
    d, fr = daemon(tmp_path, calls)
    d.store.block("host", "74.81.33.58", 3600, "feed:gift_card_payment x3")
    d.poll_once(set())
    assert len(d.platform.ended) == 5 and FraudStore(fr).list() == []
    assert '"origin": "feed"' in (tmp_path / "kill_log.jsonl").read_text()


def test_dry_run_kill_keeps_monitoring(tmp_path):
    c = Dialog("1", "dry@x", "ft", "198.51.100.1", raw=vals("1042"))
    d, fr = daemon(tmp_path, [c], {"carrier": {"policy": {"enforce": False}}})
    d.poll_once(set())
    lst = d.listeners["dry@x"][0]
    d.act(L(c), GIFT, "t", "caller")
    assert d.platform.ended == [] and not lst.stop and "dry@x" not in d.terminated
    assert "dry@x" in d.killed   # one kill record per call, monitoring continues


def test_overload_is_visible_not_silent(tmp_path):
    calls = [Dialog(str(i), f"o{i}@x", "ft", "198.51.100.1", raw=vals("1042")) for i in range(3)]
    d, fr = daemon(tmp_path, calls, {"monitor": {"max_streams": 2}})
    d.poll_once(set())
    assert len(d.listeners) == 2
    cov = d.coverage()
    assert cov["status"] == "degraded" and "skipped_cap" in cov["reasons"]
    assert cov["eligible"] == 3 and cov["monitored"] == 2 and cov["skipped_cap"] == 1
    d.write_metrics()
    d.write_status()
    m = (tmp_path / "m.prom").read_text()
    assert "scamstop_eligible 3" in m and "scamstop_skipped_cap 1" in m and "scamstop_protection_complete 0" in m
    st = json.loads((tmp_path / "status.json").read_text())
    assert st["coverage"]["status"] == "degraded" and st["policy"]["source"] == "carrier"


def test_shed_victim_overload_policy_keeps_caller_side(tmp_path):
    calls = [Dialog(str(i), f"s{i}@x", "ft", "198.51.100.1", callee_tag="v", raw=vals("1042")) for i in range(2)]
    d, fr = daemon(tmp_path, calls, {"monitor": {"max_streams": 3, "listen_victim": True, "overload": "shed_victim"}})
    d.poll_once(set())
    sides = sorted(len(g) for g in d.listeners.values())
    assert sides == [1, 2] and d.stats.v["victim_shed"] == 1
    assert "victim_shed" in d.coverage()["reasons"]


def test_complete_coverage_when_nothing_was_lost(tmp_path):
    d, fr = daemon(tmp_path, [Dialog("1", "ok@x", "ft", "198.51.100.1", raw=vals("1042"))])
    d.poll_once(set())
    assert d.coverage()["status"] == "complete"


def test_requests_stream_from_permitted_writers(tmp_path):
    d, fr = daemon(tmp_path, [])
    f = FraudStore(fr)
    f.submit_request({"op": "quarantine", "customer_id": "1042", "case_id": "pvn-77", "request_id": "portal-req-0001",
                      "actor": "portal-admin", "reason_code": "operator_review"})
    f.r.xadd("sbc:fraud:v1:requests", {"op": "block", "customer_id": "1 OR 1", "case_id": "x",
                                       "request_id": "portal-req-0002", "actor": "p"})
    res = f.process_requests()
    assert [r["result"] for r in res] == ["applied", "rejected"]
    assert f.denied("1042")["state"] == "quarantined" and f.denied("1") is None


def test_fraud_store_unavailable_is_counted_not_mistaken_for_clean(tmp_path):
    c = Dialog("1", "r@x", "ft", "198.51.100.1", raw=vals("1042"))
    d, fr = daemon(tmp_path, [c])

    def boom(*a, **k):
        raise ConnectionError("redis down")
    d.fraud.denied = boom
    d.poll_once(set())
    assert d.stats.v["fraud_store_errors"] >= 1 and "fraud_store_errors" in d.coverage()["reasons"]
    assert "r@x" in d.listeners   # monitoring continues
