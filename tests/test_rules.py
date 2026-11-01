import re

import pytest

from scamstop.rules import CallMatcher, CampaignGate, check_examples, load_rules, normalize


@pytest.fixture(scope="module")
def rules():
    return load_rules(["en_scams", "en_victim"])


def test_every_example_behaves(rules):
    assert check_examples(rules) == []


def test_ids_unique_and_actions_valid(rules):
    assert len({r.id for r in rules}) == len(rules)
    assert all(r.action in ("kill", "flag") for r in rules)


def test_normalize():
    assert normalize("Hi, Grandma!  It's ME.") == "hi grandma it's me"


def feed(m, *utterances):
    hits = []
    for u in utterances:
        hits += m.update(u)
        m.commit(u)
    return hits


def test_kill_across_utterances(rules):
    m = CallMatcher(rules)
    hits = feed(m, "you need to go to the store", "and buy google play cards right now")
    assert hits and hits[-1].rule_id == "gift_card_payment" and m.killed


def test_matching_continues_after_a_kill_but_each_rule_fires_once(rules):
    """Dry-run and warn-only calls stay monitored, so later evidence must still be seen."""
    m = CallMatcher(rules)
    feed(m, "there is a warrant for your arrest")
    assert m.killed
    later = m.update("go buy google play cards")
    assert [h.rule_id for h in later] == ["gift_card_payment"]
    m.commit("go buy google play cards")
    assert m.update("there is a warrant for your arrest") == []


def test_flag_does_not_kill(rules):
    m = CallMatcher(rules)
    hits = feed(m, "we saw an unauthorized charge on your visa")
    assert [h.action for h in hits] == ["flag"] and not m.killed


def test_flag_fires_once(rules):
    m = CallMatcher(rules)
    feed(m, "an unauthorized charge")
    assert feed(m, "another unauthorized charge") == []


def test_grandparent_opener_anchored_to_call_start(rules):
    m = CallMatcher(rules)
    feed(m, "hello this is sarah with the benefits line", "how is your grandma doing")
    assert not m.killed
    m2 = CallMatcher(rules)
    assert feed(m2, "hi grandma it's me")[0].rule_id == "grandparent_opener"


def test_legit_medicare_and_final_expense_pass(rules):
    m = CallMatcher(rules)
    feed(m, "hi this is mike a licensed agent returning your call about medicare",
         "do you have your red white and blue medicare card handy",
         "i need your social security number to prevent insurance fraud",
         "can you verify your medicare number for me", "press one to speak with an agent")
    assert not m.killed


def test_disable_and_override():
    rs = load_rules(["en_scams"], disabled=["arrest_threat"], overrides={"amazon_impersonation": "flag"})
    assert "arrest_threat" not in {r.id for r in rs}
    assert next(r for r in rs if r.id == "amazon_impersonation").action == "flag"


GATE = CampaignGate.from_config({
    "enabled": True, "allowed": ["medicare", "final expense", "life insurance"],
    "offlist": ["solar", "survey", "debt relief"], "grace_words": 5, "review_min_words": 10})


def test_campaign_gate_kills_offlist(rules):
    m = CallMatcher(rules, GATE)
    hits = feed(m, "we are offering free solar panels", "for homeowners in your area today ok")
    assert hits[-1].rule_id == "off_campaign" and m.killed


def test_campaign_gate_grace(rules):
    m = CallMatcher(rules, GATE)
    feed(m, "a quick survey about", "your medicare benefits this year ok")
    assert not m.killed and m.allowed


def test_campaign_gate_review_when_nothing_heard(rules):
    m = CallMatcher(rules, GATE)
    feed(m, "garbled words here " * 4)
    assert m.needs_review() and not m.killed


def test_window_limits_distance(rules):
    m = CallMatcher(rules, window=60)
    feed(m, "go and buy", "x " * 80, "google play")  # far apart, but "google play cards" pattern needs "cards"
    assert not m.killed
