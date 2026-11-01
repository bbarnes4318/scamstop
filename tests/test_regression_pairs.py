"""Legitimate / scam regression pairs across both rule packs (with corroboration)."""
from pathlib import Path

import pytest

from scamstop.evaluation import pairs_as_labeled, phrase_verdict
from scamstop.rules import CallEvidence, Hit, load_rules

PAIRS = Path(__file__).parent / "data" / "regression_pairs.yaml"
RULES = load_rules(["en_scams", "en_victim"])
CALLS = pairs_as_labeled(PAIRS)


@pytest.mark.parametrize("call", CALLS, ids=[c["id"] for c in CALLS])
def test_pair(call):
    verdict, hits = phrase_verdict(call["caller"], call["victim"], RULES)
    why = [(h.rule_id, h.action, h.matched) for h in hits]
    if call["label"]:
        assert verdict == "kill", why
    else:
        assert verdict != "kill", why


@pytest.mark.parametrize("text", [
    "Hi Grandma, happy birthday.",
    "I am a public defender calling to confirm your appointment tomorrow.",
    "I broke my nose playing basketball yesterday.",
    "This is the Wells Fargo fraud department. Please call the number printed on your card.",
    "We are sending your new Medicare card because you requested a replacement.",
    "Hi, this is Apple Support calling back about the case you opened, as scheduled. Please download TeamViewer "
    "so I can look at the settings you asked about.",
])
def test_reported_false_positives_are_never_killed(text):
    verdict, hits = phrase_verdict(text, "", RULES)
    assert verdict != "kill", [(h.rule_id, h.action) for h in hits]


@pytest.mark.parametrize("caller,victim", [
    ("this is officer brown there is a warrant for your arrest", ""),                       # impersonation + threat
    ("go to the store and buy google play cards and read me the numbers on the back", ""),  # payment demand
    ("do not tell the bank teller what the money is for", ""),                             # secrecy coaching
    ("your social security number has been suspended due to suspicious activity", ""),
    ("we need to move your money to a safe account today", ""),
    ("hi", "what should i tell the teller if she asks"),                                     # victim-side coaching
    ("hi grandma it's me", "how many cards do i need to get"),                               # corroborated across sides
])
def test_real_scams_still_killed(caller, victim):
    assert phrase_verdict(caller, victim, RULES)[0] == "kill"


def test_corroboration_needs_a_listed_pair():
    ev = CallEvidence(RULES)
    fam = Hit("grandparent_opener", "g", "flag", "hi grandma", "family_emergency", "context", "family")
    inj = Hit("injury_claim", "i", "flag", "broke my nose", "family_emergency", "context", "injury")
    cus = Hit("custody_claim", "c", "flag", "public defender", "family_emergency", "context", "custody")
    assert ev.add(fam) is None and ev.add(inj) is None        # family + injury alone is ambiguous
    k = ev.add(cus)
    assert k.action == "kill" and k.rule_id == "corroborated" and k.strength == "strong"
    assert ev.add(cus) is None                                # each signal counts once


def test_every_context_rule_names_a_signal_used_by_some_pair():
    combos = {s for r in RULES for c in r.combos for s in c}
    for r in RULES:
        if r.strength == "context":
            assert r.action == "flag" and r.signal in combos, r.id
