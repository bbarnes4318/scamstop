"""The evaluation report keeps phrase, smart and combined results apart, at the real thresholds."""
import json
from pathlib import Path

from scamstop import config
from scamstop.evaluation import evaluate_system, load_labeled, pairs_as_labeled
from scamstop.rules import load_rules
from scamstop.smart import Classifier

DATA = Path(__file__).parent / "data"


def test_report_layers_and_thresholds():
    cfg = config.load(None)
    r = evaluate_system(load_labeled(DATA / "smart_heldout.txt"), load_rules(["en_scams", "en_victim"]),
                        Classifier.load(), cfg["smart"])
    assert r["thresholds"] == {"flag": 0.85, "kill": 0.97, "smart_mode": "flag"}
    assert set(r) >= {"phrase", "smart", "smart_ungated", "combined", "note"}
    assert set(r["smart"]) >= {"flag@0.85", "kill@0.97", "too_short_to_score"}
    # regression guards on the fixture (not accuracy claims)
    assert r["phrase"]["kill"]["false_positives"] == 0
    assert r["smart_ungated"]["flag@0.85"]["false_positives"] == 0
    # flag-only smart mode never contributes to what ends calls
    assert r["combined"]["kill"] == r["phrase"]["kill"]


def test_kill_mode_smart_counts_toward_combined_kills():
    cfg = config.load(None)
    cfg["smart"].update(mode="kill", min_words=5, kill_threshold=0.9)
    calls = [{"id": "a", "label": 1, "victim": "",
              "caller": "this is officer brown there is a warrant go buy store cards and do not tell your bank"}]
    r = evaluate_system(calls, load_rules(["en_scams"]), Classifier.load(), cfg["smart"])
    assert r["smart"]["kill@0.9"]["true_positives"] == 1 and r["combined"]["kill"]["true_positives"] == 1


def test_jsonl_input(tmp_path):
    p = tmp_path / "calls.jsonl"
    p.write_text(json.dumps({"id": "x", "label": 0, "caller": "hi", "victim": "hello"}) + "\n")
    assert load_labeled(p) == [{"id": "x", "label": 0, "caller": "hi", "victim": "hello"}]


def test_pairs_fixture_loads_both_sides():
    calls = pairs_as_labeled(DATA / "regression_pairs.yaml")
    assert len(calls) % 2 == 0 and {c["label"] for c in calls} == {0, 1}
