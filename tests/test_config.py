from pathlib import Path

from scamstop import config
from scamstop.rules import CallMatcher, CampaignGate, load_rules

EXAMPLE = Path(__file__).parent.parent / "config.example.yaml"


def test_example_config_loads_and_is_safe_by_default():
    c = config.load(str(EXAMPLE))
    assert c["dry_run"] is True and c["campaigns"]["enabled"] is False
    assert c["centers"]["never_block_customer_ip"] is True


def test_example_campaign_lists_compile():
    c = config.load(str(EXAMPLE))
    c["campaigns"]["enabled"] = True
    g = CampaignGate.from_config(c["campaigns"])
    m = CallMatcher(load_rules(["en_scams"]), g)
    for u in ["are you interested in a home warranty", "ok " * 30]:
        m.update(u)
        m.commit(u)
    assert m.killed
