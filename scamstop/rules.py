"""Rule packs and the per-call matcher. Pure Python: no audio, no network."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

BUILTIN_DIR = Path(__file__).parent / "rules"
_PUNCT = re.compile(r"[^\w' ]+")


def normalize(text: str) -> str:
    """Lowercase, drop punctuation (keep apostrophes), collapse whitespace."""
    return " ".join(_PUNCT.sub(" ", text.lower()).split())


@dataclass
class Rule:
    id: str
    name: str
    action: str
    category: str
    regex: re.Pattern
    unless: re.Pattern | None = None
    examples: dict = field(default_factory=dict)
    pack: str = ""
    anchored: bool = False  # has a ^ pattern: matched against the whole transcript, not the tail
    side: str = "caller"    # caller = the dialer side; victim = the person being called

    def search(self, text: str):
        m = self.regex.search(text)
        if m and self.unless and self.unless.search(text):
            return None
        return m


@dataclass
class Hit:
    rule_id: str
    name: str
    action: str
    matched: str
    category: str = ""


def load_pack(path: str | Path) -> list[Rule]:
    path = Path(path)
    data = yaml.safe_load(path.read_text())
    pack_side = data.get("side", "caller")
    out = []
    for r in data["rules"]:
        action = r.get("action", "kill")
        if action not in ("kill", "flag"):
            raise ValueError(f"{path}: rule {r['id']}: action must be kill or flag")
        if r.get("side", pack_side) not in ("caller", "victim"):
            raise ValueError(f"{path}: rule {r['id']}: side must be caller or victim")
        if not r.get("examples", {}).get("hit") or not r.get("examples", {}).get("miss"):
            raise ValueError(f"{path}: rule {r['id']}: examples.hit and examples.miss are required")
        out.append(Rule(
            id=r["id"], name=r.get("name", r["id"]), action=action, category=r.get("category", ""),
            regex=re.compile("|".join(f"(?:{p})" for p in r["patterns"])),
            unless=re.compile(r["unless"]) if r.get("unless") else None,
            examples=r["examples"], pack=data.get("pack", path.stem),
            anchored=any(p.startswith("^") for p in r["patterns"]),
            side=r.get("side", pack_side)))
    return out


def load_rules(packs: list[str], disabled: list[str] | None = None,
               overrides: dict[str, str] | None = None) -> list[Rule]:
    """packs: names of built-in packs (e.g. 'en_scams') or paths to YAML files."""
    rules, seen = [], set()
    for p in packs:
        path = Path(p) if (p.endswith((".yaml", ".yml")) or "/" in p) else BUILTIN_DIR / f"{p}.yaml"
        for r in load_pack(path):
            if r.id in seen:
                raise ValueError(f"duplicate rule id {r.id}")
            seen.add(r.id)
            if r.id in (disabled or []):
                continue
            if overrides and r.id in overrides:
                r.action = overrides[r.id]
            rules.append(r)
    return rules


def check_examples(rules: list[Rule]) -> list[str]:
    """Return a list of failures; empty means every example behaves."""
    fails = []
    for r in rules:
        for t in r.examples.get("hit", []):
            if not r.search(normalize(t)):
                fails.append(f"{r.id}: should hit: {t!r}")
        for t in r.examples.get("miss", []):
            if r.search(normalize(t)):
                fails.append(f"{r.id}: should miss: {t!r}")
    return fails


@dataclass
class CampaignGate:
    """Optional: kill calls pitching something outside the operator's allowed campaigns.

    Needs a positive off-list word; garbled or foreign audio matches nothing and only
    lands in the review log. An off-list word is forgiven if an allowed word follows
    within grace_words ("a quick survey about your medicare benefits")."""
    enabled: bool = False
    allowed: re.Pattern | None = None
    offlist: re.Pattern | None = None
    grace_words: int = 25
    action: str = "kill"
    review_min_words: int = 80

    @classmethod
    def from_config(cls, c: dict) -> "CampaignGate":
        if not c or not c.get("enabled"):
            return cls()
        return cls(True, re.compile(r"\b(" + "|".join(c["allowed"]) + r")\b"),
                   re.compile(r"\b(" + "|".join(c["offlist"]) + r")\b"),
                   int(c.get("grace_words", 25)), c.get("action", "kill"),
                   int(c.get("review_min_words", 80)))


class CallMatcher:
    """Tracks one call's transcript and returns hits as text arrives."""

    def __init__(self, rules: list[Rule], gate: CampaignGate | None = None, window: int = 400, side: str = "caller"):
        self.side = side
        self.rules = [r for r in rules if r.side == side]
        # the campaign gate judges what the dialer pitches, so it only runs on the caller side
        self.gate = (gate or CampaignGate()) if side == "caller" else CampaignGate()
        self.window = window
        self.committed = ""
        self.fired: set[str] = set()
        self.killed = False
        self.allowed = False
        self.off: tuple[int, str] | None = None

    def text(self, partial: str = "") -> str:
        return " ".join((self.committed + " " + normalize(partial)).split())

    def update(self, partial: str) -> list[Hit]:
        """partial = recognizer text for the current (unfinished) utterance."""
        if self.killed:
            return []
        full = self.text(partial)
        tail = full[-self.window:]
        hits = []
        for r in self.rules:
            if r.id in self.fired:
                continue
            m = r.search(full if r.anchored else tail)
            if m:
                self.fired.add(r.id)
                hits.append(Hit(r.id, r.name, r.action, m.group(0), r.category))
                if r.action == "kill":
                    self.killed = True
                    return hits
        g = self.gate
        if g.enabled and not self.allowed:
            if g.allowed.search(tail):
                self.allowed = True
            elif self.off is None:
                m = g.offlist.search(tail)
                if m:
                    self.off = (len(full.split()), m.group(0))
            elif len(full.split()) - self.off[0] >= g.grace_words:
                self.fired.add("off_campaign")
                hits.append(Hit("off_campaign", "Off campaign", g.action, self.off[1], "campaign"))
                if g.action == "kill":
                    self.killed = True
        return hits

    def commit(self, partial: str) -> None:
        """Call at an utterance endpoint; the recognizer is then reset."""
        self.committed = self.text(partial)

    def needs_review(self, partial: str = "") -> bool:
        g = self.gate
        return (g.enabled and not self.killed and not self.allowed
                and len(self.text(partial).split()) >= g.review_min_words)
