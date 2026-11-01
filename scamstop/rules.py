"""Rule packs and the per-call matcher. Pure Python: no audio, no network."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

BUILTIN_DIR = Path(__file__).parent / "rules"
_PUNCT = re.compile(r"[^\w' ]+")
# A warning or a promise about what will NOT happen, right before the match:
#   "we will never ask you to buy gift cards", "do not buy gift cards", "i would never ..."
# but not "don't worry just buy google play cards" (the negation is about something else).
_NEGATED = re.compile(r"(\b(never|not|no one|nobody|won't|will not|wouldn't|would never)\s+(ever\s+)?"
                      r"(ask|asks|request|requests|require|tell|tells|call|calls|need|needs|make)\b(\s+\w+){0,6}\s*$)"
                      r"|(\b(never|don't|do not|not|no)\s+((buy|purchase|get|send|pay|use|deposit|load|give|share|read|wire)\s+)?$)")
# Somebody else's words being described: "if anyone says there is a warrant for your arrest
# hang up", "my grandson told me he got arrested". Downgraded to context, never dropped.
_REPORTED = re.compile(r"\b(if (someone|anyone|anybody|they|a caller|somebody)( ever)? (says?|tells? you|asks?( you)?|claims?)"
                       r"|(he|she|they|someone|somebody|the caller|a man|a woman|the man|the woman|my \w+) (said|says|told (me|us|you)|claimed|claims)"
                       r"|scammers? (say|says|will say|tell you|ask)"
                       r"|(quote|quote unquote))\b(\s+\w+){0,8}\s*$")


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
    # strength: strong = enough on its own for its action; context = only a flag, but a
    # building block for corroboration (see `combos`)
    strength: str = "strong"
    signal: str = ""        # what a context rule indicates (family, custody, injury, credential, ...)
    negatable: bool = True  # "never ask you to buy gift cards" is a warning, not a demand
    combos: tuple = ()      # signal pairs from this rule's pack that, together, are a kill

    def matches(self, text: str):
        """Every match that is not excluded by `unless` or negated right before it."""
        if self.unless and self.unless.search(text):
            return
        for m in self.regex.finditer(text):
            if self.negatable and _NEGATED.search(text[max(0, m.start() - 60):m.start()]):
                continue
            yield m

    def search(self, text: str):
        return next(self.matches(text), None)

    def qualify(self, text: str, m) -> str:
        """'reported' when the match is someone else's words being described."""
        return "reported" if _REPORTED.search(text[max(0, m.start() - 90):m.start()]) else ""


@dataclass
class Hit:
    rule_id: str
    name: str
    action: str
    matched: str
    category: str = ""
    strength: str = "strong"   # strong | context | weak
    signal: str = ""
    side: str = ""
    note: str = ""             # e.g. "reported speech", "corroborated by x + y"


def load_pack(path: str | Path) -> list[Rule]:
    path = Path(path)
    data = yaml.safe_load(path.read_text())
    pack_side = data.get("side", "caller")
    combos = tuple(tuple(sorted(c)) for c in data.get("corroboration", []) or [])
    for c in combos:
        if len(c) != 2 or not all(isinstance(x, str) and x for x in c):
            raise ValueError(f"{path}: corroboration entries are pairs of signal names")
    out = []
    for r in data["rules"]:
        action = r.get("action", "kill")
        if action not in ("kill", "flag"):
            raise ValueError(f"{path}: rule {r['id']}: action must be kill or flag")
        strength = r.get("strength", "strong")
        if strength not in ("strong", "context"):
            raise ValueError(f"{path}: rule {r['id']}: strength must be strong or context")
        if strength == "context" and (action != "flag" or not r.get("signal")):
            raise ValueError(f"{path}: rule {r['id']}: context rules are action: flag and name a signal")
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
            side=r.get("side", pack_side), strength=strength, signal=r.get("signal", ""),
            negatable=bool(r.get("negatable", True)), combos=combos))
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
                if overrides[r.id] not in ("kill", "flag"):
                    raise ValueError(f"rule {r.id}: action must be kill or flag")
                r.action = overrides[r.id]
            rules.append(r)
    return rules


def effective_match(r: Rule, text: str):
    """The match a rule acts on: like search(), but a strong kill rule ignores described speech."""
    for m in r.matches(text):
        if r.strength == "strong" and r.action == "kill" and r.qualify(text, m) == "reported":
            continue
        return m
    return None


def check_examples(rules: list[Rule]) -> list[str]:
    """Return a list of failures; empty means every example behaves."""
    fails = []
    for r in rules:
        for t in r.examples.get("hit", []):
            if not effective_match(r, normalize(t)):
                fails.append(f"{r.id}: should hit: {t!r}")
        for t in r.examples.get("miss", []):
            if effective_match(r, normalize(t)):
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
        self.reported: set[str] = set()
        self.killed = False
        self.allowed = False
        self.off: tuple[int, str] | None = None

    def text(self, partial: str = "") -> str:
        return " ".join((self.committed + " " + normalize(partial)).split())

    def update(self, partial: str) -> list[Hit]:
        """partial = recognizer text for the current (unfinished) utterance.

        Matching continues after a kill hit (dry run and warn-only calls stay monitored);
        each rule reports at most once per call."""
        full = self.text(partial)
        tail = full[-self.window:]
        hits = []
        for r in self.rules:
            if r.id in self.fired:
                continue
            text = full if r.anchored else tail
            reported = None
            for m in r.matches(text):
                if r.strength == "strong" and r.action == "kill" and r.qualify(text, m) == "reported":
                    reported = reported or m
                    continue
                self.fired.add(r.id)
                hits.append(Hit(r.id, r.name, r.action, m.group(0), r.category, r.strength, r.signal, self.side))
                if r.action == "kill":
                    self.killed = True
                break
            else:
                if reported is not None and r.id not in self.reported:
                    # someone else's words being described: a flag and a signal, not a kill;
                    # the rule can still fire for real later in the call
                    self.reported.add(r.id)
                    hits.append(Hit(r.id, r.name, "flag", reported.group(0), r.category, "context",
                                    r.signal or r.category, self.side, "reported speech"))
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
                # a business rule, not fraud evidence: never counts toward account escalation
                hits.append(Hit("off_campaign", "Off campaign", g.action, self.off[1], "campaign", "weak", "", self.side))
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


class CallEvidence:
    """Everything one call has said so far, across both sides, for corroboration.

    A context hit is only a flag. Two context hits whose signals form a pair listed in the
    rule packs' `corroboration` (e.g. family + custody: "grandma ..." + "... public defender")
    become one kill hit, "corroborated"."""

    def __init__(self, rules: list[Rule]):
        self.combos = {c for r in rules for c in r.combos}
        self.signals: dict[str, Hit] = {}
        self.fired: set[tuple] = set()

    def add(self, hit: Hit) -> Hit | None:
        if hit.strength != "context" or not hit.signal or hit.signal in self.signals:
            return None
        self.signals[hit.signal] = hit
        for other, oh in self.signals.items():
            pair = tuple(sorted((hit.signal, other)))
            if other != hit.signal and pair in self.combos and pair not in self.fired:
                self.fired.add(pair)
                return Hit("corroborated", "Corroborated scam signals", "kill",
                           f"{oh.matched} + {hit.matched}"[:160], "corroborated", "strong", "+".join(pair),
                           hit.side, f"{oh.rule_id} + {hit.rule_id}")
        return None
