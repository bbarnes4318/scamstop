"""SIP 603+ ("Network Blocked") for calls rejected because ScamStop's analytics flagged them.

FCC rule 47 CFR 64.1200(k)(9) requires 603+ (ATIS-1000099) for analytics-based blocking,
with a Reason header carrying the blocking provider's redress contact and where in the
call path the block happened. Destination (do-not-call) blocks are not analytics-based
and keep their own code.
"""
from __future__ import annotations

import re

CODE = 603
PHRASE = "Network Blocked"
LOCATIONS = {
    "LN": "originating network",
    "TN": "transit network",
    "LPN": "originating private network",
    "RPN": "private network serving the called party",
    "RLN": "network serving the called party",
}
TOKEN = "SCAMSTOP_REASON"

_TEL = re.compile(r"^\+[1-9]\d{6,14}$")
_URL = re.compile(r"^https://[^\s\";']+$")
_EMAIL = re.compile(r"^[^@\s\";']+@[^@\s\";']+\.[^@\s\";']+$")


def normalize_tel(tel: str) -> str:
    """'(904) 512-8487' -> '+19045128487'. Leaves anything already E.164 alone."""
    tel = (tel or "").strip()
    if not tel:
        return ""
    if tel.startswith("+"):
        return "+" + re.sub(r"\D", "", tel)
    digits = re.sub(r"\D", "", tel)
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) == 11 and digits.startswith("1"):
        return "+" + digits
    return "+" + digits


def problems(gate: dict) -> list[str]:
    """What is missing or wrong in the gate settings for a valid 603+."""
    out = []
    tel = normalize_tel(gate.get("redress_tel", ""))
    url = (gate.get("redress_url") or "").strip()
    email = (gate.get("redress_email") or "").strip()
    if not (tel or url or email):
        out.append("Add a phone number, web page or email where wrongly blocked callers can ask to be unblocked "
                   "(the FCC requires it on every blocked call).")
    if tel and not _TEL.match(tel):
        out.append(f"Unblock phone number {gate.get('redress_tel')!r} is not a valid phone number.")
    if url and not _URL.match(url):
        out.append("Unblock web page must start with https:// and have no spaces, quotes or semicolons.")
    if email and not _EMAIL.match(email):
        out.append(f"Unblock email {email!r} is not a valid email address.")
    if gate.get("location", "TN") not in LOCATIONS:
        out.append(f"Network position must be one of {', '.join(LOCATIONS)}.")
    return out


def reason(gate: dict) -> str:
    """The Reason header value, e.g. SIP;cause=603;text="v=analytics1;tel=+19045128487";location=LN"""
    parts = ["v=analytics1"]
    url = (gate.get("redress_url") or "").strip()
    email = (gate.get("redress_email") or "").strip()
    tel = normalize_tel(gate.get("redress_tel", ""))
    if url and _URL.match(url):
        parts.append(f"url={url}")
    if email and _EMAIL.match(email):
        parts.append(f"email={email}")
    if tel and _TEL.match(tel):
        parts.append(f"tel={tel}")
    loc = gate.get("location", "TN")
    if loc not in LOCATIONS:
        loc = "TN"
    return f'SIP;cause=603;text="{";".join(parts)}";location={loc}'


def for_config(gate: dict) -> str:
    """Reason header value escaped for a double-quoted Kamailio/OpenSIPS script string."""
    return reason(gate).replace("\\", "\\\\").replace('"', '\\"')


def fill(snippet: str, gate: dict) -> str:
    return snippet.replace(TOKEN, for_config(gate))
