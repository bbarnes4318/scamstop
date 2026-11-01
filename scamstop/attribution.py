"""Trusted call attribution (carrier integration mode, docs/carrier-integration-v1.md).

Who a call belongs to is decided by the carrier's switch, which already resolves the
customer from the portal's registry (source IP, entry IP and reseller dial prefix) and
stores the answer as dialog values. ScamStop reads those values back over the dialog
module's MI (OpenSIPS ``dlg_list_ctx``) and validates every field before using it.

SIP Contact hosts, Call-ID hosts, media IPs, caller IDs and dialer tags are supporting
indicators only. They never decide which customer account a call is charged to.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# Identifier shapes. They mirror the shapes voip-portal's sync script accepts
# (sbc/opensips-portal-sync.sh): numeric customer ids up to 18 digits, reseller
# customer endpoints "pfx:<reseller id>:<3-6 digits>".
CUSTOMER_ID = re.compile(r"^[0-9]{1,18}$")
ENDPOINT = re.compile(r"^pfx:[0-9]{1,18}:[0-9]{3,6}$")
REASON_CODE = re.compile(r"^[a-z0-9_]{1,40}$")
CASE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{8,80}$")
ACTOR = re.compile(r"^[A-Za-z0-9._@:-]{1,64}$")
CALL_ID_MAX = 256
SUPPORTED_VERSIONS = ("1",)


def valid_customer_id(v) -> bool:
    return isinstance(v, str) and bool(CUSTOMER_ID.fullmatch(v)) and v != "0" * len(v)


def valid_ipv4(v) -> bool:
    if not isinstance(v, str) or len(v) > 15:
        return False
    try:
        ipaddress.IPv4Address(v)
    except ValueError:
        return False
    return True


def valid_endpoint(v) -> bool:
    return isinstance(v, str) and bool(ENDPOINT.fullmatch(v))


def valid_callid(v) -> bool:
    return isinstance(v, str) and 0 < len(v) <= CALL_ID_MAX and v.isprintable() and " " not in v


@dataclass(frozen=True)
class Attribution:
    """What the switch says about one call. trusted=False means: monitor it, but never
    take an account-level action because of it."""
    callid: str
    customer_id: str | None = None   # the account that placed the call (a reseller's CHILD when applicable)
    parent_id: str | None = None     # the reseller above it, if any
    src_ip: str | None = None        # SIP source IP the switch authenticated
    endpoint: str | None = None      # resolved endpoint key, e.g. pfx:<reseller>:<digits>
    entry_ip: str | None = None      # switch socket the call arrived on
    dialog_id: str | None = None     # dialog module identifier (dlg_end_dlg dialog_id)
    from_tag: str | None = None
    to_tag: str | None = None
    trusted: bool = False
    problem: str = ""                # why it is untrusted, for metrics and logs

    @property
    def account(self) -> str | None:
        return self.customer_id if self.trusted else None


def _values(raw: dict) -> dict[str, str]:
    """dlg_list_ctx prints a dialog's values as a list of one-entry objects. Accept a plain
    object too, and the same list nested under "context"; anything else is ignored."""
    out: dict[str, str] = {}
    for src in (raw.get("values"), (raw.get("context") or {}).get("values") if isinstance(raw.get("context"), dict) else None):
        if isinstance(src, dict):
            src = [src]
        if not isinstance(src, list):
            continue
        for item in src:
            if isinstance(item, dict):
                for k, v in item.items():
                    if isinstance(k, str) and isinstance(v, (str, int)) and not isinstance(v, bool):
                        out.setdefault(k, str(v))
    return out


def from_dialog(dlg, names: dict) -> Attribution:
    """Build an Attribution from a control.Dialog whose raw MI record carries dialog values."""
    callid = dlg.callid if valid_callid(dlg.callid) else ""
    did = str(dlg.id) if dlg.id is not None else None
    base = dict(callid=callid, dialog_id=did, from_tag=dlg.caller_tag or None, to_tag=dlg.callee_tag or None)
    if not callid:
        return Attribution(**dict(base, callid=""), problem="bad_callid")
    vals = _values(dlg.raw or {})
    if not vals:
        return Attribution(**base, problem="no_values")
    ver = vals.get(names["version"])
    if ver not in SUPPORTED_VERSIONS:
        return Attribution(**base, problem="bad_version")
    cust = vals.get(names["customer_id"], "")
    parent = vals.get(names["parent_id"], "") or None
    src = vals.get(names["src_ip"], "") or None
    ep = vals.get(names["endpoint"], "") or None
    entry = vals.get(names["entry_ip"], "") or None
    if not valid_customer_id(cust):
        return Attribution(**base, problem="bad_customer_id")
    if parent is not None and (not valid_customer_id(parent) or parent == cust):
        return Attribution(**base, problem="bad_parent_id")
    if src is not None and not valid_ipv4(src):
        return Attribution(**base, problem="bad_src_ip")
    if entry is not None and not valid_ipv4(entry):
        return Attribution(**base, problem="bad_entry_ip")
    if ep is not None:
        if not valid_endpoint(ep):
            return Attribution(**base, problem="bad_endpoint")
        # a reseller child's endpoint names its reseller; it must agree with parent_id
        if parent is None or ep.split(":")[1] != parent:
            return Attribution(**base, problem="endpoint_parent_mismatch")
    return Attribution(**base, customer_id=cust, parent_id=parent, src_ip=src, endpoint=ep,
                       entry_ip=entry, trusted=True)


def untrusted(dlg, problem: str = "standalone") -> Attribution:
    return Attribution(callid=dlg.callid if valid_callid(dlg.callid) else "",
                       dialog_id=str(dlg.id) if dlg.id is not None else None,
                       from_tag=dlg.caller_tag or None, to_tag=dlg.callee_tag or None, problem=problem)
