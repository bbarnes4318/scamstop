"""Which enforcement policy applies to a call.

Standalone (the default): the operator's ``dry_run`` and ``warn.mode`` apply, and in hosted
mode each company's own choices apply to its calls. An operator who explicitly configures
watch-only (``dry_run: true``) gets watch-only: that advisory mode is preserved.

Carrier integration mode (``carrier.enabled``): the carrier's mandatory policy wins over
everything else. Customers and tenants cannot weaken it through any API or UI, and the
global ``dry_run`` cannot quietly turn it off either: ``carrier.policy.enforce: false`` is
the one, explicit, operator-only switch for advisory carrier mode.
"""
from __future__ import annotations

from dataclasses import dataclass

WARN_MODES = ("warn_then_hangup", "warn_only", "off")


class PolicyLocked(PermissionError):
    """A caller tried to change a setting the carrier's mandatory policy owns."""


@dataclass(frozen=True)
class Policy:
    dry_run: bool
    warn_mode: str
    tenant_id: str | None
    source: str  # carrier | tenant | operator

    @property
    def terminates(self) -> bool:
        """Will a kill decision actually end the call?"""
        return not self.dry_run and self.warn_mode != "warn_only"


def carrier_mode(cfg: dict) -> bool:
    return bool((cfg.get("carrier") or {}).get("enabled"))


def effective(cfg: dict, tenant: dict | None = None) -> Policy:
    if carrier_mode(cfg):
        p = cfg["carrier"].get("policy") or {}
        mode = p.get("warn_mode", "warn_then_hangup")
        if mode not in WARN_MODES:
            mode = "warn_then_hangup"  # a typo must not weaken enforcement
        return Policy(dry_run=not bool(p.get("enforce", True)), warn_mode=mode,
                      tenant_id=tenant["id"] if tenant else None, source="carrier")
    if tenant:
        mode = tenant.get("warn_mode") or cfg["warn"]["mode"]
        return Policy(bool(tenant.get("dry_run", True)), mode if mode in WARN_MODES else cfg["warn"]["mode"],
                      tenant["id"], "tenant")
    return Policy(bool(cfg["dry_run"]), cfg["warn"]["mode"], None, "operator")


TENANT_POLICY_FIELDS = ("dry_run", "warn_mode")


def check_tenant_change(cfg: dict, fields: dict) -> None:
    """Raise PolicyLocked if a tenant/customer change would touch the mandatory policy."""
    if carrier_mode(cfg) and any(k in fields for k in TENANT_POLICY_FIELDS):
        raise PolicyLocked(f"protection settings are set by {cfg['carrier'].get('operator') or 'the carrier'} "
                           "and cannot be changed here")
