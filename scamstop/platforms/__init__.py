"""Phone-system adapters. platform.type in the config picks one."""
from __future__ import annotations

from .base import Platform, number_of  # noqa: F401

TYPES = {
    "opensips": "OpenSIPS + rtpengine",
    "kamailio": "Kamailio + rtpengine",
    "asterisk": "Asterisk / ViciDial / FreePBX (ARI)",
    "freeswitch": "FreeSWITCH / FusionPBX (event socket)",
}


def make(cfg: dict) -> Platform:
    kind = cfg.get("platform", {}).get("type") or cfg["proxy"].get("type", "opensips")
    if kind in ("opensips", "kamailio"):
        from .sip import SipPlatform
        c = dict(cfg)
        c["proxy"] = dict(cfg["proxy"], type=kind)
        return SipPlatform.from_config(c)
    if kind == "asterisk":
        from .asterisk import AsteriskPlatform
        return AsteriskPlatform(cfg["asterisk"])
    if kind == "freeswitch":
        from .freeswitch import FreeswitchPlatform
        return FreeswitchPlatform(cfg["freeswitch"])
    raise ValueError(f"unknown platform {kind!r}")
