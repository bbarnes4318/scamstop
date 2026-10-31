"""OpenSIPS or Kamailio (dialog module) with rtpengine handling media."""
from __future__ import annotations

import socket

from .. import control
from ..rtpengine import RtpEngine
from .base import Platform, rtp_receive


class SipPlatform(Platform):
    name = "sip"

    def __init__(self, proxy, rtp: RtpEngine | None):
        self.proxy, self.rtp = proxy, rtp

    @classmethod
    def from_config(cls, cfg: dict) -> "SipPlatform":
        return cls(control.make(cfg["proxy"]), RtpEngine(cfg["rtpengine"]["host"], int(cfg["rtpengine"]["port"])))

    def all_calls(self):
        if hasattr(self.proxy, "list_all"):
            return self.proxy.list_all()
        return self.proxy.list_answered()

    def victim_tag(self, dlg) -> str | None:
        return dlg.callee_tag or (self.rtp.other_tag(dlg.callid, dlg.caller_tag) if self.rtp else None)

    def victim_available(self, dlg) -> bool:
        return bool(self.victim_tag(dlg))

    def audio(self, dlg, side, stop):
        tag = dlg.caller_tag if side == "caller" else self.victim_tag(dlg)
        if not tag:
            raise RuntimeError("no tag for the called party")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", 0))
            pt = self.rtp.subscribe(dlg.callid, tag, sock.getsockname()[1])
            yield from rtp_receive(sock, pt, stop)
        finally:
            sock.close()

    def warn(self, dlg, file, play_to):
        if not self.rtp or not file:
            return None
        if play_to != "both":
            try:
                self.rtp.silence(dlg.callid, dlg.caller_tag)  # the scammer can't talk over the warning
            except Exception:
                pass
        targets = [t for t in [self.victim_tag(dlg)] + ([dlg.caller_tag] if play_to == "both" else []) if t]
        longest = None
        for t in targets:
            try:
                ms = self.rtp.play(dlg.callid, t, file)
                longest = max(longest or 0, ms / 1000 if ms else 0)
            except Exception:
                continue
        return longest

    def unmute(self, dlg):
        if self.rtp:
            self.rtp.silence(dlg.callid, dlg.caller_tag, on=False)

    def end(self, dlg):
        self.proxy.end(dlg)

    def media_ip(self, dlg):
        return self.rtp.media_ip(dlg.callid, dlg.caller_tag) if self.rtp else None
