"""What ScamStop needs from a phone system, whatever it is.

A platform lists calls, streams one side's audio (8 kHz int16), plays the warning
to the called party, and hangs up. Everything else (rules, smart check, strikes,
blocks, the feed, the panel) is the same on every platform.
"""
from __future__ import annotations

import re
import socket
from typing import Callable, Iterator

import numpy as np

from .. import audio
from ..control import Dialog

_DIGITS = re.compile(r"\d+")


def number_of(uri_or_num: str) -> str:
    """'sip:+18135550100@1.2.3.4' -> '8135550100' (last 10 digits of a NANP number)."""
    user = (uri_or_num or "").replace("sip:", "").replace("sips:", "").replace("tel:", "").split("@")[0].split(";")[0]
    d = "".join(_DIGITS.findall(user))
    return d[-10:] if len(d) >= 10 else d


def rtp_receive(sock: socket.socket, pt: int, stop: Callable[[], bool]) -> Iterator[np.ndarray]:
    """Yield decoded G.711 frames from an RTP socket until stop() is true."""
    sock.settimeout(1)
    while not stop():
        try:
            pkt = sock.recv(2048)
        except socket.timeout:
            continue
        p = audio.rtp_payload(pkt)
        if p and p[0] == pt:
            yield audio.decode_g711(p[1], pt)


class Platform:
    name = "base"
    can_end_ringing = False   # can hang up a call before it is answered
    gate_kinds = ("host", "tag", "cli", "dnc", "src")

    def all_calls(self) -> list[Dialog]:
        """Ringing and answered calls (Dialog.state 'early' or 'up')."""
        raise NotImplementedError

    def calls(self) -> list[Dialog]:
        return [d for d in self.all_calls() if d.state == "up"]

    def victim_available(self, dlg: Dialog) -> bool:
        return True

    def audio(self, dlg: Dialog, side: str, stop: Callable[[], bool]) -> Iterator[np.ndarray]:
        """side: 'caller' (the dialer / scammer) or 'victim' (the called party)."""
        raise NotImplementedError

    def warn(self, dlg: Dialog, file: str, play_to: str) -> float | None:
        """Play the warning; return its length in seconds, or None if it couldn't play."""
        return None

    def unmute(self, dlg: Dialog) -> None:
        """Undo the muting done for a warning (warn-only mode: the call goes on)."""
        return None

    def end(self, dlg: Dialog) -> None:
        raise NotImplementedError

    def reject(self, dlg: Dialog, reason: str) -> None:
        """Turn away a ringing call that analytics flagged: SIP 603+ "Network Blocked" with this Reason header."""
        self.end(dlg)

    def media_ip(self, dlg: Dialog) -> str | None:
        return None

    def call_exists(self, dlg: Dialog) -> bool | None:
        """Is this call still up or ringing on the switch? None = cannot tell. Used to confirm
        a termination really happened; never assume a hang-up request worked."""
        return any(d.callid == dlg.callid for d in self.all_calls())

    def check(self) -> str:
        """Connection test for the panel. Return a short success message or raise."""
        n = len(self.all_calls())
        return f"Connected. {n} call{'s' if n != 1 else ''} right now."
