"""Minimal rtpengine NG client: query a call, and subscribe to one party's audio.

Subscribing ("subscribe request" / "subscribe answer", rtpengine >= 11) makes
rtpengine send a copy of that party's RTP to a local UDP port. The parties hear
nothing and nothing restarts.
"""
from __future__ import annotations

import os
import re
import socket


def bencode(o) -> bytes:
    if isinstance(o, dict):
        return b"d" + b"".join(bencode(k) + bencode(v) for k, v in sorted(o.items())) + b"e"
    if isinstance(o, list):
        return b"l" + b"".join(bencode(x) for x in o) + b"e"
    if isinstance(o, int):
        return b"i" + str(o).encode() + b"e"
    o = o.encode() if isinstance(o, str) else o
    return str(len(o)).encode() + b":" + o


def bdecode(s: bytes, i: int = 0):
    c = s[i:i + 1]
    if c == b"i":
        j = s.index(b"e", i)
        return int(s[i + 1:j]), j + 1
    if c in (b"l", b"d"):
        i += 1
        out = []
        while s[i:i + 1] != b"e":
            v, i = bdecode(s, i)
            out.append(v)
        return (dict(zip(out[::2], out[1::2])) if c == b"d" else out), i + 1
    j = s.index(b":", i)
    n = int(s[i:j])
    return s[j + 1:j + 1 + n].decode(errors="replace"), j + 1 + n


class RtpEngine:
    def __init__(self, host: str = "127.0.0.1", port: int = 22222, timeout: float = 3.0):
        self.addr, self.timeout = (host, port), timeout

    def ng(self, msg: dict) -> dict:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        ck = os.urandom(6).hex().encode()
        try:
            s.sendto(ck + b" " + bencode(msg), self.addr)
            data = s.recv(65535)
            return bdecode(data[len(ck) + 1:])[0]
        finally:
            s.close()

    def media_ip(self, callid: str, from_tag: str) -> str | None:
        """The media address one party sends RTP from (identifies the real dialer box)."""
        try:
            t = self.ng({"command": "query", "call-id": callid})["tags"][from_tag]
            return t["medias"][0]["streams"][0]["endpoint"]["address"]
        except Exception:
            return None

    def subscribe(self, callid: str, from_tag: str, local_port: int) -> int:
        """Fork from_tag's audio to 127.0.0.1:local_port. Returns the G.711 payload type."""
        r = self.ng({"command": "subscribe request", "call-id": callid, "from-tag": from_tag})
        if r.get("result") != "ok":
            raise RuntimeError(f"subscribe request: {r.get('error-reason')}")
        m = re.search(r"m=audio \d+ RTP/AVP ([\d ]+)", r["sdp"])
        pts = m.group(1).split() if m else []
        pt = next((p for p in pts if p in ("0", "8")), None)
        if pt is None:
            raise RuntimeError(f"no G.711 offered ({pts}); transcode on rtpengine or add PCMU/PCMA")
        # rtpengine refuses an answer that drops codecs it offered (telephone-event): echo them all
        maps = "".join(a + "\r\n" for a in re.findall(r"a=(?:rtpmap|fmtp):[^\r\n]*", r["sdp"]))
        sdp = ("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=scamstop\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
               f"m=audio {local_port} RTP/AVP {' '.join(pts)}\r\n{maps}a=recvonly\r\n")
        r2 = self.ng({"command": "subscribe answer", "call-id": callid, "to-tag": r["to-tag"], "sdp": sdp})
        if r2.get("result") != "ok":
            raise RuntimeError(f"subscribe answer: {r2.get('error-reason')}")
        return int(pt)

    def other_tag(self, callid: str, tag: str) -> str | None:
        """The other party's tag, from rtpengine's own view of the call."""
        try:
            tags = self.ng({"command": "query", "call-id": callid})["tags"]
            return next((t for t in tags if t != tag), None)
        except Exception:
            return None

    def play(self, callid: str, to_tag: str, file: str) -> int:
        """Play an audio file TO one party. 'block egress' mutes everything else that party
        would hear while it plays, so the other side can't talk over it. Returns duration in ms
        (0 if rtpengine didn't say). Needs rtpengine built with transcoding support."""
        r = self.ng({"command": "play media", "call-id": callid, "from-tag": to_tag, "file": file,
                     "flags": ["block egress"]})
        if r.get("result") != "ok":
            raise RuntimeError(f"play media: {r.get('error-reason')}")
        return int(r.get("duration") or 0)

    def silence(self, callid: str, from_tag: str, on: bool = True) -> None:
        """Replace one party's audio with silence (so the other side hears only the warning)."""
        r = self.ng({"command": "silence media" if on else "unsilence media", "call-id": callid,
                     "from-tag": from_tag, "flags": ["directional"]})
        if r.get("result") != "ok":
            raise RuntimeError(f"{'silence' if on else 'unsilence'} media: {r.get('error-reason')}")
