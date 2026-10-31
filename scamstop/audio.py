"""G.711 decode and 8 -> 16 kHz resample with numpy (audioop is gone in Python 3.13)."""
from __future__ import annotations

import numpy as np


def _ulaw_table() -> np.ndarray:
    t = np.zeros(256, np.int16)
    for i in range(256):
        u = ~i & 0xFF
        sign, exp, mant = u & 0x80, (u >> 4) & 0x07, u & 0x0F
        s = (((mant << 3) + 0x84) << exp) - 0x84
        t[i] = -s if sign else s
    return t


def _alaw_table() -> np.ndarray:
    t = np.zeros(256, np.int16)
    for i in range(256):
        a = i ^ 0x55
        sign, exp, mant = a & 0x80, (a >> 4) & 0x07, a & 0x0F
        s = (mant << 4) + 8 if exp == 0 else ((mant << 4) + 0x108) << (exp - 1)
        t[i] = s if sign else -s
    return t


ULAW, ALAW = _ulaw_table(), _alaw_table()


def decode_g711(payload: bytes, pt: int) -> np.ndarray:
    """RTP payload -> int16 samples at 8 kHz. pt 0 = PCMU, 8 = PCMA."""
    table = ULAW if pt == 0 else ALAW
    return table[np.frombuffer(payload, np.uint8)]


def upsample_8k_16k(x: np.ndarray) -> np.ndarray:
    """Linear interpolation; plenty for speech recognition."""
    if len(x) == 0:
        return x.astype(np.float32)
    xf = x.astype(np.float32)
    out = np.empty(len(xf) * 2, np.float32)
    out[0::2] = xf
    out[1:-1:2] = (xf[:-1] + xf[1:]) / 2
    out[-1] = xf[-1]
    return out


def rms(x: np.ndarray) -> float:
    return float(np.sqrt(np.mean(x.astype(np.float32) ** 2))) if len(x) else 0.0


def rtp_payload(pkt: bytes) -> tuple[int, bytes] | None:
    """Return (payload_type, payload) or None for junk. Handles CSRCs and header extensions."""
    if len(pkt) <= 12 or (pkt[0] >> 6) != 2:
        return None
    cc, ext, pad = pkt[0] & 0x0F, pkt[0] & 0x10, pkt[0] & 0x20
    off = 12 + 4 * cc
    if ext:
        if len(pkt) < off + 4:
            return None
        off += 4 + 4 * int.from_bytes(pkt[off + 2:off + 4], "big")
    end = len(pkt) - (pkt[-1] if pad else 0)
    if off >= end:
        return None
    return pkt[1] & 0x7F, pkt[off:end]
