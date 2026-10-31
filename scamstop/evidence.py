"""Append-only JSONL evidence logs. Calls that aren't killed/flagged are never stored
(except the opt-in review and watch logs)."""
from __future__ import annotations

import json
import os
import syslog
import threading
import time

_lock = threading.Lock()


def trim(text: str, mode: str, window: int = 400) -> str | None:
    if mode == "none":
        return None
    if mode == "window":
        return text[-window:]
    return text


def write(path: str | None, record: dict) -> None:
    if not path:
        return
    record = {"ts": int(time.time()), **record}
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with _lock, open(path, "a") as f:
        f.write(json.dumps(record) + "\n")


_HAS_SYSLOG = os.path.exists("/dev/log")


def log(level: int, msg: str) -> None:
    if _HAS_SYSLOG:
        syslog.syslog(level, msg)
    else:  # containers without syslog: stderr (docker logs / journald)
        import sys
        print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, file=sys.stderr, flush=True)
