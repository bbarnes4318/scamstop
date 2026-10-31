"""FreeSWITCH (incl. FusionPBX) over the stock event socket (mod_event_socket).

  calls    `show channels as json`; the victim leg is the channel toward the
           called person, matched by `external_regex` (e.g. ^sofia/gateway/)
  audio    `uuid_record` in stereo to RAM (/dev/shm): one channel is what the
           victim says, the other what they hear. ScamStop tails the file and
           deletes it when the call is done
  warning  `uuid_broadcast <uuid> <file> aleg` plays it to the victim leg
  hang up  `uuid_kill`; works while ringing too
"""
from __future__ import annotations

import json
import os
import re
import socket
import threading
import time

import numpy as np

from ..control import Dialog
from .base import Platform


class EslError(RuntimeError):
    pass


def esl_api(host: str, port: int, password: str, cmd: str, timeout: float = 5.0) -> str:
    s = socket.create_connection((host, port), timeout=timeout)
    f = s.makefile("rb")
    try:
        def read_msg():
            headers = {}
            while True:
                line = f.readline()
                if not line:
                    raise EslError("event socket closed")
                line = line.decode().rstrip("\n")
                if not line:
                    if headers:
                        break
                    continue
                k, _, v = line.partition(": ")
                headers[k] = v
            n = int(headers.get("Content-Length", 0))
            body = f.read(n).decode(errors="replace") if n else ""
            return headers, body

        h, _ = read_msg()
        if h.get("Content-Type") != "auth/request":
            raise EslError("not a FreeSWITCH event socket")
        s.sendall(f"auth {password}\n\n".encode())
        h, _ = read_msg()
        if not h.get("Reply-Text", "").startswith("+OK"):
            raise EslError("event socket password rejected")
        s.sendall(f"api {cmd}\n\n".encode())
        h, body = read_msg()
        return body
    finally:
        f.close()
        s.close()


class FreeswitchPlatform(Platform):
    name = "freeswitch"
    can_end_ringing = True
    gate_kinds = ("cli", "dnc")

    def __init__(self, cfg: dict):
        self.c = cfg
        self.ext = re.compile(cfg.get("external_regex") or "^sofia/")
        self.rec_dir = cfg.get("record_dir", "/dev/shm/scamstop")
        self.refs: dict[str, int] = {}
        self.lock = threading.Lock()

    def api(self, cmd: str) -> str:
        return esl_api(self.c["host"], int(self.c["port"]), self.c["password"], cmd)

    def all_calls(self):
        body = self.api("show channels as json").strip()
        rows = json.loads(body).get("rows", []) if body.startswith("{") else []
        out = []
        for r in rows:
            if not self.ext.search(r.get("name", "")):
                continue
            cs = (r.get("callstate") or "").upper()
            if cs == "ACTIVE":
                state = "up"
            elif cs in ("RINGING", "EARLY", "RING_WAIT", "DOWN"):
                state = "early"
            else:
                continue
            out.append(Dialog(r["uuid"], r["uuid"], "", "", from_uri=r.get("cid_num", ""),
                              to_uri=r.get("dest") or r.get("callee_num", ""), state=state, extra={"name": r.get("name")}))
        return out

    def channel_names(self) -> list[str]:
        body = self.api("show channels as json").strip()
        return [r.get("name", "") for r in (json.loads(body).get("rows", []) if body.startswith("{") else [])]

    def _path(self, uuid: str) -> str:
        return os.path.join(self.rec_dir, f"{uuid}.wav")

    def _start_rec(self, uuid: str) -> str:
        path = self._path(uuid)
        with self.lock:
            self.refs[uuid] = self.refs.get(uuid, 0) + 1
            if self.refs[uuid] > 1:
                return path
        os.makedirs(self.rec_dir, exist_ok=True)
        self.api(f"uuid_setvar {uuid} RECORD_STEREO true")
        self.api(f"uuid_setvar {uuid} record_sample_rate 8000")
        r = self.api(f"uuid_record {uuid} start {path}")
        if r.startswith("-ERR"):
            raise EslError(r.strip())
        return path

    def _stop_rec(self, uuid: str) -> None:
        with self.lock:
            self.refs[uuid] = self.refs.get(uuid, 1) - 1
            if self.refs[uuid] > 0:
                return
            self.refs.pop(uuid, None)
        path = self._path(uuid)
        try:
            self.api(f"uuid_record {uuid} stop {path}")
        except Exception:
            pass
        try:
            os.remove(path)
        except OSError:
            pass

    def audio(self, dlg, side, stop):
        path = self._start_rec(dlg.id)
        # left = audio read from the leg (the victim talking), right = audio written to it (the caller)
        victim_left = self.c.get("victim_channel", "left") == "left"
        ch = (0 if victim_left else 1) if side == "victim" else (1 if victim_left else 0)
        try:
            for _ in range(50):
                if os.path.exists(path) or stop():
                    break
                time.sleep(0.1)
            with open(path, "rb") as f:
                f.seek(44)  # WAV header
                leftover = b""
                while not stop():
                    data = f.read(16000)
                    if not data:
                        time.sleep(0.1)
                        continue
                    data = leftover + data
                    cut = len(data) - len(data) % 4
                    leftover = data[cut:]
                    frames = np.frombuffer(data[:cut], np.int16).reshape(-1, 2)
                    yield frames[:, ch].copy()
        finally:
            self._stop_rec(dlg.id)

    def warn(self, dlg, file, play_to):
        from ..daemon import wav_seconds
        if not file:
            return None
        r = self.api(f"uuid_broadcast {dlg.id} {file} {'both' if play_to == 'both' else 'aleg'}")
        if r.startswith("-ERR"):
            raise EslError(r.strip())
        return wav_seconds(file) or 15

    def end(self, dlg):
        self.api(f"uuid_kill {dlg.id}")

    def check(self) -> str:
        st = self.api("status").splitlines()
        ver = next((l for l in st if "FreeSWITCH" in l), "FreeSWITCH").strip()
        n = len(self.all_calls())
        return f"Connected. {ver[:80]}. {n} matching call{'s' if n != 1 else ''} right now."
