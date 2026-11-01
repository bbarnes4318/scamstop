"""SIP proxy adapters: list answered dialogs and hang them up.

Each adapter returns Dialog objects in one shape so the daemon doesn't care which
proxy it runs beside. Add a new proxy by implementing list_answered() and end().
"""
from __future__ import annotations

import json
import os
import secrets
import select
import stat
import time
import urllib.request
from dataclasses import dataclass, field


@dataclass
class Dialog:
    id: object            # whatever end() needs
    callid: str
    caller_tag: str
    caller_ip: str        # host part of the caller's Contact
    bind_addr: str = ""   # local socket the call came in on
    from_uri: str = ""
    to_uri: str = ""
    callee_tag: str = ""  # the called party (the person who would hear a warning)
    raw: dict = field(default_factory=dict, repr=False)
    state: str = "up"     # up = answered; early = ringing / early media
    extra: dict = field(default_factory=dict, repr=False)


def _host(contact: str) -> str:
    return contact.split("@")[-1].split(":")[0].split(";")[0].strip("<>")


def _jsonrpc(url: str, method: str, params=None, timeout: float = 5.0):
    body = {"jsonrpc": "2.0", "method": method, "id": 1}
    if params is not None:
        body["params"] = params
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        out = json.loads(resp.read())
    if "error" in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out.get("result")


def _fifo_jsonrpc(fifo: str, method: str, params=None, reply_dir: str = "/tmp", timeout: float = 5.0):
    """OpenSIPS 3.x mi_fifo: write ':<reply fifo name>:<JSON-RPC>' and read the reply fifo.
    The reply fifo is created in mi_fifo's reply_dir (default /tmp)."""
    if not os.path.exists(fifo):
        raise FileNotFoundError(f"no MI FIFO at {fifo}; is OpenSIPS running with mi_fifo loaded?")
    if not stat.S_ISFIFO(os.stat(fifo).st_mode):
        raise RuntimeError(f"{fifo} is not a FIFO")
    name = f"scamstop_{secrets.token_hex(6)}"
    path = os.path.join(reply_dir, name)
    os.mkfifo(path, 0o666)
    try:
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}, "id": 1})
        for _ in range(20):  # ENXIO = nobody reading the FIFO yet
            try:
                fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                break
            except OSError as e:
                if e.errno != 6:
                    raise
                time.sleep(0.05)
        else:
            raise RuntimeError(f"nothing is reading {fifo}; is OpenSIPS running?")
        try:
            os.write(fd, f":{name}:{body}\n".encode())
        finally:
            os.close(fd)
        rfd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        try:
            data, deadline = b"", time.time() + timeout
            while True:
                left = deadline - time.time()
                if left <= 0:
                    raise TimeoutError("OpenSIPS did not answer on the MI FIFO")
                r, _, _ = select.select([rfd], [], [], left)
                if not r:
                    continue
                chunk = os.read(rfd, 65536)
                if not chunk and data:
                    break
                data += chunk
                try:
                    out = json.loads(data)
                    break
                except ValueError:
                    continue
        finally:
            os.close(rfd)
        if "error" in out:
            raise RuntimeError(f"{method}: {out['error']}")
        return out.get("result")
    finally:
        os.unlink(path)


class OpenSIPS:
    """OpenSIPS 3.x dialog module over mi_http (JSON-RPC) or the MI FIFO."""

    def __init__(self, url: str | None = None, fifo: str | None = None, reply_dir: str = "/tmp",
                 with_context: bool = False):
        if not url and not fifo:
            raise ValueError("opensips: set url (mi_http) or fifo")
        self.url, self.fifo, self.reply_dir = url, fifo, reply_dir
        # dlg_list_ctx also prints each dialog's $dlg_val() values: carrier mode reads the
        # switch's attribution from them (docs/carrier-integration-v1.md)
        self.with_context = with_context

    def _call(self, method, params=None):
        if self.url:
            return _jsonrpc(self.url, method, params or {})
        return _fifo_jsonrpc(self.fifo, method, params, self.reply_dir)

    def list_all(self) -> list[Dialog]:
        """Dialogs that are ringing (states 1-3) or answered (4)."""
        return self._dialogs(self._call("dlg_list_ctx" if self.with_context else "dlg_list"))

    @staticmethod
    def _dialogs(res) -> list[Dialog]:
        out = []
        for d in (res or {}).get("Dialogs", []) or []:
            if not isinstance(d, dict):
                continue
            st = d.get("state")
            if st not in (1, 2, 3, 4) or "callid" not in d or "ID" not in d:
                continue
            callee = d.get("callee_tag") or ((d.get("CALLEES") or [{}])[0] or {}).get("callee_tag", "")
            out.append(Dialog(d["ID"], d["callid"], d.get("caller_tag", ""), _host(d.get("caller_contact", "")),
                              d.get("caller_bind_addr", ""), d.get("from_uri", ""), d.get("to_uri", ""), callee, d,
                              "up" if st in (3, 4) else "early"))  # 3 = answered, ACK not seen yet
        return out

    def list_answered(self) -> list[Dialog]:
        return [d for d in self.list_all() if d.state == "up"]

    def end(self, dlg: Dialog) -> None:
        self._call("dlg_end_dlg", {"dialog_id": dlg.id})

    def exists(self, dlg: Dialog) -> bool:
        """Is this exact dialog still listed (not terminated)? dlg_list takes a callid filter."""
        try:
            res = self._call("dlg_list", {"callid": dlg.callid})
        except RuntimeError as e:
            if "not found" in str(e).lower():
                return False
            raise
        return any(str(d.id) == str(dlg.id) for d in self._dialogs(res))


class Kamailio:
    """Kamailio dialog module over jsonrpcs (xhttp transport)."""

    def __init__(self, url: str):
        self.url = url

    def list_all(self) -> list[Dialog]:
        res = _jsonrpc(self.url, "dlg.list") or []
        out = []
        for d in res:
            st = d.get("state")
            if st not in (1, 2, 3, 4):
                continue
            caller = d.get("caller", {})
            out.append(Dialog((d["h_entry"], d["h_id"]), d["call-id"], caller.get("tag", ""),
                              _host(caller.get("contact", "")), caller.get("socket", ""),
                              d.get("from_uri", ""), d.get("to_uri", ""), d.get("callee", {}).get("tag", ""), d,
                              "up" if st in (3, 4) else "early"))  # 3 = answered, ACK not seen yet
        return out

    def list_answered(self) -> list[Dialog]:
        return [d for d in self.list_all() if d.state == "up"]

    def end(self, dlg: Dialog) -> None:
        _jsonrpc(self.url, "dlg.end_dlg", list(dlg.id))


def make(cfg: dict):
    kind = cfg.get("type", "opensips")
    if kind == "opensips":
        return OpenSIPS(cfg.get("url"), cfg.get("fifo"), cfg.get("reply_dir", "/tmp"), bool(cfg.get("with_context")))
    if kind == "kamailio":
        return Kamailio(cfg["url"])
    raise ValueError(f"unknown proxy type {kind!r}")
