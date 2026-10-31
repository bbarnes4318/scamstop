"""Asterisk 16.6+ (incl. ViciDial / ViciBox, FreePBX, Issabel) over ARI.

Needs only stock ARI: in http.conf `enabled=yes`, and an ari.conf user. The panel's
system check writes both for you.

  calls    GET /ari/channels; the "victim" leg is the channel toward the called
           person, matched by `external_regex` against the channel name
           (e.g. ^PJSIP/carrier- or ^SIP/fractel-)
  audio    a snoop channel on the victim leg (spy=out: what the victim hears,
           i.e. the caller; spy=in: what the victim says) bridged to an
           External Media channel that sends RTP (ulaw) to ScamStop
  warning  a snoop channel with whisper=out plays the recording into the
           victim's ear (sound:scamstop-warning, copied into the sounds dir)
  hang up  DELETE /ari/channels/{id}; works while ringing too
An ARI websocket for the app stays open, which is what registers the Stasis
app Asterisk needs for snoop and External Media.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from ..control import Dialog
from .base import Platform, rtp_receive

SOUND = "scamstop-warning"


class AriError(RuntimeError):
    pass


class AsteriskPlatform(Platform):
    name = "asterisk"
    can_end_ringing = True
    gate_kinds = ("cli", "dnc")

    def __init__(self, cfg: dict):
        self.c = cfg
        self.base = cfg["url"].rstrip("/") + "/ari"
        self.auth = "Basic " + base64.b64encode(f"{cfg['user']}:{cfg['password']}".encode()).decode()
        self.app = cfg.get("app", "scamstop")
        self.ext = re.compile(cfg.get("external_regex") or "^(PJSIP|SIP)/")
        self._ws_thread = None
        self._ws_ok = threading.Event()

    # http ----------------------------------------------------------------------
    def req(self, method: str, path: str, **params):
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        url = f"{self.base}{path}" + (f"?{q}" if q else "")
        r = urllib.request.Request(url, method=method, headers={"Authorization": self.auth})
        try:
            with urllib.request.urlopen(r, timeout=5) as resp:
                body = resp.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as e:
            raise AriError(f"ARI {method} {path}: {e.code} {e.read()[:200].decode(errors='replace')}") from None

    # stasis app registration ---------------------------------------------------
    def ensure_app(self) -> None:
        """Keep an ARI websocket open so the Stasis app exists."""
        if self._ws_thread and self._ws_thread.is_alive():
            self._ws_ok.wait(3)
            return
        self._ws_ok.clear()
        self._ws_thread = threading.Thread(target=self._ws_loop, daemon=True)
        self._ws_thread.start()
        if not self._ws_ok.wait(5):
            raise AriError("could not open the ARI websocket (is res_ari_websockets / http.conf enabled?)")

    def _ws_loop(self):
        u = urllib.parse.urlparse(self.c["url"])
        while True:
            try:
                s = socket.create_connection((u.hostname, u.port or 8088), timeout=10)
                key = base64.b64encode(os.urandom(16)).decode()
                path = f"/ari/events?app={urllib.parse.quote(self.app)}&subscribeAll=false"
                s.sendall((f"GET {path} HTTP/1.1\r\nHost: {u.hostname}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nAuthorization: {self.auth}\r\n\r\n").encode())
                head = b""
                while b"\r\n\r\n" not in head:
                    chunk = s.recv(4096)
                    if not chunk:
                        raise ConnectionError("closed during handshake")
                    head += chunk
                if b" 101 " not in head.split(b"\r\n")[0]:
                    raise ConnectionError(head.split(b"\r\n")[0].decode(errors="replace"))
                self._ws_ok.set()
                s.settimeout(None)
                while True:  # read and discard events; answer pings
                    hdr = s.recv(2)
                    if len(hdr) < 2:
                        raise ConnectionError("websocket closed")
                    op, ln = hdr[0] & 0x0F, hdr[1] & 0x7F
                    if ln == 126:
                        ln = int.from_bytes(s.recv(2), "big")
                    elif ln == 127:
                        ln = int.from_bytes(s.recv(8), "big")
                    data = b""
                    while len(data) < ln:
                        data += s.recv(ln - len(data))
                    if op == 0x9:  # ping -> masked pong
                        mask = os.urandom(4)
                        s.sendall(bytes([0x8A, 0x80 | len(data)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))
                    elif op == 0x8:
                        raise ConnectionError("websocket closed by asterisk")
            except Exception:
                self._ws_ok.clear()
                time.sleep(3)

    # platform ------------------------------------------------------------------
    def all_calls(self):
        out = []
        for ch in self.req("GET", "/channels") or []:
            if not self.ext.search(ch.get("name", "")) or ch.get("dialplan", {}).get("app_name") == "Stasis":
                continue
            st = ch.get("state")
            if st not in ("Up", "Ring", "Ringing", "Dialing"):
                continue
            to = (ch.get("connected") or {}).get("number") or (ch.get("dialplan") or {}).get("exten") or ""
            out.append(Dialog(ch["id"], ch["id"], "", "", from_uri=(ch.get("caller") or {}).get("number", ""),
                              to_uri=to, state="up" if st == "Up" else "early",
                              extra={"name": ch.get("name", "")}))
        return out

    def channel_names(self) -> list[str]:
        return [c.get("name", "") for c in self.req("GET", "/channels") or [] if c.get("dialplan", {}).get("app_name") != "Stasis"]

    def audio(self, dlg, side, stop):
        self.ensure_app()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        made = []
        bridge = None
        try:
            sock.bind((self.c.get("media_host", "127.0.0.1"), 0))
            host = f"{sock.getsockname()[0]}:{sock.getsockname()[1]}"
            snoop = self.req("POST", f"/channels/{dlg.id}/snoop", app=self.app,
                             spy="out" if side == "caller" else "in", whisper="none")
            made.append(snoop["id"])
            ext = self.req("POST", "/channels/externalMedia", app=self.app, external_host=host, format="ulaw",
                           encapsulation="rtp", transport="udp")
            made.append(ext["id"])
            bridge = self.req("POST", "/bridges", type="mixing")["id"]
            self.req("POST", f"/bridges/{bridge}/addChannel", channel=",".join(made))
            yield from rtp_receive(sock, 0, stop)
        finally:
            sock.close()
            for cid in made:
                try:
                    self.req("DELETE", f"/channels/{cid}")
                except Exception:
                    pass
            if bridge:
                try:
                    self.req("DELETE", f"/bridges/{bridge}")
                except Exception:
                    pass

    def install_sound(self, file: str) -> None:
        d = self.c.get("sounds_dir")
        if d and file and os.path.exists(file):
            dst = os.path.join(d, SOUND + ".wav")
            if not os.path.exists(dst) or os.path.getmtime(dst) < os.path.getmtime(file):
                shutil.copyfile(file, dst)
                os.chmod(dst, 0o644)

    def warn(self, dlg, file, play_to):
        from ..daemon import wav_seconds
        self.ensure_app()
        try:
            self.install_sound(file)
        except OSError:
            pass  # may already be there, or the dir isn't writable; play will tell us
        secs = wav_seconds(file) or 15
        whisper = "both" if play_to == "both" else "out"
        snoop = self.req("POST", f"/channels/{dlg.id}/snoop", app=self.app, spy="none", whisper=whisper)
        self.req("POST", f"/channels/{snoop['id']}/play", media=f"sound:{SOUND}")
        t = threading.Timer(secs + 1, lambda: self._quiet_delete(snoop["id"]))
        t.daemon = True
        t.start()
        return secs

    def _quiet_delete(self, cid):
        try:
            self.req("DELETE", f"/channels/{cid}")
        except Exception:
            pass

    def end(self, dlg):
        self.req("DELETE", f"/channels/{dlg.id}")

    def check(self) -> str:
        info = self.req("GET", "/asterisk/info", only="system") or {}
        ver = (info.get("system") or {}).get("version", "?")
        m = re.match(r"(\d+)\.(\d+)", ver)
        if m and (int(m.group(1)), int(m.group(2))) < (16, 6):
            raise AriError(f"Asterisk {ver} is too old: External Media needs 16.6 or newer")
        n = len(self.all_calls())
        return f"Connected to Asterisk {ver}. {n} matching call{'s' if n != 1 else ''} right now."
