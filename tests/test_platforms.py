"""Asterisk (ARI) and FreeSWITCH (ESL) adapters against fake servers."""
import json
import os
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import numpy as np
import pytest

from scamstop import config
from scamstop.platforms.asterisk import AriError, AsteriskPlatform
from scamstop.platforms.freeswitch import FreeswitchPlatform

# ---------------------------------------------------------------- fake Asterisk
ULAW_OF = {"out": 0x9F, "in": 0x1F}   # distinct, decodable bytes per spy direction


class FakeAri:
    def __init__(self, version="18.20.0"):
        self.version, self.log, self.snoops, self.stop = version, [], {}, threading.Event()
        self.channels = [
            {"id": "100.1", "name": "PJSIP/carrier-00000001", "state": "Up",
             "caller": {"number": "8004321000"}, "connected": {"number": "18655550122"}, "dialplan": {"exten": "s"}},
            {"id": "100.2", "name": "PJSIP/agent101-00000002", "state": "Up", "caller": {"number": "101"}},
            {"id": "100.3", "name": "PJSIP/carrier-00000003", "state": "Ringing",
             "caller": {"number": "2025550111"}, "connected": {"number": ""}, "dialplan": {"exten": "14235550100"}},
        ]
        fake = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def reply(self, obj=None, code=200):
                data = json.dumps(obj).encode() if obj is not None else b""
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                u = urlparse(self.path)
                if u.path == "/ari/events":
                    fake.log.append("ws")
                    self.send_response(101)
                    self.send_header("Upgrade", "websocket")
                    self.send_header("Connection", "Upgrade")
                    self.end_headers()
                    self.wfile.flush()
                    fake.stop.wait(30)
                    return
                if u.path == "/ari/channels":
                    return self.reply(fake.channels)
                if u.path == "/ari/asterisk/info":
                    return self.reply({"system": {"version": fake.version}})
                self.reply({"message": "nope"}, 404)

            def do_POST(self):
                u = urlparse(self.path)
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                fake.log.append(("POST", u.path, q))
                if u.path.endswith("/snoop"):
                    sid = f"snoop{len(fake.snoops)}"
                    fake.snoops[sid] = q
                    return self.reply({"id": sid})
                if u.path == "/ari/channels/externalMedia":
                    host, port = q["external_host"].split(":")
                    spy = list(fake.snoops.values())[-1]["spy"]
                    threading.Thread(target=fake.send_rtp, args=(host, int(port), ULAW_OF[spy]), daemon=True).start()
                    return self.reply({"id": "ext1"})
                if u.path == "/ari/bridges":
                    return self.reply({"id": "br1"})
                return self.reply()

            def do_DELETE(self):
                fake.log.append(("DELETE", urlparse(self.path).path))
                self.reply(code=204)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def send_rtp(self, host, port, byte):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for seq in range(60):
            if self.stop.is_set():
                break
            s.sendto(bytes([0x80, 0]) + struct.pack(">HII", seq, seq * 160, 1) + bytes([byte]) * 160, (host, port))
            time.sleep(0.005)

    def close(self):
        self.stop.set()
        self.srv.shutdown()


@pytest.fixture()
def ari():
    f = FakeAri()
    yield f
    f.close()


def ast(url, **over):
    c = config.load(None)["asterisk"]
    c.update(url=url, password="pw", external_regex="^PJSIP/carrier-", **over)
    return AsteriskPlatform(c)


def test_ari_lists_only_victim_legs_with_numbers(ari):
    calls = ast(ari.url).all_calls()
    assert [(c.id, c.state, c.from_uri, c.to_uri) for c in calls] == [
        ("100.1", "up", "8004321000", "18655550122"), ("100.3", "early", "2025550111", "14235550100")]


def test_ari_audio_per_side_via_snoop_and_external_media(ari):
    p = ast(ari.url)
    d = p.all_calls()[0]
    from scamstop import audio
    for side, spy in (("caller", "out"), ("victim", "in")):
        got = []
        for frame in p.audio(d, side, lambda: len(got) >= 5):
            got.append(frame)
        assert len(got) == 5 and np.all(got[0] == audio.ULAW[ULAW_OF[spy]])
        assert list(ari.snoops.values())[-1]["spy"] == spy
    assert ("DELETE", "/ari/bridges/br1") in ari.log and ("DELETE", "/ari/channels/ext1") in ari.log
    assert "ws" in ari.log                                    # Stasis app registered


def test_ari_warning_whispers_to_victim_and_hangs_up(ari, tmp_path):
    p = ast(ari.url, sounds_dir=str(tmp_path))
    d = p.all_calls()[0]
    from scamstop.daemon import DEFAULT_WARNING
    secs = p.warn(d, DEFAULT_WARNING, "victim")
    assert 14 < secs < 16 and (tmp_path / "scamstop-warning.wav").exists()
    snoop = list(ari.snoops.values())[-1]
    assert snoop["whisper"] == "out" and snoop["spy"] == "none"
    assert any(e[0] == "POST" and e[1].endswith("/play") and e[2]["media"] == "sound:scamstop-warning" for e in ari.log if isinstance(e, tuple))
    p.end(d)
    assert ("DELETE", "/ari/channels/100.1") in ari.log


def test_ari_check_rejects_old_asterisk(ari):
    assert "Asterisk 18.20.0" in ast(ari.url).check()
    ari.version = "13.38.3"
    with pytest.raises(AriError, match="16.6"):
        ast(ari.url).check()


# ---------------------------------------------------------------- fake FreeSWITCH
class FakeEsl:
    def __init__(self, rec_dir):
        self.cmds, self.writers = [], {}
        self.rows = [
            {"uuid": "u1", "name": "sofia/gateway/carrier/18655550122", "callstate": "ACTIVE", "cid_num": "8004321000", "dest": "18655550122"},
            {"uuid": "u2", "name": "sofia/internal/1001@pbx", "callstate": "ACTIVE", "cid_num": "1001", "dest": "x"},
            {"uuid": "u3", "name": "sofia/gateway/carrier/14235550100", "callstate": "RINGING", "cid_num": "2025550111", "dest": "14235550100"},
        ]
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.conn, args=(c,), daemon=True).start()

    def conn(self, c):
        f = c.makefile("rb")
        c.sendall(b"Content-Type: auth/request\n\n")
        auth = f.readline().decode().strip()
        f.readline()
        ok = auth == "auth ClueCon"
        c.sendall(f"Content-Type: command/reply\nReply-Text: {'+OK accepted' if ok else '-ERR invalid'}\n\n".encode())
        if not ok:
            return c.close()
        cmd = f.readline().decode().strip()[4:]
        f.readline()
        self.cmds.append(cmd)
        body = self.run(cmd)
        c.sendall(f"Content-Type: api/response\nContent-Length: {len(body)}\n\n{body}".encode())
        c.close()

    def run(self, cmd):
        if cmd == "show channels as json":
            return json.dumps({"row_count": len(self.rows), "rows": self.rows})
        if cmd == "status":
            return "UP 0 years\nFreeSWITCH (Version 1.10.11 -release 64bit) is ready\n"
        if cmd.startswith("uuid_record") and " start " in cmd:
            path = cmd.split()[-1]
            ev = threading.Event()
            self.writers[path] = ev
            threading.Thread(target=self.write_wav, args=(path, ev), daemon=True).start()
            return "+OK Success\n"
        if cmd.startswith("uuid_record") and " stop " in cmd:
            self.writers.get(cmd.split()[-1], threading.Event()).set()
        return "+OK\n"

    def write_wav(self, path, ev):
        with open(path, "wb") as f:
            f.write(b"RIFF" + b"\0" * 40)
            while not ev.is_set():
                f.write(np.tile(np.array([1000, -1000], np.int16), 800).tobytes())   # L=1000 R=-1000
                f.flush()
                time.sleep(0.05)

    def close(self):
        self.sock.close()


@pytest.fixture()
def esl(tmp_path):
    f = FakeEsl(str(tmp_path))
    yield f
    f.close()


def fs(port, tmp_path):
    c = config.load(None)["freeswitch"]
    c.update(port=port, record_dir=str(tmp_path / "rec"))
    return FreeswitchPlatform(c)


def test_esl_lists_victim_legs(esl, tmp_path):
    calls = fs(esl.port, tmp_path).all_calls()
    assert [(c.id, c.state, c.from_uri, c.to_uri) for c in calls] == [
        ("u1", "up", "8004321000", "18655550122"), ("u3", "early", "2025550111", "14235550100")]


def test_esl_stereo_record_gives_each_side_and_cleans_up(esl, tmp_path):
    p = fs(esl.port, tmp_path)
    d = p.all_calls()[0]
    for side, want in (("victim", 1000), ("caller", -1000)):
        got = []
        for frame in p.audio(d, side, lambda: sum(map(len, got)) >= 4000):
            got.append(frame)
        assert np.all(np.concatenate(got) == want)
    assert "uuid_setvar u1 RECORD_STEREO true" in esl.cmds
    assert any(c.startswith("uuid_record u1 stop") for c in esl.cmds)
    assert os.listdir(tmp_path / "rec") == []                # recording deleted


def test_esl_warn_and_kill(esl, tmp_path):
    from scamstop.daemon import DEFAULT_WARNING
    p = fs(esl.port, tmp_path)
    d = p.all_calls()[0]
    assert 14 < p.warn(d, DEFAULT_WARNING, "victim") < 16
    p.end(d)
    assert f"uuid_broadcast u1 {DEFAULT_WARNING} aleg" in esl.cmds and "uuid_kill u1" in esl.cmds
    assert "1.10.11" in p.check()


def test_esl_bad_password(esl, tmp_path):
    c = config.load(None)["freeswitch"]
    c.update(port=esl.port, password="wrong")
    with pytest.raises(Exception, match="password"):
        FreeswitchPlatform(c).all_calls()
