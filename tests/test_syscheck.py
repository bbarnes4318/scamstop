"""Auto-detection and fixes against a fake server filesystem."""
from pathlib import Path

import pytest

from scamstop import config, syscheck


def fs(tmp_path, files: dict, procs=()):
    for path, text in files.items():
        f = tmp_path / path.lstrip("/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    for i, name in enumerate(procs):
        f = tmp_path / f"proc/{100 + i}/comm"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(name + "\n")
    return tmp_path


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setattr(syscheck, "ROOT", tmp_path)
    monkeypatch.setattr(syscheck, "version", lambda cmd: None)
    return tmp_path


OPENSIPS = '''
loadmodule "dialog.so"
loadmodule "mi_fifo.so"
loadmodule "rtpengine.so"
modparam("mi_fifo", "fifo_name", "/var/run/opensips/fifo")
modparam("mi_fifo", "reply_dir", "/var/tmp/")
modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")
'''


def test_detects_opensips_and_rtpengine(root):
    fs(root, {"/etc/opensips/opensips.cfg": OPENSIPS, "/etc/rtpengine/rtpengine.conf": "[rtpengine]\nlisten-ng = 127.0.0.1:2223\n"},
       procs=["opensips", "rtpengine", "redis-server"])
    d = syscheck.detect()
    assert d["platform"] == "opensips" and d["label"] == "OpenSIPS"
    s = d["settings"]
    assert s["proxy"] == {"type": "opensips", "fifo": "/var/run/opensips/fifo", "reply_dir": "/var/tmp/"}
    assert s["rtpengine"] == {"host": "127.0.0.1", "port": 2223} and s["asr"]["workers"] >= 1


def test_detects_vicidial_trunks(root):
    fs(root, {
        "/etc/asterisk/http.conf": "[general]\nenabled=no\nbindport=8088\n",
        "/etc/asterisk/sip.conf": "[fractel]\ntype=peer\nhost=64.34.1.2\n\n[8001]\ntype=friend\nhost=dynamic\n",
        "/etc/asterisk/pjsip.conf": "[telnyx]\ntype=endpoint\naors=telnyx\n[telnyx]\ntype=aor\ncontact=sip:192.76.120.10\n",
        "/etc/astguiclient.conf": "PATHhome => /usr/share/astguiclient\n"}, procs=["asterisk"])
    d = syscheck.detect()
    a = d["found"]["asterisk"]
    assert d["platform"] == "asterisk" and d["label"] == "ViciDial (Asterisk)"
    assert a["trunks"] == ["fractel", "telnyx"] and not a["http_enabled"]
    assert d["settings"]["asterisk"]["external_regex"] == "^(PJSIP|SIP)/(fractel|telnyx)-"


def test_detects_freeswitch_gateways(root):
    fs(root, {"/etc/freeswitch/autoload_configs/event_socket.conf.xml":
              '<param name="listen-ip" value="::"/><param name="listen-port" value="8022"/><param name="password" value="s3cret"/>',
              "/etc/freeswitch/sip_profiles/external/carrier.xml": '<include><gateway name="voipms"></gateway></include>'},
       procs=["freeswitch"])
    s = syscheck.detect()["settings"]["freeswitch"]
    assert s == {"host": "127.0.0.1", "port": 8022, "password": "s3cret", "external_regex": "^sofia/gateway/(voipms)/"}


def test_fix_ari_enables_and_backs_up(root):
    fs(root, {"/etc/asterisk/http.conf": "[general]\nenabled=no\nbindport=8088\n", "/etc/asterisk/ari.conf": "[general]\nenabled=no\n"})
    r = syscheck.fix_ari("pw123")
    http = (root / "etc/asterisk/http.conf").read_text()
    ari = (root / "etc/asterisk/ari.conf").read_text()
    assert "enabled=yes" in http and "enabled=no" not in http and "bindaddr=127.0.0.1" in http
    assert "enabled=yes" in ari and "[scamstop]\ntype=user\nread_only=no\npassword=pw123" in ari
    assert len(list((root / "etc/asterisk").glob("*.bak"))) == 2
    a = syscheck.asterisk_settings()
    assert a["http_enabled"] and a["ari_enabled"] and a["ari_users"] == ["scamstop"]
    syscheck.fix_ari("pw456")                                  # idempotent: one user, new password
    assert (root / "etc/asterisk/ari.conf").read_text().count("[scamstop]") == 1


def test_checklist_explains_fixes(root):
    fs(root, {"/etc/opensips/opensips.cfg": 'loadmodule "mi_fifo.so"\n'}, procs=["opensips"])
    cfg = config.load(None)
    cfg["proxy"]["fifo"] = str(root / "missing_fifo")
    cfg["asr"]["model_dir"] = str(root / "nomodel")
    cfg["redis"]["url"] = "redis://127.0.0.1:1/0"
    out = {c["id"]: c for c in syscheck.checks(cfg)}
    assert out["platform"]["status"] == "fail" and "mi_fifo" in out["platform"]["fix"]
    assert out["dialog"]["status"] == "fail" and "create_dialog()" in out["dialog"]["fix"]
    assert out["redis"]["status"] == "fail"
    assert out["model"]["action"] is None and "installer" in out["model"]["fix"]     # no download from anywhere by default
    cfg["asr"]["model_url"] = "https://models.example.net/m.tar.bz2"
    assert {c["id"]: c for c in syscheck.checks(cfg)}["model"]["action"] == "download_model"
