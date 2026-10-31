"""System check: find the phone system on this server, read its settings, and say
exactly what is missing and how to fix it.

detect()  -> what is installed/running and the ScamStop settings that fit it
checks()  -> a list of {id, label, status: ok|warn|fail, detail, fix, action?}
fix_ari() -> turn on ARI in Asterisk and create the ScamStop user (with backups)
"""
from __future__ import annotations

import glob
import os
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(os.environ.get("SCAMSTOP_ROOT", "/"))  # tests point this at a fake filesystem


def p(path: str) -> Path:
    return ROOT / path.lstrip("/")


def running() -> set[str]:
    names = set()
    for comm in glob.glob(str(p("/proc/[0-9]*/comm"))):
        try:
            names.add(Path(comm).read_text().strip())
        except OSError:
            pass
    return names


def version(cmd: list[str]) -> str | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
        m = re.search(r"(\d+\.\d+(\.\d+)*)", out.stdout + out.stderr)
        return m.group(1) if m else (out.stdout + out.stderr).strip()[:60] or None
    except Exception:
        return None


def _read(path: str) -> str:
    try:
        return p(path).read_text(errors="replace")
    except OSError:
        return ""


def _vtuple(v: str | None) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3]) or (0,)


# ------------------------------------------------------------------ per-system parsers
def opensips_settings() -> dict:
    cfg = _read("/etc/opensips/opensips.cfg")
    mods = set(re.findall(r'^\s*loadmodule\s+"([^"]+?)(?:\.so)?"', cfg, re.M))
    fifo = re.search(r'modparam\(\s*"mi_fifo"\s*,\s*"fifo_name"\s*,\s*"([^"]+)"', cfg)
    reply = re.search(r'modparam\(\s*"mi_fifo"\s*,\s*"reply_dir"\s*,\s*"([^"]+)"', cfg)
    http = re.search(r'modparam\(\s*"httpd"\s*,\s*"port"\s*,\s*(\d+)', cfg)
    rtp = re.search(r'modparam\(\s*"rtpengine"\s*,\s*"rtpengine_sock"\s*,\s*"udp:([\d.]+):(\d+)', cfg)
    out = {"found": bool(cfg), "modules": sorted(mods)}
    proxy = {"type": "opensips"}
    if fifo:
        proxy["fifo"] = fifo.group(1)
    elif "mi_http" in mods and http:
        proxy["url"] = f"http://127.0.0.1:{http.group(1)}/mi"
    if reply:
        proxy["reply_dir"] = reply.group(1)
    out["settings"] = {"platform": {"type": "opensips"}, "proxy": proxy}
    if rtp:
        out["settings"]["rtpengine"] = {"host": rtp.group(1), "port": int(rtp.group(2))}
    return out


def kamailio_settings() -> dict:
    cfg = _read("/etc/kamailio/kamailio.cfg")
    mods = set(re.findall(r'^\s*loadmodule\s+"([^"]+?)(?:\.so)?"', cfg, re.M))
    port = re.search(r"^\s*listen\s*=\s*tcp:[\d.]+:(\d+)", cfg, re.M)
    rtp = re.search(r'rtpengine_sock"\s*,\s*"udp:([\d.]+):(\d+)', cfg)
    out = {"found": bool(cfg), "modules": sorted(mods),
           "settings": {"platform": {"type": "kamailio"},
                        "proxy": {"type": "kamailio", "url": f"http://127.0.0.1:{port.group(1) if port else 5060}/RPC"}}}
    if rtp:
        out["settings"]["rtpengine"] = {"host": rtp.group(1), "port": int(rtp.group(2))}
    return out


def rtpengine_settings() -> dict:
    conf = _read("/etc/rtpengine/rtpengine.conf") or _read("/etc/rtpengine.conf")
    ng = re.search(r"^\s*listen-ng\s*=\s*([\d.]+):(\d+)", conf, re.M)
    out = {"found": bool(conf)}
    if ng:
        out["settings"] = {"rtpengine": {"host": ng.group(1), "port": int(ng.group(2))}}
    return out


def rtpengine_transcoding() -> bool | None:
    if not shutil.which("rtpengine"):
        return None
    try:
        r = subprocess.run(["rtpengine", "--codecs"], capture_output=True, text=True, timeout=4)
        return r.returncode == 0 and bool(re.search(r"(?i)opus|g722|pcma", r.stdout))
    except Exception:
        return None


def _ini_blocks(text: str) -> list[tuple[str, dict[str, str]]]:
    """Asterisk-style config as (section, settings) pairs; pjsip.conf reuses section names, so keep them all."""
    out, cur = [], None
    for line in text.splitlines():
        line = line.split(";")[0].strip()
        m = re.match(r"\[([^\]]+)\](\(.*\))?", line)
        if m:
            cur = (m.group(1).strip(), {})
            out.append(cur)
        elif cur and "=" in line:
            k, _, v = line.partition("=")
            cur[1][k.strip().lstrip(">")] = v.strip()
    return out


def _ini_sections(text: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for name, kv in _ini_blocks(text):
        out.setdefault(name, {}).update(kv)
    return out


def asterisk_settings() -> dict:
    http = _ini_sections(_read("/etc/asterisk/http.conf"))
    ari = _ini_sections(_read("/etc/asterisk/ari.conf"))
    g = http.get("general", {})
    port = g.get("bindport", "8088")
    users = [s for s, kv in ari.items() if kv.get("type") == "user"]
    # trunks: pjsip endpoints whose aor has a static contact, chan_sip peers with a fixed host
    trunks = set()
    pj = _ini_blocks(_read("/etc/asterisk/pjsip.conf"))
    static_aors = {s for s, kv in pj if kv.get("type") == "aor" and re.search(r"sip:[\d.]+", kv.get("contact", ""))}
    for s, kv in pj:
        if kv.get("type") == "endpoint" and (kv.get("aors", s) in static_aors):
            trunks.add(("PJSIP", s))
    for s, kv in _ini_blocks(_read("/etc/asterisk/sip.conf")):
        if re.fullmatch(r"[\d.]+", kv.get("host", "")) and kv.get("type") in ("peer", "friend"):
            trunks.add(("SIP", s))
    techs = sorted({t for t, _ in trunks})
    names = sorted({re.escape(n) for _, n in trunks})
    regex = f"^({'|'.join(techs)})/({'|'.join(names)})-" if trunks else "^(PJSIP|SIP)/"
    vicidial = bool(_read("/etc/astguiclient.conf")) or p("/usr/share/astguiclient").exists()
    return {"found": bool(http or ari), "http_enabled": g.get("enabled", "no").lower() == "yes",
            "ari_enabled": ari.get("general", {}).get("enabled", "no").lower() == "yes",
            "ari_users": users, "trunks": sorted(n for _, n in trunks), "vicidial": vicidial,
            "settings": {"platform": {"type": "asterisk"},
                         "asterisk": {"url": f"http://127.0.0.1:{port}", "external_regex": regex,
                                      **({"user": "scamstop"} if "scamstop" in users else {})}}}


def freeswitch_settings() -> dict:
    es = _read("/etc/freeswitch/autoload_configs/event_socket.conf.xml")
    def param(name):
        m = re.search(rf'name="{name}"\s+value="([^"]+)"', es)
        return m.group(1) if m else None
    gws = set()
    for f in glob.glob(str(p("/etc/freeswitch/sip_profiles/external/*.xml"))):
        gws |= set(re.findall(r'<gateway\s+name="([^"]+)"', Path(f).read_text(errors="replace")))
    regex = f"^sofia/gateway/({'|'.join(sorted(re.escape(g) for g in gws))})/" if gws else "^sofia/gateway/"
    host = param("listen-ip") or "127.0.0.1"
    return {"found": bool(es), "gateways": sorted(gws),
            "settings": {"platform": {"type": "freeswitch"},
                         "freeswitch": {"host": "127.0.0.1" if host in ("::", "0.0.0.0") else host,
                                        "port": int(param("listen-port") or 8021),
                                        "password": param("password") or "ClueCon", "external_regex": regex}}}


# ------------------------------------------------------------------ detection
def merge(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def detect() -> dict:
    procs = running()
    found = {
        "opensips": {"running": "opensips" in procs, "version": version(["opensips", "-V"])},
        "kamailio": {"running": "kamailio" in procs, "version": version(["kamailio", "-v"])},
        "rtpengine": {"running": "rtpengine" in procs, "version": version(["rtpengine", "--version"])},
        "asterisk": {"running": "asterisk" in procs, "version": version(["asterisk", "-V"])},
        "freeswitch": {"running": "freeswitch" in procs, "version": version(["freeswitch", "-version"])},
        "redis": {"running": bool(procs & {"redis-server", "valkey-server", "keydb-server"})},
    }
    found["opensips"].update(opensips_settings())
    found["kamailio"].update(kamailio_settings())
    found["rtpengine"].update(rtpengine_settings())
    found["asterisk"].update(asterisk_settings())
    found["freeswitch"].update(freeswitch_settings())
    order = ["opensips", "kamailio", "asterisk", "freeswitch"]
    pick = next((k for k in order if found[k]["running"]), None) or next((k for k in order if found[k].get("found")), None)
    settings = {}
    if pick:
        settings = merge(settings, found[pick]["settings"])
        if pick in ("opensips", "kamailio") and found["rtpengine"].get("settings"):
            settings = merge(settings, found["rtpengine"]["settings"])
    cores = os.cpu_count() or 2
    workers = max(1, min(8, cores - 1))
    settings = merge(settings, {"asr": {"workers": workers}, "monitor": {"max_streams": max(40, workers * 70)}})
    label = {"opensips": "OpenSIPS", "kamailio": "Kamailio", "asterisk": "Asterisk", "freeswitch": "FreeSWITCH"}.get(pick)
    if pick == "asterisk" and found["asterisk"].get("vicidial"):
        label = "ViciDial (Asterisk)"
    return {"platform": pick, "label": label, "found": found, "settings": settings, "cores": cores}


# ------------------------------------------------------------------ checklist
def checks(cfg: dict, det: dict | None = None, status: dict | None = None) -> list[dict]:
    det = det or detect()
    f = det["found"]
    kind = (cfg.get("platform") or {}).get("type") or cfg["proxy"]["type"]
    out = []

    def add(id_, label, ok, detail="", fix="", action=None, warn=False):
        out.append({"id": id_, "label": label, "status": "ok" if ok else ("warn" if warn else "fail"),
                    "detail": detail, "fix": "" if ok else fix, "action": None if ok else action})

    from . import platforms
    plat_msg = ""
    try:
        msg = plat_msg = platforms.make(cfg).check()
        add("platform", f"Connected to {platforms.TYPES.get(kind, kind)}", True, msg)
    except Exception as e:
        fixes = {
            "opensips": 'In opensips.cfg: loadmodule "dialog.so" and loadmodule "mi_fifo.so", plus '
                        'modparam("mi_fifo", "fifo_name", "/run/opensips/opensips_fifo"). Restart OpenSIPS.',
            "kamailio": 'In kamailio.cfg: loadmodule "dialog.so", "xhttp.so", "jsonrpcs.so", a TCP listen= line, and '
                        'event_route[xhttp:request] { if ($hu =~ "^/RPC") { jsonrpc_dispatch(); exit; } }',
            "asterisk": "Click 'Set up ARI for me', or enable ARI in http.conf and ari.conf.",
            "freeswitch": "Load mod_event_socket and check the password in autoload_configs/event_socket.conf.xml.",
        }
        action = "fix_ari" if kind == "asterisk" else None
        add("platform", f"Connect to {platforms.TYPES.get(kind, kind)}", False, str(e)[:240], fixes.get(kind, ""), action)

    if kind in ("opensips", "kamailio"):
        mods = f[kind].get("modules", [])
        if f[kind].get("found"):
            add("dialog", "Dialog module loaded", "dialog" in mods, "",
                f'Add loadmodule "dialog.so" to {kind}.cfg and call {"create_dialog()" if kind == "opensips" else "dlg_manage()"} on new INVITEs.')
        v = f["rtpengine"].get("version")
        add("rtpengine", "rtpengine 11 or newer", _vtuple(v) >= (11,), f"Found {v}" if v else "rtpengine not found on this server",
            "ScamStop copies call audio through rtpengine 'subscribe', added in version 11. Upgrade rtpengine.",
            warn=v is None)
        tc = rtpengine_transcoding()
        add("transcoding", "rtpengine can play the warning", bool(tc),
            "" if tc else ("rtpengine not on this server, couldn't check" if tc is None else "Built without transcoding"),
            "Playing the warning needs rtpengine built with transcoding (ffmpeg). Without it ScamStop hangs up without a warning.",
            warn=True)
        try:
            from .rtpengine import RtpEngine
            r = RtpEngine(cfg["rtpengine"]["host"], int(cfg["rtpengine"]["port"]), timeout=2).ng({"command": "ping"})
            add("rtpengine_ng", "rtpengine control port answers", r.get("result") == "pong")
        except Exception as e:
            add("rtpengine_ng", "rtpengine control port answers", False, str(e)[:160],
                f"Check listen-ng in rtpengine.conf matches {cfg['rtpengine']['host']}:{cfg['rtpengine']['port']}.")
    if kind == "asterisk":
        v = f["asterisk"].get("version") or (re.search(r"Asterisk ([\d.]+)", plat_msg) or [None, None])[1]
        add("asterisk_version", "Asterisk 16.6 or newer", _vtuple(v) >= (16, 6), f"Found {v}" if v else "",
            "External Media (how ScamStop hears calls) needs Asterisk 16.6+. Upgrade Asterisk / ViciBox.", warn=v is None)
        add("asterisk_ari", "ARI turned on", f["asterisk"].get("http_enabled") and f["asterisk"].get("ari_enabled")
            and "scamstop" in f["asterisk"].get("ari_users", []), "", "Click 'Set up ARI for me'.", "fix_ari")
        add("trunks", "Carrier trunks identified", bool(f["asterisk"].get("trunks")),
            ", ".join(f["asterisk"].get("trunks", [])[:6]),
            "Set 'Calls to protect' to a pattern matching your carrier trunk channels, e.g. ^PJSIP/mycarrier-", warn=True)
    if kind == "freeswitch":
        add("gateways", "Carrier gateways identified", bool(f["freeswitch"].get("gateways")),
            ", ".join(f["freeswitch"].get("gateways", [])[:6]),
            "Set 'Calls to protect' to a pattern matching your gateway channels, e.g. ^sofia/gateway/mycarrier/", warn=True)

    try:
        from .store import Store
        Store.from_url(cfg["redis"]["url"]).r.ping()
        add("redis", "Redis running", True)
    except Exception as e:
        add("redis", "Redis running", False, str(e)[:160], "Install and start Redis: the installer does this for you.")

    from . import model
    st = (status or {}).get("model", {})
    if st.get("state") == "downloading":
        add("model", "Speech model", False, f"Downloading… {st.get('percent', 0)}%", "Nothing to do, it's on its way.", warn=True)
    else:
        has_url = bool(cfg["asr"].get("model_url"))
        add("model", "Speech model installed", model.present(cfg["asr"]["model_dir"]), "",
            "The installer includes it: run the installer again to restore it."
            + (" Or download it from your model_url." if has_url else ""),
            "download_model" if has_url else None)
    cores = det.get("cores", 1)
    add("cpu", f"{cores} CPU cores", cores >= 2, f"About {max(1, cores - 1) * 70} calls at once",
        "One core is tight; ScamStop will run but can listen to fewer calls.", warn=True)
    from . import block603
    gate = cfg.get("gate", {})
    bad = block603.problems(gate)
    add("redress", "Unblock contact on blocked calls (SIP 603+)", not bad,
        block603.reason(gate) if not bad else " ".join(bad),
        "In Setup, step 4, enter the phone number or web page where a wrongly blocked caller can ask to be "
        "unblocked. It is sent with every call ScamStop turns away.", warn=True)
    return out


# ------------------------------------------------------------------ fixes
def _backup(path: Path) -> None:
    if path.exists():
        shutil.copyfile(path, path.with_name(path.name + f".scamstop-{int(time.time())}.bak"))


def fix_ari(password: str | None = None) -> dict:
    """Enable Asterisk's HTTP server and ARI, add a 'scamstop' ARI user, reload. Backs files up first."""
    password = password or secrets.token_urlsafe(18)
    http, ari = p("/etc/asterisk/http.conf"), p("/etc/asterisk/ari.conf")
    if not http.parent.exists():
        raise RuntimeError("Asterisk config folder /etc/asterisk not found")
    for f in (http, ari):
        _backup(f)
    h = http.read_text() if http.exists() else ""
    if not re.search(r"^\[general\]", h, re.M):
        h = "[general]\n" + h
    h = re.sub(r"^\s*enabled\s*=.*$", "", h, flags=re.M)
    h = re.sub(r"^\[general\]", "[general]\nenabled=yes", h, count=1, flags=re.M)
    if not re.search(r"^\s*bindaddr\s*=", h, re.M):
        h = re.sub(r"^\[general\]", "[general]\nbindaddr=127.0.0.1", h, count=1, flags=re.M)
    http.write_text(h)
    a = ari.read_text() if ari.exists() else ""
    if not re.search(r"^\[general\]", a, re.M):
        a = "[general]\nenabled=yes\n" + a
    else:
        a = re.sub(r"^\s*enabled\s*=.*$", "", a, flags=re.M)
        a = re.sub(r"^\[general\]", "[general]\nenabled=yes", a, count=1, flags=re.M)
    a = re.sub(r"\n\[scamstop\][^\[]*", "\n", a)
    a = a.rstrip() + f"\n\n[scamstop]\ntype=user\nread_only=no\npassword={password}\n"
    ari.write_text(a)
    reloaded = False
    if shutil.which("asterisk"):
        for cmd in ("module reload http", "module reload res_ari.so"):
            subprocess.run(["asterisk", "-rx", cmd], capture_output=True, timeout=10)
        reloaded = True
    return {"user": "scamstop", "password": password, "reloaded": reloaded}
