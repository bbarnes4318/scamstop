"""scamstop command line.

  scamstop run [-c config.yaml]            live daemon
  scamstop test-rules [-c ...]             every rule's examples must behave
  scamstop scan FILE...  [-c ...]          run rules over text / JSONL transcripts
  scamstop scan-audio FILE.wav... [-c ...] transcribe recordings locally, then scan
  scamstop block KIND VALUE [--ttl 7d] [--reason ...]
  scamstop unblock KIND VALUE
  scamstop blocks [KIND]
  scamstop sweep                           remove expired blocks now
  scamstop ui [--host 0.0.0.0] [--port 8090] web control panel
  scamstop smart-train --labels FILE        retrain the smart check on your reviewed calls
  scamstop smart-eval FILE                 precision/recall on labeled calls
  scamstop feed-sync                       share/pull the threat feed now
  scamstop feed-server [--db ...]          host a shared threat feed
  scamstop feed-admin ACTION [ARGS]        installs | trust ID | ban ID | allow KIND VALUE | delete KIND VALUE
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import wave

from . import config as cfgmod
from .rules import CallMatcher, CampaignGate, check_examples, load_rules
from .store import KINDS, Store


def _ttl(s: str) -> int:
    if not s or s == "0":
        return 0
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return int(s[:-1]) * mult[s[-1]] if s[-1] in mult else int(s)


def _rules(cfg):
    r = cfg["rules"]
    return load_rules(r["packs"], r["disabled"], r["actions"])


def _store(cfg):
    r = cfg["redis"]
    return Store.from_url(r["url"], prefix=r["prefix"], customer_key=r["customer_key"])


def _scan_text(text, rules, gate, window):
    m = CallMatcher(rules, gate, window)
    hits = []
    # feed word by word so windowed matching behaves as it does live
    words = text.split()
    for i in range(0, len(words), 8):
        chunk = " ".join(words[i:i + 8])
        hits += m.update(chunk)
        m.commit(chunk)
        if m.killed:
            break
    return hits, m


def cmd_test_rules(cfg, a):
    rules = _rules(cfg)
    fails = check_examples(rules)
    for f in fails:
        print("FAIL", f)
    print(f"{len(rules)} rules, {len(fails)} failures")
    return 1 if fails else 0


def _report(name, text, rules, gate, window):
    hits, m = _scan_text(text, rules, gate, window)
    out = {"file": name, "hits": [h.__dict__ for h in hits], "words": len(text.split())}
    if m.needs_review():
        out["review"] = True
    print(json.dumps(out))
    return bool(hits)


def cmd_scan(cfg, a):
    rules, gate, w = _rules(cfg), CampaignGate.from_config(cfg["campaigns"]), cfg["rules"]["window"]
    any_hit = False
    for path in a.files:
        with open(path) as f:
            if path.endswith(".jsonl"):
                for i, line in enumerate(f):
                    rec = json.loads(line)
                    any_hit |= _report(f"{path}:{rec.get('callid', i)}", rec.get(a.field, ""), rules, gate, w)
            else:
                any_hit |= _report(path, f.read(), rules, gate, w)
    return 0


def cmd_scan_audio(cfg, a):
    import numpy as np
    from .asr import make_recognizer
    rec = make_recognizer(a.model or cfg["asr"]["model_dir"])
    rules, gate, w = _rules(cfg), CampaignGate.from_config(cfg["campaigns"]), cfg["rules"]["window"]
    for path in a.files:
        with wave.open(path) as wf:
            if wf.getsampwidth() != 2 or wf.getnchannels() != 1:
                print(f"{path}: need 16-bit mono WAV (ffmpeg -i in -ac 1 -ar 16000 out.wav)", file=sys.stderr)
                continue
            sr = wf.getframerate()
            x = np.frombuffer(wf.readframes(wf.getnframes()), np.int16).astype(np.float32) / 32768
        s = rec.create_stream()
        s.accept_waveform(sr, x)
        s.accept_waveform(sr, np.zeros(int(sr * 0.5), np.float32))
        s.input_finished()
        parts = []
        while rec.is_ready(s):
            rec.decode_stream(s)
            if rec.is_endpoint(s):
                parts.append(rec.get_result(s))
                rec.reset(s)
        parts.append(rec.get_result(s))
        _report(path, " ".join(parts), rules, gate, w)
    return 0


def cmd_block(cfg, a):
    _store(cfg).block(a.kind, a.value, _ttl(a.ttl), a.reason or "manual")
    print(f"blocked {a.kind} {a.value}")
    return 0


def cmd_unblock(cfg, a):
    print("removed" if _store(cfg).unblock(a.kind, a.value) else "not found")
    return 0


def cmd_blocks(cfg, a):
    st = _store(cfg)
    for k in ([a.kind] if a.kind else KINDS):
        for b in st.list_blocks(k):
            exp = time.strftime("%Y-%m-%d %H:%M", time.localtime(b["expires"])) if b["expires"] else "never"
            print(f"{k:6} {b['value']:20} expires={exp:16} {b['reason']}")
    return 0


def cmd_sweep(cfg, a):
    print(f"expired {_store(cfg).sweep()}")
    return 0


def cmd_ui(cfg, a):
    from .ui import self_signed, serve
    cert, key = a.tls_cert, a.tls_key
    if a.tls == "auto" and not cert:
        base = os.path.dirname(a.config) or "."
        cert, key = os.path.join(base, "panel.crt"), os.path.join(base, "panel.key")
        self_signed(cert, key)
    serve(a.config, a.host, a.port, a.allow_restart, cert, key)
    return 0


def cmd_syscheck(cfg, a):
    from . import syscheck
    det = syscheck.detect()
    if a.write_config:
        from .ui import Panel
        p = Panel(a.config, "", False)
        if not os.path.exists(a.config):
            p.save_cfg({"dry_run": True})
        if det["settings"]:
            p.save_cfg(det["settings"])
        print(f"wrote detected settings for {det['label'] or 'no phone system found'} to {a.config}")
        cfg = p.cfg()
    print(f"phone system: {det['label'] or 'none found'}")
    icon = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL"}
    for c in syscheck.checks(cfg, det):
        print(f"[{icon[c['status']]}] {c['label']}" + (f" - {c['detail']}" if c["detail"] else ""))
        if c["fix"]:
            print(f"       fix: {c['fix']}")
    return 0


def cmd_feed_sync(cfg, a):
    from .feed import FeedClient
    print(json.dumps(FeedClient(cfg, _store(cfg)).sync()))
    return 0


def cmd_feed_server(cfg, a):
    from .feed_server import serve
    serve(a.db, a.host, a.port, a.min_networks, a.ttl_days, a.trust_proxy)
    return 0


def cmd_feed_admin(cfg, a):
    from .feed_server import Feed
    print(Feed(a.db).admin(a.action, *a.args))
    return 0


def _labeled(path):
    """Read labeled transcripts: JSONL with transcript + label (scam/not_scam or 1/0), or TSV 'label<TAB>text'."""
    from .rules import normalize
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                r = json.loads(line)
                lab = r.get("label")
                y = 1 if lab in (1, "1", "scam", True) else 0 if lab in (0, "0", "not_scam", False) else None
                if y is not None and r.get("transcript"):
                    out.append((normalize(r["transcript"]), y))
            else:
                lab, text = line.split("\t", 1)
                out.append((normalize(text), int(lab)))
    return out


def cmd_smart_train(cfg, a):
    from .smart import Classifier, evaluate
    from .smart_data import generate
    data = generate(a.samples)
    extra = []
    for path in a.labels or []:
        extra += _labeled(path)
    clf = Classifier.train(data + extra * a.weight)
    out = a.out or cfg["smart"].get("model") or "/var/lib/scamstop/smart-model.npz"
    clf.save(out)
    print(f"trained on {len(data)} generated + {len(extra)} labeled windows -> {out}")
    if extra:
        print(json.dumps(evaluate(clf, extra)))
    print("set smart.model to this path and restart to use it" if out != cfg["smart"].get("model") else "restart to use it")
    return 0


def cmd_smart_eval(cfg, a):
    from .smart import Classifier, evaluate
    clf = Classifier.load(a.model or cfg["smart"].get("model") or None)
    print(json.dumps(evaluate(clf, _labeled(a.file)), indent=2))
    return 0


def cmd_run(cfg, a):
    from .daemon import Daemon
    Daemon(cfg, a.config).run()
    return 0


def cmd_download_model(cfg, a):
    from . import model
    d = a.dir or cfg["asr"]["model_dir"]
    if model.present(d):
        print(f"speech model already in {d}")
        return 0
    last = [-1]

    def progress(p):
        if p // 10 != last[0]:
            last[0] = p // 10
            print(f"  {p}%", flush=True)
    print(f"downloading speech model to {d}")
    model.ensure(d, a.url or cfg["asr"].get("model_url"), progress)
    print("done")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser("scamstop", description="Hang up on phone scams in real time.")
    p.add_argument("-c", "--config", default=None)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run")
    sub.add_parser("test-rules")
    s = sub.add_parser("scan")
    s.add_argument("files", nargs="+")
    s.add_argument("--field", default="transcript", help="JSONL field holding the text")
    s = sub.add_parser("scan-audio")
    s.add_argument("files", nargs="+")
    s.add_argument("--model", default=None)
    s = sub.add_parser("block")
    s.add_argument("kind", choices=KINDS)
    s.add_argument("value")
    s.add_argument("--ttl", default="0", help="e.g. 3600, 12h, 7d; 0 = never expires")
    s.add_argument("--reason", default="")
    s = sub.add_parser("unblock")
    s.add_argument("kind", choices=KINDS)
    s.add_argument("value")
    s = sub.add_parser("blocks")
    s.add_argument("kind", nargs="?", choices=KINDS)
    sub.add_parser("sweep")
    s = sub.add_parser("ui", help="web control panel")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8090)
    s.add_argument("--allow-restart", action="store_true", help="let the panel run systemctl restart scamstop")
    s.add_argument("--tls", choices=["off", "auto"], default="off", help="auto: HTTPS with a self-signed certificate")
    s.add_argument("--tls-cert", default=None)
    s.add_argument("--tls-key", default=None)
    s = sub.add_parser("syscheck", help="find the phone system on this server and check everything ScamStop needs")
    s.add_argument("--write-config", action="store_true", help="save the detected settings to the config")
    s = sub.add_parser("smart-train", help="retrain the smart check with your own labeled calls")
    s.add_argument("--labels", action="append", help="labels.jsonl from the panel, or TSV label<TAB>text; repeatable")
    s.add_argument("--out", default=None)
    s.add_argument("--samples", type=int, default=2500, help="generated windows per class")
    s.add_argument("--weight", type=int, default=3, help="how many times each real labeled call counts")
    s = sub.add_parser("smart-eval", help="precision/recall of the smart check on labeled calls")
    s.add_argument("file")
    s.add_argument("--model", default=None)
    s = sub.add_parser("download-model", help="fetch the speech model from a URL you host")
    s.add_argument("--dir", default=None)
    s.add_argument("--url", default=None, help="the model .tar.bz2 archive (defaults to asr.model_url)")
    sub.add_parser("feed-sync", help="share and pull the threat feed once")
    s = sub.add_parser("feed-server", help="host a shared threat feed")
    s.add_argument("--db", default="/var/lib/scamstop-feed/feed.db")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8095)
    s.add_argument("--min-networks", type=int, default=2, help="distinct /24s that must report an indicator")
    s.add_argument("--ttl-days", type=int, default=14)
    s.add_argument("--trust-proxy", action="store_true", help="read client IP from X-Forwarded-For")
    s = sub.add_parser("feed-admin", help="manage a feed server's installs and indicators")
    s.add_argument("--db", default="/var/lib/scamstop-feed/feed.db")
    s.add_argument("action", choices=["installs", "trust", "untrust", "ban", "unban", "allow", "unallow", "delete"])
    s.add_argument("args", nargs="*")
    a = p.parse_args(argv)
    if a.config is None and (a.cmd in ("ui", "syscheck") or os.path.exists(cfgmod.DEFAULT_PATH)):
        a.config = cfgmod.DEFAULT_PATH
    cfg = cfgmod.load(a.config)
    fn = {"run": cmd_run, "test-rules": cmd_test_rules, "scan": cmd_scan, "scan-audio": cmd_scan_audio,
          "ui": cmd_ui, "syscheck": cmd_syscheck, "download-model": cmd_download_model, "smart-train": cmd_smart_train, "smart-eval": cmd_smart_eval, "feed-sync": cmd_feed_sync, "feed-server": cmd_feed_server, "feed-admin": cmd_feed_admin, "block": cmd_block, "unblock": cmd_unblock, "blocks": cmd_blocks, "sweep": cmd_sweep}[a.cmd]
    sys.exit(fn(cfg, a))


if __name__ == "__main__":
    main()
