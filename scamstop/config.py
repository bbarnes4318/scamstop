"""Config loading with defaults. Every key in config.example.yaml is documented there."""
from __future__ import annotations

import copy
from pathlib import Path

import yaml

DEFAULTS: dict = {
    "dry_run": True,
    "redis": {"url": "redis://127.0.0.1:6379/0", "prefix": "sbc:",
              "customer_key": "sbc:cust:{ip}", "customer_cache_s": 60},
    "platform": {"type": None},  # opensips | kamailio | asterisk | freeswitch (None = proxy.type)
    "proxy": {"type": "opensips", "url": None, "fifo": "/run/opensips/opensips_fifo", "reply_dir": "/tmp"},
    "asterisk": {"url": "http://127.0.0.1:8088", "user": "scamstop", "password": "", "app": "scamstop",
                 "external_regex": "^(PJSIP|SIP|IAX2|DAHDI)/", "sounds_dir": "/var/lib/asterisk/sounds/en",
                 "media_host": "127.0.0.1"},
    "freeswitch": {"host": "127.0.0.1", "port": 8021, "password": "ClueCon",
                   "external_regex": "^sofia/(gateway|external)/", "record_dir": "/dev/shm/scamstop",
                   "victim_channel": "left"},
    "gate": {"enabled": True,
             # SIP 603+ for analytics-based blocks (FCC 47 CFR 64.1200(k)(9)): where wrongly blocked callers
             # ask for an unblock (at least one), and where this network sits in the call path (LN/TN/LPN/RPN/RLN)
             "redress_tel": "", "redress_url": "", "redress_email": "", "location": "TN"},
    # hosted mode: companies sign up in the portal and send calls through your SBC
    "hosted": {"enabled": False, "brand": "ScamStop", "sbc_address": "", "sbc_port": 5060, "sbc_transport": "UDP",
               "default_carrier": "", "default_carrier_label": "Our termination", "auto_approve": False,
               "signup_open": True, "support_email": ""},
    "status_file": "/var/lib/scamstop/status.json",
    "rtpengine": {"host": "127.0.0.1", "port": 22222},
    "monitor": {"poll_s": 1.5, "max_streams": 400, "exclude_ips": ["127.0.0.1"],
                "exclude_bind_suffix": [], "listen_victim": True},
    "asr": {"model_dir": "/opt/scamstop/models/sherpa-onnx-streaming-zipformer-en-2023-06-21",
            "workers": 6, "quiet_rms": 120, "queue_max": 5000, "model_url": None},
    "rules": {"packs": ["en_scams", "en_victim"], "disabled": [], "actions": {}, "window": 400},
    "campaigns": {"enabled": False},
    "centers": {"strategies": ["callid_host", "media_ip"], "media_ip_callid_regex": ".*",
                "strikes_to_block": 2, "strike_window_s": 86400, "block_ttl_s": 604800,
                "never_block_customer_ip": True},
    "evidence": {"kill_log": "/var/log/scamstop/kills.jsonl", "flag_log": "/var/log/scamstop/flags.jsonl",
                 "review_log": "/var/log/scamstop/review.jsonl", "watch_log": "/var/log/scamstop/watch.jsonl",
                 "transcript": "full", "watch_regex": None},
    "warn": {"mode": "warn_then_hangup", "file": "/var/lib/scamstop/warning.wav", "play_to": "victim",
             "on_flag": False, "max_wait_s": 25},
    "feed": {"enabled": True, "url": "https://scamstop.pvnvoice.com", "name": "", "share": True, "share_manual": True, "apply": True,
             "apply_kinds": ["media", "host", "tag", "cli"], "min_reporters": 1, "block_ttl_s": 259200,
             "sync_s": 300, "never_apply": [], "state_file": "/var/lib/scamstop/feed.json"},
    "smart": {"enabled": True, "mode": "flag", "threshold": 0.85, "kill_threshold": 0.97,
              "min_words": 25, "every_words": 12, "window_words": 75, "model": None,
              "labels_file": "/var/lib/scamstop/labels.jsonl",
              "proven": {"min_reviewed": 50, "min_precision": 0.95},
              "llm": {"enabled": False, "url": "http://127.0.0.1:11434/v1/chat/completions",
                      "model": "qwen2.5:3b-instruct", "api_key": "", "ask_above": 0.6, "min_confidence": 0.8,
                      "timeout_s": 6, "max_concurrent": 4}},
    "metrics": {"textfile": "/var/lib/scamstop/metrics.prom"},
}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


DEFAULT_PATH = "/etc/scamstop/config.yaml"


def load(path: str | None) -> dict:
    user = yaml.safe_load(Path(path).read_text()) if path and Path(path).exists() else {}
    return _merge(DEFAULTS, user or {})
