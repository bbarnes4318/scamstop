"""Speech model. The installer ships it; this module can also fetch the archive
from a URL you host (asr.model_url), e.g. for Docker builds.

The archive is streamed and only the files ScamStop needs are extracted, so no
500 MB temp file is ever written. Progress goes to a callback for the panel.
"""
from __future__ import annotations

import os
import tarfile
import urllib.request
from pathlib import Path

MODEL_NAME = "sherpa-onnx-streaming-zipformer-en-2023-06-21"
MODEL_URL = None  # the installer ships the model; set asr.model_url only to fetch it from your own server
NEEDED = ("tokens.txt", "encoder-epoch-99-avg-1.int8.onnx", "decoder-epoch-99-avg-1.onnx",
          "joiner-epoch-99-avg-1.int8.onnx")


def present(model_dir: str) -> bool:
    d = Path(model_dir)
    return all((d / f).exists() for f in NEEDED)


class _Counting:
    def __init__(self, f, total, cb):
        self.f, self.total, self.cb, self.n, self.last = f, total, cb, 0, -1

    def read(self, size=-1):
        b = self.f.read(size)
        self.n += len(b)
        pct = int(self.n * 100 / self.total) if self.total else 0
        if self.cb and pct != self.last:
            self.last = pct
            self.cb(pct)
        return b


def ensure(model_dir: str, url: str | None = MODEL_URL, progress=None) -> bool:
    """Download the model into model_dir if it isn't there. Returns True if it downloaded."""
    if present(model_dir):
        return False
    if not url:
        raise RuntimeError(f"the speech model is missing from {model_dir}. Run the ScamStop installer again "
                           "(it includes the model), or set asr.model_url to a copy on your own server")
    d = Path(model_dir)
    d.mkdir(parents=True, exist_ok=True)
    tmp = d.with_name(d.name + ".partial")
    tmp.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "scamstop"})
    with urllib.request.urlopen(req, timeout=60) as r:
        total = int(r.headers.get("Content-Length") or 0)
        with tarfile.open(fileobj=_Counting(r, total, progress), mode="r|bz2") as tar:
            for m in tar:
                name = os.path.basename(m.name)
                if m.isfile() and name in NEEDED:
                    src = tar.extractfile(m)
                    with open(tmp / name, "wb") as out:
                        while chunk := src.read(1 << 20):
                            out.write(chunk)
    missing = [f for f in NEEDED if not (tmp / f).exists()]
    if missing:
        raise RuntimeError(f"model archive is missing {missing}")
    for f in NEEDED:
        os.replace(tmp / f, d / f)
    tmp.rmdir()
    return True
