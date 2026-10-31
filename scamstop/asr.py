"""Local streaming speech recognition (sherpa-onnx). Free, offline, no per-minute fees."""
from __future__ import annotations

from pathlib import Path


def make_recognizer(model_dir: str, threads: int = 1):
    import sherpa_onnx  # pip install sherpa-onnx

    d = Path(model_dir)

    def pick(stem: str) -> str:
        for name in (f"{stem}-epoch-99-avg-1.int8.onnx", f"{stem}-epoch-99-avg-1.onnx"):
            if (d / name).exists():
                return str(d / name)
        found = sorted(d.glob(f"{stem}*.int8.onnx")) or sorted(d.glob(f"{stem}*.onnx"))
        if not found:
            raise FileNotFoundError(f"no {stem}*.onnx in {d}")
        return str(found[0])

    return sherpa_onnx.OnlineRecognizer.from_transducer(
        tokens=str(d / "tokens.txt"), encoder=pick("encoder"),
        decoder=pick("decoder"), joiner=pick("joiner"),
        num_threads=threads, sample_rate=16000, feature_dim=80, enable_endpoint_detection=True)
