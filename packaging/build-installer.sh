#!/usr/bin/env bash
# Build the standalone installer: dist/scamstop-installer-<version>-linux-x86_64.run
#
# Needs: python3 with `build`, pip, uv (for the standalone Python), and the speech
# model files (downloaded once into packaging/cache/model if missing).
set -euo pipefail
cd "$(dirname "$0")/.."
VER=$(python3 -c "import re;print(re.search(r'version = \"([^\"]+)\"', open('pyproject.toml').read()).group(1))")
CACHE=packaging/cache
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$CACHE" dist "$STAGE/wheels" "$STAGE/model"

echo "== wheel"
rm -rf build dist/scamstop-*.whl
python3 -m build -q --wheel --outdir dist
cp dist/scamstop-"$VER"-py3-none-any.whl "$STAGE/wheels/"

echo "== dependency wheels (Linux x86_64, CPython 3.12, glibc 2.17+)"
pip download -q --dest "$STAGE/wheels" --only-binary=:all: --platform manylinux2014_x86_64 \
  --platform manylinux_2_17_x86_64 --python-version 3.12 --implementation cp \
  "numpy>=1.24,<2.3" "pyyaml>=6" "redis>=5" "sherpa-onnx>=1.10"

echo "== standalone Python 3.12"
if [ ! -d "$CACHE/python" ]; then
  rm -rf "$CACHE/pyinst"
  UV_PYTHON_INSTALL_DIR="$CACHE/pyinst" uv python install 3.12
  src=$(find "$CACHE/pyinst" -maxdepth 1 -type d -name 'cpython-3.12.*-linux-x86_64-gnu' | head -1)
  cp -a "$src" "$CACHE/python"
  rm -rf "$CACHE/pyinst"
  # trim what a server never needs
  rm -rf "$CACHE"/python/lib/python3.12/{test,idlelib,tkinter,turtledemo,lib2to3} "$CACHE"/python/lib/{tcl*,tk*,itcl*,thread*,libtcl*,libtk*} "$CACHE"/python/{include,share} "$CACHE"/python/lib/python3.12/config-3.12-*/*.a 2>/dev/null || true
  find "$CACHE/python" -name __pycache__ -prune -exec rm -rf {} +
fi
cp -a "$CACHE/python" "$STAGE/python"

echo "== speech model"
MODEL_DIR="$CACHE/model"
if [ ! -f "$MODEL_DIR/tokens.txt" ]; then
  # build machine only: the model's publisher (k2-fsa / sherpa-onnx, Apache-2.0)
  SRC_URL="${MODEL_SOURCE_URL:-https://github.com/k2-fsa/sherpa-onnx/releases/download/asr-models/sherpa-onnx-streaming-zipformer-en-2023-06-21.tar.bz2}"
  PYTHONPATH=. python3 -c "from scamstop import model; model.ensure('$MODEL_DIR', '$SRC_URL')"
fi
cp "$MODEL_DIR"/* "$STAGE/model/"

cp install.sh "$STAGE/install.sh"
echo "$VER" > "$STAGE/VERSION"

OUT="dist/scamstop-installer-$VER-linux-x86_64.run"
echo "== packing $OUT"
cat packaging/installer-header.sh > "$OUT"
tar czf - -C "$STAGE" . >> "$OUT"
chmod +x "$OUT"
ls -la "$OUT"
