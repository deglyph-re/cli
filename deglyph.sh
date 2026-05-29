#!/usr/bin/env bash
# deglyph quick launcher — Author: Alex Spataru | GPLv3
#
# Bootstraps an isolated venv (first run only), installs requirements, and
# launches deglyph. Pass any deglyph arguments straight through:
#
#   ./deglyph.sh /path/to/library.dll
#   ./deglyph.sh lib.so --arch arm64
#   ./deglyph.sh lib.dll --analyze SetRfPower
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/.venv"
PY="${PYTHON:-python3}"

if [[ ! -x "$VENV/bin/python" ]]; then
    echo "deglyph: creating virtual environment…" >&2
    "$PY" -m venv "$VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip
    # The Anthropic SDK ships as a runtime dependency, so the assistant is
    # usable on first launch.
    "$VENV/bin/pip" install --quiet -e "$HERE"
fi

exec "$VENV/bin/python" -m deglyph.cli "$@"
