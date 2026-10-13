#!/usr/bin/env bash
# One-click launcher: ./scripts/start.sh [--demo] [sniff_sight options...]
set -e
cd "$(dirname "$0")/.."
[ -x .venv/bin/python ] || ./scripts/install.sh
exec .venv/bin/python -m sniff_sight "$@"