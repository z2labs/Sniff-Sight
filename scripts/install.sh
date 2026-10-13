#!/usr/bin/env bash
# Sniff-Sight installer for Linux (apt) and macOS (brew): tshark, Python 3.11+, .venv, pip install -e .
#   ./scripts/install.sh [--with-spinel] [--no-wireshark]
set -euo pipefail
cd "$(dirname "$0")/.."
WITH_SPINEL=0; WIRESHARK=1
for a in "$@"; do
  case "$a" in
    --with-spinel) WITH_SPINEL=1 ;;
    --no-wireshark) WIRESHARK=0 ;;
    *) echo "unknown option $a"; exit 2 ;;
  esac
done

if command -v apt-get >/dev/null; then
  sudo apt-get update
  pkgs="python3 python3-venv python3-pip"
  [ "$WIRESHARK" = 1 ] && pkgs="$pkgs tshark"
  sudo apt-get install -y $pkgs
  echo "Serial ports: sudo usermod -aG dialout \$USER  (log out/in afterwards)"
elif command -v brew >/dev/null; then
  brew install python@3.12
  [ "$WIRESHARK" = 1 ] && brew install --cask wireshark
else
  echo "No apt-get or brew: install Python 3.11+ and tshark manually." >&2
fi

PY=""
for c in python3.13 python3.12 python3.11 python3; do
  if command -v "$c" >/dev/null && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then PY="$c"; break; fi
done
[ -n "$PY" ] || { echo "Python 3.11+ not found" >&2; exit 1; }
echo "Python: $PY"

[ -x .venv/bin/python ] || "$PY" -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .

if [ "$WITH_SPINEL" = 1 ]; then
  SV="$(cd .. && pwd)/spinel_venv"
  [ -x "$SV/bin/python" ] || "$PY" -m venv "$SV"
  "$SV/bin/python" -m pip install pyspinel pyserial
  echo "RCP sniffer venv: $SV (override with SNIFF_SPINEL_VENV)"
fi

echo "Optional: remote access via Tailscale (https://tailscale.com/download); always use --auth-file with funnel."
echo
echo "Done. Try:  ./scripts/start.sh --demo"