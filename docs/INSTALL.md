# Installing Sniff-Sight

Sniff-Sight is a Python 3.11+ app with a browser UI. The installers below set up a local
virtual environment (`.venv`) in the repository folder; nothing is installed system-wide
except Wireshark/tshark and Python themselves.

## Windows (PowerShell)

```powershell
git clone https://github.com/z2labs/Sniff-Sight.git
cd Sniff-Sight
powershell -ExecutionPolicy Bypass -File scripts\install.ps1          # add -NoWireshark / -WithSpinel as needed
scripts\start.bat --demo                                               # try it without hardware
scripts\start.bat --esp-port COM7 --thread-port COM16 --channel 15     # with hardware
```

`install.ps1` uses `winget` to install **Wireshark** (for `tshark` decoding and live view) and
**Python 3.11+** if missing, creates `.venv`, runs `pip install -e .` and, with `-WithSpinel`,
creates the separate `../spinel_venv` with `pyspinel` for the OpenThread RCP sniffer.

## Linux / macOS

```bash
git clone https://github.com/z2labs/Sniff-Sight.git && cd Sniff-Sight
./scripts/install.sh            # apt (Debian/Ubuntu) or brew (macOS); --with-spinel for the RCP venv
./scripts/start.sh --demo
./scripts/start.sh --esp-port /dev/ttyACM0 --thread-port /dev/ttyACM1 --channel 15
```

On Linux add yourself to the `dialout` group (serial ports) and, if tshark asks, to `wireshark`.
Note: live Wireshark (named pipe) is currently Windows-only; pcap files and tshark decoding work everywhere.

## Manual install

```bash
python3 -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
python -m venv ../spinel_venv && ../spinel_venv/bin/pip install pyspinel pyserial   # RCP sniffer
python -m sniff_sight --demo
```

## Demo mode (no hardware)

`--demo` (or `scripts/start.* --demo`) serves the normal dashboard and replays a bundled
~2.5 MB sample: a 41 s lab capture of an OpenThread test network on channel 15 with ~300
packets, their packet/RF pairing results, 20 per-packet spectrum snippets and ~4 000
classified RF bursts (Wi-Fi, BLE, 802.15.4, unknown). The replay runs in the browser
(`sniff_sight/demo/player.js` replaces the dashboard's WebSocket and API calls); the
full-span spectrum is re-synthesised from the burst log. No serial port is opened.
Open <http://127.0.0.1:8000> (or the `--http-port` you chose).

The same player powers the static page in `docs/demo/` (GitHub Pages: *Settings > Pages >
Deploy from branch > main, /docs*, then open `/demo/`). Rebuild it after UI changes with
`python tools/demo/build_pages.py`; rebuild the sample from your own capture with
`python tools/demo/build_demo_sample.py --captures <captures dir> --session <snippet prefix>`
(addresses are replaced by synthetic ones, times are shifted to zero).

## Optional: remote access with Tailscale

Install Tailscale (`winget install Tailscale.Tailscale`, `brew install tailscale`, or
<https://tailscale.com/download>) and see *Remote access* in the README. Always use
`--auth-file` before exposing the dashboard with `tailscale funnel`.