"""Sniff-Sight launcher: python -m sniff_sight [options]

Starts everything in one process:
  * ESP32-S3 ESP-SDR spectrum on --esp-port (default COM7) (SPEC stream, z2-web-sdr setup)
  * 802.15.4 / Thread sniffer on --thread-port (default COM16) (spinel_sniffer.py owns the port and
    writes IEEE 802.15.4 TAP pcap; teed to rolling pcap files, tshark for
    decoding and, optionally, Wireshark live via a named pipe); optional
    channel hopping
  * the web dashboard (http://127.0.0.1:8000)
--demo replays a bundled sample capture without any hardware.
Ctrl+C: graceful shutdown (stop SPEC, restore BANDWIDTH 20 / DC 1, close
ports, end child processes). A second Ctrl+C, or the hard timeout, forces the
exit after a synchronous device reset and killing the children.
"""

from .paths import DEFAULT_CAPTURES
import argparse
import os
import sys
import threading


def _channels(spec: str):
    if spec in ("", "all"):
        return list(range(11, 27))
    out = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out += list(range(int(a), int(b) + 1))
        elif part.strip():
            out.append(int(part))
    if not out or any(c < 11 or c > 26 for c in out):
        raise argparse.ArgumentTypeError("channels must be 11..26")
    return out


def main():
    ap = argparse.ArgumentParser(prog="python -m sniff_sight", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--also-localhost", action="store_true",
                    help="additionally listen on 127.0.0.1 (needed for 'tailscale funnel/serve' on Windows)")
    ap.add_argument("--auth", default=None, metavar="USER:PASS", help="require login (also env SNIFF_AUTH)")
    ap.add_argument("--auth-file", default=None, help="file containing USER:PASS (keeps the password off the command line)")
    ap.add_argument("--http-port", type=int, default=8000)
    ap.add_argument("--esp-port", default="COM7")
    ap.add_argument("--no-esp", action="store_true", help="do not open the ESP32-S3 SDR")
    ap.add_argument("--freq", type=float, default=None, help="SDR centre MHz (default 2437)")
    ap.add_argument("--span", type=int, choices=[16_000_000, 40_000_000, 80_000_000], default=None)
    ap.add_argument("--bins", type=int, choices=[256, 512, 1024, 2048, 4096], default=None,
                    help="FFT bins (4096 = experimental, needs firmware support)")
    ap.add_argument("--gain", type=int, default=None, help="manual gain 0..82 (default 60)")
    ap.add_argument("--thread-port", default="COM16")
    ap.add_argument("--thread-baud", type=int, default=460800)
    ap.add_argument("--channel", type=int, default=15, help="802.15.4 channel 11..26 (no hopping)")
    ap.add_argument("--hop", nargs="?", const="all", default=None, metavar="CHANNELS",
                    help="hop channels: --hop (11-26), --hop 11,15,20,25 or --hop 11-14")
    ap.add_argument("--dwell", type=float, default=2.0, help="seconds per channel when hopping (default 2)")
    ap.add_argument("--no-thread", action="store_true", help="do not start the 802.15.4 sniffer")
    ap.add_argument("--no-wireshark", action="store_true", help="do not open Wireshark live")
    ap.add_argument("--captures", default=DEFAULT_CAPTURES, help="output folder (default: ../captures next to the repo, env SNIFF_CAPTURES)")
    ap.add_argument("--demo", action="store_true",
                    help="replay the bundled sample capture in the dashboard (no hardware, no serial ports)")
    ap.add_argument("--hard-timeout", type=float, default=15.0,
                    help="seconds after Ctrl+C before the exit is forced (default 15)")
    a = ap.parse_args()

    env = {
        "SNIFF_PORT": a.esp_port, "SNIFF_THREAD_PORT": a.thread_port,
        "SNIFF_THREAD_BAUD": str(a.thread_baud), "SNIFF_THREAD_CHANNEL": str(a.channel),
        "SNIFF_THREAD": "0" if a.no_thread else "1", "SNIFF_WIRESHARK": "0" if a.no_wireshark else "1",
        "SNIFF_CAPTURES": a.captures, "SNIFF_DWELL": str(a.dwell),
        "SNIFF_HOP": ",".join(map(str, _channels(a.hop))) if a.hop is not None else "",
    }
    if a.no_esp:
        env["SNIFF_NO_SERIAL"] = "1"
    if a.demo:   # browser-side replay: no serial ports, no sniffer, no Wireshark, scratch captures dir
        import tempfile
        env.update(SNIFF_DEMO="1", SNIFF_NO_SERIAL="1", SNIFF_THREAD="0", SNIFF_WIRESHARK="0",
                   SNIFF_CAPTURES=os.path.join(tempfile.gettempdir(), "sniff_sight_demo"))
        print("[sniff-sight] demo mode: replaying the bundled sample (no hardware)", flush=True)
    for k, v in (("SNIFF_FREQ_MHZ", a.freq), ("SNIFF_SPAN", a.span), ("SNIFF_BINS", a.bins), ("SNIFF_GAIN", a.gain)):
        if v is not None:
            env[k] = str(v)
    if a.auth_file:
        with open(a.auth_file, encoding="utf-8-sig") as fh:
            env["SNIFF_AUTH"] = fh.read().strip()
    elif a.auth:
        env["SNIFF_AUTH"] = a.auth
    os.environ.update(env)

    import uvicorn
    from . import web

    force_lock = threading.Lock()

    def force(reason: str):
        if not force_lock.acquire(blocking=False):
            return
        print(f"[sniff-sight] {reason}: forcing exit", flush=True)
        try:
            web.emergency_cleanup()
        finally:
            os._exit(1)

    class Server(uvicorn.Server):
        def handle_exit(self, sig, frame):
            if self.should_exit:   # second Ctrl+C
                threading.Thread(target=force, args=("second Ctrl+C",), daemon=True).start()
                return
            print(f"[sniff-sight] Ctrl+C: shutting down (Ctrl+C again to force; hard timeout {a.hard_timeout:g} s)", flush=True)
            t = threading.Timer(a.hard_timeout, force, args=(f"shutdown did not finish within {a.hard_timeout:g} s",))
            t.daemon = True
            t.start()
            super().handle_exit(sig, frame)

    print(f"[sniff-sight] dashboard: http://{a.host}:{a.http_port}  (Ctrl+C to stop)", flush=True)
    cfg = uvicorn.Config(web.app, host=a.host, port=a.http_port, log_level="warning")
    if a.also_localhost and a.host not in ("127.0.0.1", "0.0.0.0", "localhost"):
        import socket
        socks = []
        for h in (a.host, "127.0.0.1"):
            sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sk.bind((h, a.http_port))
            sk.set_inheritable(True)
            socks.append(sk)
        print(f"[sniff-sight] also on http://127.0.0.1:{a.http_port}", flush=True)
        Server(cfg).run(sockets=socks)
    else:
        Server(cfg).run()


if __name__ == "__main__":
    main()
