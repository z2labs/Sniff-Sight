"""802.15.4 / Thread sniffer pipeline.

One process owns the radio port: spinel_sniffer.py (pyspinel based, run with
the spinel venv) writes a pcap stream in IEEE 802.15.4 TAP format (DLT 283:
FCS type, RSS, LQI and channel TLVs, recomputed FCS) to stdout and can hop
channels; "CHANNEL n" lines on its stderr announce the current channel. A reader thread splits it into records and tees each to
  * rolling pcap files in the captures directory,
  * tshark (stdin) for decoding with the user's Wireshark prefs/keys,
  * optionally Wireshark live through a Windows named pipe.
Decoded packets are handed to a callback (called from a worker thread).

All child processes are put into a Windows Job object with
KILL_ON_JOB_CLOSE, so they die with this process even if it is killed.
"""

from __future__ import annotations

import collections
import ctypes
import os
import queue
import struct
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from typing import Callable, Optional

from .per import parse_payload
from .paths import DEFAULT_CAPTURES, DEFAULT_SPINEL_VENV

DEFAULT_VENV = DEFAULT_SPINEL_VENV
WIRESHARK_DIR = r"C:\Program Files\Wireshark"

TSHARK_FIELDS = [
    "frame.time_epoch", "wpan.src16", "wpan.src64", "wpan.dst16", "wpan.dst64",
    "wpan.dst_pan", "wpan.src_pan", "wpan.frame_type", "wpan-tap.rss", "wpan-tap.lqi", "wpan-tap.ch_num",
    "frame.len", "wpan.fcs_ok", "wpan.seq_no", "mle.cmd", "_ws.col.Protocol", "_ws.col.Info",
    "udp.dstport", "data.data", "wpan.aux_sec.frame_counter", "wpan-tap.length",   # data.data: decrypted UDP payload (PER test packets, see per.py)
]
FRAME_TYPES = {0: "Beacon", 1: "Data", 2: "Ack", 3: "Command", 5: "Multipurpose", 6: "Fragment", 7: "Extended"}


def channel_mhz(ch: int) -> float:
    return 2405.0 + 5.0 * (ch - 11)


# ---------------------------------------------------------------- Windows job object
class _JobObject:
    def __init__(self):
        self.handle = None
        if os.name != "nt":
            return
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k32 = k32
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        h = k32.CreateJobObjectW(None, None)
        if not h:
            return

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in ("r", "w", "o", "rb", "wb", "ob")]

        class EXT(ctypes.Structure):
            _fields_ = [("Basic", BASIC), ("Io", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        info = EXT()
        info.Basic.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if k32.SetInformationJobObject(h, 9, ctypes.byref(info), ctypes.sizeof(info)):
            self.handle = h

    def add(self, proc: subprocess.Popen):
        if not self.handle:
            return
        try:
            self.k32.AssignProcessToJobObject(wintypes.HANDLE(self.handle), wintypes.HANDLE(int(proc._handle)))
        except Exception:
            pass


JOB = _JobObject()


# ---------------------------------------------------------------- Windows named pipe for Wireshark
class _PipeFeeder(threading.Thread):
    """Serves pcap to Wireshark over \\\\.\\pipe\\<name>. Reconnects if Wireshark restarts."""

    def __init__(self, name: str, header: Callable[[], Optional[bytes]]):
        super().__init__(daemon=True, name="wireshark-pipe")
        self.path = r"\\.\pipe" + "\\" + name
        self.header = header
        self.q: "queue.Queue[bytes]" = queue.Queue(maxsize=10000)
        self.stop_evt = threading.Event()
        self.connected = False
        self.packets = 0
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k32.CreateNamedPipeW.restype = wintypes.HANDLE
        self.h = None

    def put(self, rec: bytes):
        if self.connected:
            try:
                self.q.put_nowait(rec)
            except queue.Full:
                pass

    def _write(self, data: bytes) -> bool:
        n = wintypes.DWORD()
        return bool(self.k32.WriteFile(wintypes.HANDLE(self.h), data, len(data), ctypes.byref(n), None))

    def run(self):
        INVALID = wintypes.HANDLE(-1).value
        while not self.stop_evt.is_set():
            # PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE | PIPE_WAIT
            self.h = self.k32.CreateNamedPipeW(self.path, 0x2, 0x0, 1, 1 << 20, 1 << 16, 0, None)
            if not self.h or self.h == INVALID:
                time.sleep(1)
                continue
            ok = self.k32.ConnectNamedPipe(wintypes.HANDLE(self.h), None) or ctypes.get_last_error() == 535
            if self.stop_evt.is_set():
                break
            if ok:
                while self.header() is None and not self.stop_evt.is_set():
                    time.sleep(0.1)
                self.connected = self._write(self.header() or b"")
                while self.connected and not self.stop_evt.is_set():
                    try:
                        rec = self.q.get(timeout=0.5)
                    except queue.Empty:
                        continue
                    if not self._write(rec):
                        self.connected = False
                    else:
                        self.packets += 1
            self.connected = False
            self.k32.DisconnectNamedPipe(wintypes.HANDLE(self.h))
            self.k32.CloseHandle(wintypes.HANDLE(self.h))
            self.h = None

    def stop(self):
        self.stop_evt.set()
        try:  # unblock ConnectNamedPipe by connecting once
            with open(self.path, "rb"):
                pass
        except Exception:
            pass


# ---------------------------------------------------------------- the sniffer pipeline
class ThreadSniffer:
    def __init__(self, port: str = "COM16", baud: int = 460800, channel: int = 15,
                 hop: Optional[list] = None, dwell: float = 2.0,
                 on_channel: Optional[Callable[[int], None]] = None,
                 captures_dir: str = DEFAULT_CAPTURES,
                 venv: str = DEFAULT_VENV, wireshark: bool = True, rotate_mb: float = 50.0,
                 rotate_s: float = 3600.0, pipe_name: str = "sniffsight_thread",
                 on_packet: Optional[Callable[[dict], None]] = None,
                 on_log: Optional[Callable[[str], None]] = None):
        self.port, self.baud, self.channel = port, baud, channel
        self.hop = [int(c) for c in hop] if hop else None
        self.dwell = dwell
        self.current_channel = self.hop[0] if self.hop else channel
        self.on_channel = on_channel or (lambda ch: None)
        self.captures_dir, self.venv = captures_dir, venv
        self.want_wireshark, self.rotate_bytes, self.rotate_s = wireshark, int(rotate_mb * 1e6), rotate_s
        self.pipe_name = pipe_name
        self.on_packet = on_packet or (lambda p: None)
        self.on_log = on_log or (lambda s: print("[sniffer]", s, file=sys.stderr))
        self.procs: dict[str, subprocess.Popen] = {}
        self.pcap_header: Optional[bytes] = None
        self.stats = {"records": 0, "decoded": 0, "bytes": 0, "file": None, "wireshark_packets": 0}
        self.pipe: Optional[_PipeFeeder] = None
        self._file = None
        self._file_t0 = 0.0
        self._running = False
        self._threads: list[threading.Thread] = []
        self._frames: "collections.deque" = collections.deque(maxlen=10000)  # (pcap file, frame no.)
        self._frame_no = 0

    # ---------------------------------------------------------- lifecycle
    def start(self):
        os.makedirs(self.captures_dir, exist_ok=True)
        self._running = True
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        py = os.path.join(self.venv, "Scripts", "python.exe")
        sn = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spinel_sniffer.py")
        chans = ",".join(str(c) for c in (self.hop or [self.channel]))
        cmd = [py, "-u", sn, "-u", self.port, "-b", str(self.baud), "--channels", chans, "--dwell", str(self.dwell)]
        self.on_log("start: " + " ".join(cmd))
        self.procs["sniffer"] = p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                     stdin=subprocess.DEVNULL, creationflags=flags)
        JOB.add(p)
        tshark = os.path.join(WIRESHARK_DIR, "tshark.exe")
        tcmd = [tshark, "-l", "-n", "-r", "-", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
                "-E", "quote=n"]
        for f in TSHARK_FIELDS:
            tcmd += ["-e", f]
        self.procs["tshark"] = t = subprocess.Popen(tcmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                    stderr=subprocess.PIPE, creationflags=flags, bufsize=0)
        JOB.add(t)
        if self.want_wireshark and os.name == "nt":
            self.pipe = _PipeFeeder(self.pipe_name, lambda: self.pcap_header)
            self.pipe.start()
            time.sleep(0.2)
            ws = os.path.join(WIRESHARK_DIR, "Wireshark.exe")
            self.procs["wireshark"] = w = subprocess.Popen([ws, "-k", "-i", self.pipe.path],
                                                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                                           stderr=subprocess.DEVNULL)
            JOB.add(w)
        for target, name in ((self._read_sniffer, "sniffer-read"), (self._read_tshark, "tshark-read"),
                             (self._log_stderr("sniffer"), "sniffer-err"), (self._log_stderr("tshark"), "tshark-err")):
            th = threading.Thread(target=target, daemon=True, name=name)
            th.start()
            self._threads.append(th)

    def stop(self):
        self._running = False
        for name in ("sniffer", "tshark", "wireshark"):
            p = self.procs.get(name)
            if p and p.poll() is None:
                try:
                    if name == "tshark" and p.stdin:
                        p.stdin.close()
                    p.terminate()
                    p.wait(3)
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass
        if self.pipe:
            self.pipe.stop()
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None
        self.on_log("stopped")

    def status(self) -> dict:
        s = dict(self.stats)
        s.update({"port": self.port, "channel": self.current_channel, "channel_mhz": channel_mhz(self.current_channel),
                  "hop": self.hop, "dwell": self.dwell,
                  "running": {k: p.poll() is None for k, p in self.procs.items()},
                  "wireshark_connected": bool(self.pipe and self.pipe.connected)})
        if self.pipe:
            s["wireshark_packets"] = self.pipe.packets
        return s

    # ---------------------------------------------------------- workers
    def _log_stderr(self, name):
        def run():
            p = self.procs[name]
            for line in iter(p.stderr.readline, b""):
                txt = line.decode(errors="replace").rstrip()
                if name == "sniffer" and txt.startswith("CHANNEL "):
                    try:
                        self.current_channel = int(txt.split()[1])
                        self.on_channel(self.current_channel)
                    except ValueError:
                        pass
                    continue
                if txt:
                    self.on_log(f"{name}: {txt}")
        return run

    def _rotate(self):
        if self._file:
            self._file.close()
        tag = "hop" if self.hop else "ch%d" % self.channel
        fn = os.path.join(self.captures_dir, time.strftime("thread_%s_%%Y%%m%%d_%%H%%M%%S.pcap" % tag))
        self._file = open(fn, "wb")
        self._file.write(self.pcap_header)
        self._file_t0 = time.time()
        self._frame_no = 0
        self.stats["file"] = fn
        self.on_log("capture file " + fn)

    def _read_exact(self, f, n) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            chunk = f.read(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _read_sniffer(self):
        p = self.procs["sniffer"]
        out = p.stdout
        hdr = self._read_exact(out, 24)
        if not hdr:
            self.on_log("sniffer ended before sending a pcap header")
            return
        endian = "<" if hdr[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        self.pcap_header = hdr
        tsh = self.procs["tshark"].stdin
        try:
            tsh.write(hdr)
            tsh.flush()
        except Exception:
            pass
        self._rotate()
        while self._running:
            rh = self._read_exact(out, 16)
            if not rh:
                break
            incl = struct.unpack(endian + "IIII", rh)[2]
            body = self._read_exact(out, incl)
            if body is None:
                break
            rec = rh + body
            self.stats["records"] += 1
            self.stats["bytes"] += len(rec)
            try:
                if self._file.tell() + len(rec) > self.rotate_bytes or time.time() - self._file_t0 > self.rotate_s:
                    self._rotate()
                self._file.write(rec)
                self._file.flush()
                self._frame_no += 1
                self._frames.append((self.stats["file"], self._frame_no))
            except Exception as e:
                self.on_log(f"file write error: {e}")
            try:
                tsh.write(rec)
                tsh.flush()
            except Exception:
                pass
            if self.pipe:
                self.pipe.put(rec)
        self.on_log(f"sniffer stream ended (exit {p.poll()})")

    def _read_tshark(self):
        p = self.procs["tshark"]
        for line in iter(p.stdout.readline, b""):
            parts = line.decode(errors="replace").rstrip("\r\n").split("\t")
            if len(parts) < len(TSHARK_FIELDS):
                parts += [""] * (len(TSHARK_FIELDS) - len(parts))
            d = dict(zip(TSHARK_FIELDS, parts))
            self.stats["decoded"] += 1
            pkt = self._packet(d)
            try:
                fn, no = self._frames.popleft()
            except IndexError:
                fn, no = self.stats.get("file"), None
            pkt["pcap_file"] = os.path.basename(fn) if fn else None
            pkt["frame"] = no
            pkt["id"] = f"{os.path.splitext(pkt['pcap_file'])[0]}_{no}" if fn and no else None
            self.on_packet(pkt)

    def _packet(self, d: dict) -> dict:
        def num(v, base=10):
            try:
                return int(v, base)
            except Exception:
                return None
        def fnum(v):
            try:
                return round(float(v), 1)
            except Exception:
                return None
        ch = num(d["wpan-tap.ch_num"]) or self.current_channel
        ft = num(d["wpan.frame_type"], 0) if d["wpan.frame_type"] else None
        src = d["wpan.src64"] or d["wpan.src16"] or ""
        dst = d["wpan.dst64"] or d["wpan.dst16"] or ""
        proto = d["_ws.col.Protocol"]
        info = d["_ws.col.Info"]
        kind = FRAME_TYPES.get(ft, "?") if ft is not None else proto
        if proto == "MLE" or d["mle.cmd"]:
            kind = "MLE " + (info.split(",")[0].strip() if info else "")
        elif proto and proto not in ("IEEE 802.15.4",):
            kind = f"{proto} ({FRAME_TYPES.get(ft, '?')})"
        try:
            t = float(d["frame.time_epoch"])
        except Exception:
            t = time.time()
        fcs = d["wpan.fcs_ok"]
        per = parse_payload(d.get("data.data", ""))
        fc = num(d.get("wpan.aux_sec.frame_counter", ""))
        tapl, flen = num(d.get("wpan-tap.length", "")), num(d["frame.len"])
        psdu = flen - tapl if (flen is not None and tapl is not None and flen > tapl) else None
        # O-QPSK 250 kb/s: SHR 5 B (160 us) + PHR 1 B + PSDU, 32 us per byte
        air_ms = round((6 + psdu) * 0.032, 3) if psdu is not None else None
        return {"per": per, "fc": fc, "psdu_len": psdu, "airtime_ms": air_ms, "fc_stream": ("mle" if (proto == "MLE" or d["mle.cmd"]) else "mac") if fc is not None else None,
            "type": "pkt", "t": t, "src": src, "dst": dst,
            "pan": d["wpan.dst_pan"] or d["wpan.src_pan"], "kind": kind, "proto": proto, "info": info,
            "rssi": fnum(d["wpan-tap.rss"]), "lqi": num(d["wpan-tap.lqi"]), "len": num(d["frame.len"]),
            # the FCS is recomputed by spinel_sniffer.py, so this is always True:
            # frames reach the host only if the RCP accepted them.
            "fcs_ok": None if fcs == "" else fcs in ("1", "True", "true"), "seq": num(d["wpan.seq_no"]),
            "channel": ch, "freq_mhz": channel_mhz(ch),
        }
