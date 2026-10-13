"""Sniff-Sight Thread test-traffic driver (ESP-IDF ot_cli over USB-serial-JTAG).

Drives one (leader, COM8) or two (leader + node) ESP32-C6 ot_cli consoles through a
timed schedule and logs every command (host timestamp) plus every console line to a CSV
in the captures directory, for comparison with pcap packets / RF snippets.

Does NOT touch the running Sniff-Sight launcher.  Ports are opened with DTR/RTS low so
the C6 is NOT reset on open (default pyserial open resets it!).

Examples:
  python tools\\traffic\\traffic_test.py --phases state,burst                 # quick smoke
  python tools\\traffic\\traffic_test.py --port2 COM9 --channels 15             # full plan, 1 channel
  python tools\\traffic\\traffic_test.py --port2 COM9 --channels 15,20,25       # + channel steps
  python tools\\traffic\\traffic_test.py --dry-run --channels 15,20             # print schedule only
"""
import argparse, csv, datetime as dt, os, re, sys, threading, time

try:
    import serial
except ImportError:
    sys.exit("pip install pyserial")

CAPTURES = os.environ.get("SNIFF_CAPTURES") or os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "captures")   # default: ../captures next to the repo
PROMPT = re.compile(r"^(esp32c6>\s*)+")
ALL_PHASES = ["state", "burst", "sizes", "udp", "density", "unicast", "sed", "txpower", "scan"]


class Log:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.f = open(path, "w", newline="", encoding="utf-8")
        self.w = csv.writer(self.f)
        self.w.writerow(["host_iso", "host_epoch", "t_rel_s", "node", "kind", "phase", "channel", "text"])
        self.t0 = time.time()
        self.lock = threading.Lock()
        self.phase, self.channel = "", ""

    def row(self, node, kind, text, t=None):
        t = time.time() if t is None else t
        iso = dt.datetime.fromtimestamp(t).isoformat(timespec="milliseconds")
        with self.lock:
            self.w.writerow([iso, "%.6f" % t, "%.3f" % (t - self.t0), node, kind, self.phase, self.channel, text])
            self.f.flush()
        if kind != "rx" or text.strip():
            print("%s %-6s %-5s %s" % (iso[11:], node, kind, text), flush=True)


class Node:
    def __init__(self, name, port, log, dry=False):
        self.name, self.log, self.dry = name, log, dry
        self.lines, self.cv = [], threading.Condition()
        if dry:
            return
        self.s = serial.Serial()
        self.s.port, self.s.baudrate, self.s.timeout = port, 115200, 0.05
        self.s.dtr = False  # keep EN/BOOT untouched -> no reset on open
        self.s.rts = False
        self.s.open()
        threading.Thread(target=self._rx, daemon=True).start()

    def _rx(self):
        buf = b""
        while True:
            try:
                buf += self.s.read(4096)
            except Exception as e:
                self.log.row(self.name, "error", repr(e)); return
            while b"\n" in buf:
                ln, buf = buf.split(b"\n", 1)
                t = time.time()
                txt = PROMPT.sub("", ln.decode(errors="replace").rstrip("\r"))
                if not txt.strip():
                    continue
                self.log.row(self.name, "rx", txt, t)
                with self.cv:
                    self.lines.append(txt); self.cv.notify_all()

    def send(self, cmd):
        """Fire a command, log host timestamp (just before write). Non-blocking."""
        if not cmd.startswith("ot "):
            cmd = "ot " + cmd
        with self.cv:
            mark = len(self.lines)
        self.log.row(self.name, "cmd", cmd)
        if not self.dry:
            self.s.write((cmd + "\r\n").encode())
        return mark

    NOISE = re.compile(r"^(I|W|E|D)\(\d+\)|packets transmitted|bytes from|^\s*$")

    def query(self, cmd, timeout=3.0):
        """Send and wait for Done/Error; returns output lines after the echo (async noise removed)."""
        if not cmd.startswith("ot "):
            cmd = "ot " + cmd
        mark = self.send(cmd)
        if self.dry:
            return []
        end = time.time() + timeout
        with self.cv:
            while time.time() < end:
                new = self.lines[mark:]
                try:
                    i = next(k for k, l in enumerate(new) if l.strip() == cmd)
                except StopIteration:
                    self.cv.wait(0.05); continue
                body = [l for l in new[i + 1:] if not self.NOISE.search(l)]
                if any(l.startswith(("Done", "Error")) for l in body):
                    out = []
                    for l in body:
                        out.append(l)
                        if l.startswith(("Done", "Error")):
                            break
                    return out
                self.cv.wait(0.05)
        self.log.row(self.name, "error", "timeout waiting for '%s'" % cmd)
        return []

    def ping(self, dst, size=16, count=1, interval=1, timeout=0.05):
        """Non-blocking ping (ot_cli 'ping' blocks the console until the timeout, default 3 s!).
        Only one ping session may run at a time (Error 5: Busy otherwise)."""
        r = self.query("ping async %s %d %d %s 64 %s" % (dst, size, count, interval, timeout), 1.0)
        if r and r[-1].startswith("Error 5"):
            self.query("ping stop", 1.0)
            r = self.query("ping async %s %d %d %s 64 %s" % (dst, size, count, interval, timeout), 1.0)
        return r

def wait(s, log, why=""):
    if why:
        log.row("host", "mark", "wait %.2fs %s" % (s, why))
    time.sleep(s)


def wait_attached(n, log, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        r = n.query("state", 2)
        if n.dry or any(x in ("leader", "router", "child") for x in r):
            return r[0] if r else "?"
        time.sleep(2)
    log.row(n.name, "error", "not attached after %ss" % timeout)
    return None


def first_addr(n, sub):
    r = n.query("ipaddr " + sub, 2)
    return next((x for x in r if ":" in x), None)


# ---------------------------------------------------------------- phases
def ph_state(L, N2, log):
    for n in [L] + ([N2] if N2 else []):
        for c in ("state", "channel", "rloc16", "extaddr", "ipaddr", "counters mac"):
            n.query(c)
    if N2:
        L.query("child table"); L.query("router table"); N2.query("parent")


def ph_burst(L, N2, log, dst="ff02::1"):
    # 3 bursts x 3 small pings, 100 ms apart, 1.5 s gap -> clear "III   III   III" on waterfall
    for b in range(3):
        for i in range(3):
            L.ping(dst, 16); time.sleep(0.10)
        wait(1.5, log, "burst gap")


def ph_sizes(L, N2, log, dst="ff02::1"):
    # size ladder: 16/64/80 = single frame; 200/400/1000 = 6LoWPAN fragmented (2/4/9+ frames)
    for size in (16, 64, 80, 200, 400, 1000):
        log.row("host", "mark", "size %d" % size)
        L.ping(dst, size); wait(0.8, log)


def ph_udp(L, N2, log, dst="ff02::1"):
    L.query("udp open"); L.query("udp bind :: 61631")
    if N2:
        N2.query("udp open"); N2.query("udp bind :: 61631")
    for p in ("hello", "-s 50", "-s 120", "-s 300"):
        L.send("udp send %s 61631 %s" % (dst, p)); wait(0.6, log)
    if N2:
        N2.send("udp send %s 61631 -s 60" % dst); wait(0.6, log)
        N2.query("udp close")
    L.query("udp close")


def ph_density(L, N2, log, dst="ff02::1"):
    # same frame, three densities: 5/s, 20/s, ~50/s (ot ping interval in seconds)
    for count, iv in ((10, 0.2), (20, 0.05), (30, 0.02)):
        log.row("host", "mark", "density %d x %.3fs" % (count, iv))
        L.ping(dst, 32, count, iv); wait(count * iv + 1.5, log)


def ph_unicast(L, N2, log):
    if not N2:
        log.row("host", "mark", "skip unicast (no --port2)"); return
    a = first_addr(N2, "mleid") or first_addr(N2, "rloc")
    if not a:
        log.row("host", "error", "node2 has no address"); return
    # unicast: frame + ACK (+ echo reply + ACK) -> 4 RF bursts per ping
    for size in (16, 100, 400, 1200):
        L.ping(a, size, timeout=0.5); wait(1.0, log, "unicast %d" % size)
    for i in range(3):
        L.ping(a, 16); time.sleep(0.10)
    wait(1.0, log)


def ph_sed(L, N2, log):
    # node2 becomes sleepy end device -> periodic MAC Data Requests (poll) every 300 ms
    if not N2:
        log.row("host", "mark", "skip sed (no --port2)"); return
    oldmode = (N2.query("mode") or ["rdn"])[0]
    N2.query("pollperiod 300"); N2.query("mode -")
    wait(6, log, "SED polling (data requests)")
    a = first_addr(N2, "mleid")
    if a:
        L.ping(a, 32, 3, 1, 1); wait(4, log, "indirect tx to SED")
    N2.query("mode " + oldmode); N2.query("pollperiod 0")
    wait(3, log, "node2 back to %s" % oldmode)


def ph_scan(L, N2, log):
    # active scan (beacon req on all 16 ch) + MLE discover + energy scan: wideband, use --hop
    scanner = N2 or L
    scanner.query("scan", 10); wait(1, log)
    scanner.query("discover", 10); wait(1, log)
    scanner.query("scan energy 100", 10); wait(1, log)


# ---------------------------------------------------------------- PER (sequenced UDP)
PER = dict(count=100, interval=0.1, size=64, dst="ff02::1", port=61631, node="lead", txpowers="20,0,-10,-20,-24")


def _per_txpower(n):
    r = n.query("txpower")
    try:
        return int(r[0].split()[0])
    except Exception:
        return None


def per_run(L, N2, log, tag=""):
    """Sequenced UDP run: payload SSPR,<run>,<seq>,<tx_ms>,<ch>,<txp>,<pad>; TX list -> captures/per/per_<run>_tx.csv.
    The dashboard (sniff_sight/per.py) keeps the per-seq ledger and labels the losses."""
    n = N2 if (PER["node"] == "node2" and N2) else L
    rid = time.strftime("%m%d%H%M%S") + tag
    ch = log.channel or "?"
    txp = _per_txpower(n)
    d = os.path.join(CAPTURES, "per")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "per_%s_tx.csv" % rid)
    f = open(path, "w", newline="", encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["run", "seq", "tx_t", "channel", "txpower", "size", "dst", "node"]); f.flush()
    log.row("host", "mark", "PER run %s: %d x %.3fs, %d B -> %s:%d from %s, ch %s, txpower %s"
            % (rid, PER["count"], PER["interval"], PER["size"], PER["dst"], PER["port"], n.name, ch, txp))
    n.query("udp open")
    t_next = time.time()
    for seq in range(PER["count"]):
        t_next += PER["interval"]
        tx = time.time()
        body = "SSPR,%s,%d,%d,%s,%s," % (rid, seq, int(tx * 1000), ch, txp)
        body += "." * max(0, PER["size"] - len(body))
        w.writerow([rid, seq, "%.4f" % tx, ch, txp, len(body), PER["dst"], n.name]); f.flush()
        r = n.query("udp send %s %d %s" % (PER["dst"], PER["port"], body), 1.0)
        if not r or not r[-1].startswith("Done"):
            log.row(n.name, "error", "PER seq %d send: %s" % (seq, r))
        time.sleep(max(0.0, t_next - time.time()))
    w.writerow([rid, "END", "%.4f" % time.time(), ch, txp, "", "", n.name]); f.close()
    n.query("udp close")
    log.row("host", "mark", "PER run %s done, TX log %s" % (rid, path))
    return rid


def ph_per(L, N2, log):
    per_run(L, N2, log)


def ph_pertx(L, N2, log):
    """PER run at each TX power step (provoke weak-signal losses), then restore the original power."""
    n = N2 if (PER["node"] == "node2" and N2) else L
    orig = _per_txpower(n)
    TXP_ORIG[n.name] = (n, str(orig))
    try:
        for p in [int(x) for x in PER["txpowers"].split(",")]:
            n.query("txpower %d" % p)
            per_run(L, N2, log, tag="p%d" % p if p >= 0 else "m%d" % -p)
            wait(1.0, log, "pertx step")
    finally:
        restore_txpower(log)


TXP_ORIG = {}


def ph_txpower(L, N2, log, dst="ff02::1"):
    # step TX power down to provoke weak signal / loss / FCS errors at the sniffer;
    # each step: read back actual value, then 3 pings 100 ms apart + 1 x 400 B fragmented
    n = L
    orig = (n.query("txpower") or ["?"])[0].split()[0]
    TXP_ORIG[n.name] = (n, orig)
    log.row(n.name, "mark", "txpower original %s" % orig)
    for p in (20, 10, 0, -10, -15, -20, -24):
        n.query("txpower %d" % p)
        got = (n.query("txpower") or ["?"])[0]
        log.row(n.name, "mark", "txpower set %d -> %s" % (p, got))
        for i in range(3):
            n.ping(dst, 16); time.sleep(0.10)
        wait(0.5, log); n.ping(dst, 400); wait(1.0, log, "txpower step gap")
    restore_txpower(log)


def restore_txpower(log):
    for name, (n, orig) in list(TXP_ORIG.items()):
        if orig.lstrip("-").isdigit():
            n.query("txpower %s" % orig)
            log.row(name, "mark", "txpower restored %s" % ((n.query("txpower") or ["?"])[0]))
        TXP_ORIG.pop(name)


PHASES = dict(per=ph_per, pertx=ph_pertx, txpower=ph_txpower, state=ph_state, burst=ph_burst, sizes=ph_sizes, udp=ph_udp, density=ph_density,
              unicast=ph_unicast, sed=ph_sed, scan=ph_scan)


def change_channel(L, N2, log, ch, delay_ms=5000):
    """Pending-dataset channel move; joined nodes follow automatically."""
    log.channel = ""
    log.row("host", "mark", "CHANNEL -> %d (delay %d ms)" % (ch, delay_ms))
    if L.dry:
        for c in ("dataset clear", "dataset init active", "dataset activetimestamp N+1",
                  "dataset channel %d" % ch, "dataset delay %d" % delay_ms, "dataset commit pending"):
            L.send(c)
        log.channel = ch; return True
    act = L.query("dataset active -x", 3)
    ts_lines = L.query("dataset active", 3)
    ts = next((int(x.split(":")[1]) for x in ts_lines if x.startswith("Active Timestamp")), 1)
    for c in ("dataset clear", "dataset init active", "dataset activetimestamp %d" % (ts + 1),
              "dataset channel %d" % ch, "dataset delay %d" % delay_ms):
        L.query(c)
    r = L.query("dataset commit pending", 3)
    if not r or not r[-1].startswith("Done"):
        log.row("host", "error", "commit pending failed: %s" % r); return False
    L.query("dataset clear")
    wait(delay_ms / 1000 + 3, log, "wait for pending dataset")
    for n in [L] + ([N2] if N2 else []):
        got = n.query("channel")
        log.row(n.name, "mark", "now on channel %s" % (got[0] if got else "?"))
    if N2:
        wait_attached(N2, log, 30)
    log.channel = ch
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="COM8", help="leader ot_cli console")
    ap.add_argument("--port2", default=None, help="second C6 (child/router) console, optional")
    ap.add_argument("--channels", default="15", help="comma list, e.g. 15,20,25 (pending-dataset steps)")
    ap.add_argument("--phases", default=",".join(ALL_PHASES), help="subset of " + ",".join(ALL_PHASES))
    ap.add_argument("--repeat", type=int, default=1, help="repeat phase set per channel")
    ap.add_argument("--home", type=int, default=15, help="channel restored at the end")
    ap.add_argument("--gap", type=float, default=3.0, help="idle seconds between phases")
    ap.add_argument("--csv", default=None)
    ap.add_argument("--per-count", type=int, default=PER["count"], help="PER: packets per run")
    ap.add_argument("--per-interval", type=float, default=PER["interval"], help="PER: seconds between packets (>=0.05)")
    ap.add_argument("--per-size", type=int, default=PER["size"], help="PER: UDP payload bytes (40..200)")
    ap.add_argument("--per-dst", default=PER["dst"], help="PER: destination (ff02::1 on air with 1 node; node2 ML-EID later)")
    ap.add_argument("--per-node", choices=["lead", "node2"], default="lead", help="PER: sending node")
    ap.add_argument("--per-txpowers", default=PER["txpowers"], help="pertx: TX power steps (dBm)")
    ap.add_argument("--dry-run", action="store_true", help="no serial, just print schedule")
    a = ap.parse_args()

    PER.update(count=a.per_count, interval=max(0.05, a.per_interval), size=max(40, min(200, a.per_size)),
               dst=a.per_dst, node=a.per_node, txpowers=a.per_txpowers)
    phases = [p.strip() for p in a.phases.split(",") if p.strip()]
    for p in phases:
        if p not in PHASES:
            sys.exit("unknown phase " + p)
    chans = [int(c) for c in a.channels.split(",")]
    path = a.csv or os.path.join(CAPTURES, "traffic", time.strftime("traffic_%Y%m%d_%H%M%S.csv"))
    log = Log(path)
    print("CSV:", path)
    L = Node("lead", a.port, log, a.dry_run)
    N2 = Node("node2", a.port2, log, a.dry_run) if a.port2 else None
    time.sleep(0.3)
    try:
        if not wait_attached(L, log):
            sys.exit(1)
        if N2:
            wait_attached(N2, log)
        cur = (L.query("channel") or [str(a.home)])[0]
        log.channel = cur
        for ch in chans:
            if str(ch) != str(log.channel):
                if not change_channel(L, N2, log, ch):
                    break
            for r in range(a.repeat):
                for p in phases:
                    log.phase = p
                    log.row("host", "mark", "PHASE %s ch%s start" % (p, log.channel))
                    PHASES[p](L, N2, log)
                    log.row("host", "mark", "PHASE %s end" % p)
                    log.phase = ""
                    wait(a.gap, log, "inter-phase gap")
    except KeyboardInterrupt:
        log.row("host", "mark", "interrupted")
    finally:
        log.phase = "restore"
        restore_txpower(log)
        if str(log.channel) != str(a.home):
            change_channel(L, N2, log, a.home)
        L.query("udp close", 1)
        log.row("host", "mark", "done")
        print("CSV:", path)


if __name__ == "__main__":
    main()



