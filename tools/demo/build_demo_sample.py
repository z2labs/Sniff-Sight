"""Build the canned demo sample (sniff_sight/demo/sample.json) from a capture session.

    python tools/demo/build_demo_sample.py --captures <workdir>/captures --session thread_ch15_20261014_001843

Uses the per-packet spectrum snippets (captures/snippets/<session>_*.npz) and the burst
log (captures/bursts/bursts_*.csv) of the same time window. Scrubbing: device addresses
are replaced by synthetic ones, absolute times are shifted to t=0, file paths are dropped.
Full-span spectrum frames are not stored; the demo player re-synthesises them from the
burst log (floor + burst shapes) so the sample stays small.
"""
import argparse, csv, glob, json, os, re
import numpy as np

ap = argparse.ArgumentParser()
ap.add_argument("--captures", required=True)
ap.add_argument("--session", required=True, help="snippet file prefix, e.g. thread_ch15_20261014_001843")
ap.add_argument("--max-s", type=float, default=90.0)
ap.add_argument("--min-excess", type=float, default=10.0, help="drop weak bursts (dB over floor)")
ap.add_argument("--max-snips", type=int, default=20)
ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "..", "sniff_sight", "demo", "sample.json"))
a = ap.parse_args()

files = sorted(glob.glob(os.path.join(a.captures, "snippets", a.session + "_*.npz")),
               key=lambda p: int(re.findall(r"_(\d+)\.npz$", p)[0]))
snips = []
for p in files:
    with np.load(p, allow_pickle=False) as z:
        m = json.loads(str(z["meta"])); m.setdefault("t_host", m.get("t"))
        snips.append((m, json.loads(str(z["pair"])), z["db"], z["freqs_mhz"], z["t0_s"], z["t1_s"], float(z["t_packet"])))
if not snips:
    raise SystemExit("no snippets")
ts = [s[0]["t_host"] for s in snips]
best = max(range(len(ts)), key=lambda i: sum(1 for t in ts if ts[i] <= t <= ts[i] + a.max_s - 4))
T0 = ts[best] - 2.0
T1 = min(T0 + a.max_s, max(t for t in ts if t <= T0 + a.max_s - 2) + 2.0)
snips = [s for s in snips if T0 <= s[0]["t_host"] <= T1]

addr_map = {}
def fake(m):
    v = m.group(0).lower()
    if v not in addr_map:
        n = len(addr_map) + 1
        addr_map[v] = "02:00:5e:00:00:00:00:%02x" % n
    return addr_map[v]
MAC = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){7}\b")
def scrub(x):
    return MAC.sub(fake, x) if isinstance(x, str) else x

packets, snippets = [], {}
for i, (meta, pair, db, fr, t0, t1, tp) in enumerate(snips):
    sid = "demo_%03d" % (i + 1)
    pkt = {k: scrub(meta.get(k)) for k in ("src", "dst", "pan", "kind", "info", "rssi", "lqi", "len", "seq", "channel", "freq_mhz", "frame", "airtime_ms", "psdu_len")}
    pkt.update(type="pkt", id=sid, t=round(meta["t_host"] - T0, 4), fcs_ok=True, pcap_file="demo.pcap")
    pair = dict(pair, snippet=sid)
    pkt["pair"] = pair
    packets.append(pkt)
    if i < a.max_snips:
        m2 = dict(pkt); m2.pop("pair"); m2["t_host"] = m2["t"]
        m2["spectrum"] = meta.get("spectrum")
        snippets[sid] = {"db": np.rint(db).astype(int).tolist(), "freqs_mhz": np.round(fr, 3).tolist(),
                         "t0_ms": np.round(t0 * 1e3, 2).tolist(), "t1_ms": np.round(t1 * 1e3, 2).tolist(),
                         "t_packet": pkt["t"], "meta": m2, "pair": pair}

KEEP = ("t0", "t1", "duration_ms", "f_center_mhz", "f_lo_mhz", "f_hi_mhz", "bw10_mhz", "bw20_mhz", "peak_excess_db",
        "peak_dbfs", "floor_dbfs", "cls", "confidence", "reason", "gt", "drift_range_mhz", "flatness", "ibi_med_ms")
bursts = []
for f in sorted(glob.glob(os.path.join(a.captures, "bursts", "bursts_*.csv"))):
    with open(f, newline="", encoding="utf-8") as fh:
        r = csv.DictReader(fh)
        for row in r:
            try:
                t0 = float(row["t0"])
            except (TypeError, ValueError):
                continue
            if T0 <= t0 <= T1 and float(row.get("peak_excess_db") or 0) >= a.min_excess:
                b = {}
                for k in KEEP:
                    v = row.get(k)
                    try:
                        b[k] = round(float(v), 2)
                    except (TypeError, ValueError):
                        b[k] = v or None
                b["t0"] = round(b["t0"] - T0, 4); b["t1"] = round(float(row["t1"]) - T0, 4)
                b["gt"] = "802.15.4" if row.get("gt") else None
                bursts.append(b)
bursts.sort(key=lambda b: b["t0"])
for i, b in enumerate(bursts):
    b["id"] = "demo_b%05d" % (i + 1)
    b["snippet"] = None
    b["ask"] = False

out = {"version": 1, "source": "Sniff-Sight lab capture (OpenThread test network, ch 15), scrubbed",
       "duration_s": round(T1 - T0, 2), "center_hz": 2437e6, "span_hz": 80e6, "bins": 2048, "frame_ms": 4.35,
       "floor_dbfs": -70.0, "packets": packets, "bursts": bursts, "snippets": snippets}
os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
with open(a.out, "w", encoding="utf-8") as fh:
    json.dump(out, fh, separators=(",", ":"))
print(f"{len(packets)} packets, {len(bursts)} bursts, {len(snippets)} snippets, {out['duration_s']} s -> {a.out} ({os.path.getsize(a.out)/1e6:.2f} MB)")