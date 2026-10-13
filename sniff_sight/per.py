"""Packet-loss ledgers.

PRIMARY (key independent): per source + stream the aux-security Frame Counter (and MAC DSN);
gaps = frames the sniffer missed.  Works on foreign networks without the key (FcSource).
SECONDARY (needs decryption): sequenced SSPR UDP test payload, described below.

Sequenced packet-error-rate (PER) ledger.

traffic_test.py (phase 'per') sends UDP datagrams whose payload starts with
    SSPR,<run>,<seq>,<tx_ms>,<channel>,<txpower>,<pad...>
and logs every send to  <captures>/per/per_<run>_tx.csv  (run,seq,tx_t,channel,txpower,size,dst,node).
The sniffer side (thread_sniffer -> tshark data.data, decrypted with the Thread key) feeds
received payloads here.  Per run we keep a strict seq ledger (received / missing / duplicate /
late).  A sequence number that is still missing GRACE_S after its expected air time
(tx host time + median tx->sniffer offset of the run, or interpolation between neighbours
when there is no TX log) is classified from the spectrum ring at that moment:

    sniffer-blind   sniffer was on another channel (hop) or the channel is outside the SDR view
    lost-with-burst a burst is present in the channel band within +-WINDOW of the expected time
    lost-no-burst   nothing above the noise floor -> the frame was probably never sent
    lost-nospec     no spectrum frames for that time

and a spectrum snippet  snippets/per_<run>_<seq>.npz  is written (same format as packet
snippets, so the dashboard can open it).  Results: per_<run>_ledger.csv, per_<run>_summary.json
and the append-only per_labels.csv (one row per missing frame, for ML).
"""
import collections
import csv
import glob
import json
import os
import time
from typing import Callable, Optional

from . import rfpair

MAGIC = b"SSPR"
GRACE_S = 2.0          # wait this long after the expected air time before declaring a loss
WINDOW_S = 0.030       # burst search window around the expected air time
DEFAULT_OFFSET_S = 0.025


def parse_payload(hexstr: str) -> Optional[dict]:
    if not hexstr or not hexstr.startswith("53535052"):
        return None
    try:
        txt = bytes.fromhex(hexstr.replace(":", "")).decode("ascii", "replace")
        f = txt.split(",")
        return {"run": f[1], "seq": int(f[2]), "tx_ms": int(f[3]), "channel": int(f[4]),
                "txpower": int(f[5]) if f[5].lstrip("-").isdigit() else None, "size": len(txt)}
    except Exception:
        return None


class Run:
    def __init__(self, rid):
        self.id = rid
        self.tx = {}            # seq -> dict(tx_t, channel, txpower, size, dst, node)
        self.rx = {}            # seq -> dict(t, count, pkt_id, rssi, lqi, pair)
        self.miss = {}          # seq -> dict(expected_t, label, snippet, excess_db, offset_ms, late)
        self.ended = False
        self.offsets = []
        self.dirty = True
        self.first = self.last = time.time()

    def offset(self):
        if not self.offsets:
            return DEFAULT_OFFSET_S
        s = sorted(self.offsets[-200:])
        return s[len(s) // 2]

    def expected(self, seq):
        if seq in self.tx:
            return self.tx[seq]["tx_t"] + self.offset()
        # no TX log: interpolate between received neighbours
        lo = max((s for s in self.rx if s < seq), default=None)
        hi = min((s for s in self.rx if s > seq), default=None)
        if lo is not None and hi is not None:
            a, b = self.rx[lo]["t"], self.rx[hi]["t"]
            return a + (b - a) * (seq - lo) / (hi - lo)
        return None

    def summary(self):
        seqs = set(self.tx) | set(self.rx)
        expected = (max(seqs) - min(seqs) + 1) if seqs else 0
        if self.tx:
            expected = len(self.tx)
        rx = len(self.rx)
        dup = sum(max(0, r["count"] - 1) for r in self.rx.values())
        late = sum(1 for m in self.miss.values() if m.get("late"))
        lost = sum(1 for s, m in self.miss.items() if s not in self.rx)
        labels = {}
        for s, m in self.miss.items():
            if s not in self.rx:
                labels[m["label"]] = labels.get(m["label"], 0) + 1
        any_tx = next(iter(self.tx.values()), None)
        any_rx = next(iter(self.rx.values()), None)
        rss = [r["rssi"] for r in self.rx.values() if r.get("rssi") is not None]
        decided = rx + lost
        return {"run": self.id, "tx": len(self.tx), "expected": expected, "rx": rx, "lost": lost,
                "pending": max(0, expected - decided), "dup": dup, "late": late, "labels": labels,
                "per_pct": round(100.0 * lost / decided, 2) if decided else None,
                "channel": (any_tx or {}).get("channel") or (any_rx or {}).get("channel"),
                "txpower": (any_tx or {}).get("txpower"), "size": (any_tx or {}).get("size"),
                "offset_ms": round(self.offset() * 1e3, 1), "ended": self.ended,
                "first": self.first, "last": self.last,
                "rssi_mean": round(sum(rss) / len(rss), 1) if rss else None}

    def rows(self):
        out = []
        for s in sorted(set(self.tx) | set(self.rx) | set(self.miss)):
            t, r, m = self.tx.get(s, {}), self.rx.get(s), self.miss.get(s)
            status = "rx" if r and not (m and m.get("late")) else ("late" if r else ("lost" if m else "pending"))
            if r and r["count"] > 1:
                status += "+dup"
            out.append({"seq": s, "status": status, "tx_t": t.get("tx_t"), "expected_t": (m or {}).get("expected_t"),
                        "rx_t": r and r["t"], "rx_count": r["count"] if r else 0, "pkt_id": r and r.get("pkt_id"),
                        "rssi": r and r.get("rssi"), "lqi": r and r.get("lqi"),
                        "rf": (r or {}).get("pair") or None, "label": (m or {}).get("label"),
                        "snippet": (m or {}).get("snippet") or (r and r.get("pkt_id")),
                        "excess_db": (m or {}).get("excess_db"), "burst_offset_ms": (m or {}).get("offset_ms"),
                        "channel": t.get("channel"), "txpower": t.get("txpower"), "size": t.get("size")})
        return out


class FcSource:
    """Key-independent loss ledger for one (source, stream): the 32-bit security Frame Counter
    in the aux security header increments once per secured frame (a MAC retransmission keeps
    counter and DSN), so a jump of k > 1 means k-1 frames were sent that the sniffer did not get.
    stream 'mac' = MAC-layer secured frames, 'mle' = MLE (key id mode 2, own counter)."""

    def __init__(self, key):
        self.key = key
        self.rx = 0
        self.missed = 0
        self.retx = 0
        self.resets = 0
        self.dsn_gaps = 0
        self.last_fc = self.last_dsn = None
        self.last_t = 0.0
        self.first_fc = None
        self.labels = {}

    def summary(self):
        tot = self.rx + self.missed
        return {"src": self.key[0], "stream": self.key[1], "rx": self.rx, "missed": self.missed,
                "retx": self.retx, "resets": self.resets, "dsn_gaps": self.dsn_gaps, "last_fc": self.last_fc,
                "per_pct": round(100.0 * self.missed / tot, 2) if tot else None, "labels": dict(self.labels),
                "last": self.last_t}


class PerTracker:
    def __init__(self, captures: str, snippets: str, ring_fn: Callable, channel_at: Callable[[float], Optional[int]],
                 center_info: Callable[[], dict], on_update: Callable[[dict], None], half_s=0.1, half_mhz=4.0):
        self.dir = os.path.join(captures, "per")
        self.snippets = snippets
        os.makedirs(self.dir, exist_ok=True)
        self.ring_fn, self.channel_at, self.center_info, self.on_update = ring_fn, channel_at, center_info, on_update
        self.half_s, self.half_mhz = half_s, half_mhz
        self.runs: dict[str, Run] = {}
        self._pos: dict[str, int] = {}
        self._last_write = 0.0
        self.labels_path = os.path.join(self.dir, "per_labels.csv")
        self.t_start = time.time()
        self.fc: dict = {}
        self.fc_pending = []                     # (src, stream, fc, expected_t, gap_info)
        self.fc_events = collections.deque(maxlen=3000)
        self.fc_dirty = False
        self.fc_path = os.path.join(self.dir, "fc_missed_%s.csv" % time.strftime("%Y%m%d"))
        self.max_gap = 64                        # larger jumps = counter reset / we were away

    # -------------------------------------------------- inputs
    def _run(self, rid):
        r = self.runs.get(rid)
        if r is None:
            r = self.runs[rid] = Run(rid)
            if len(self.runs) > 50:
                for k in sorted(self.runs, key=lambda k: self.runs[k].last)[:len(self.runs) - 50]:
                    self.runs.pop(k, None)
        return r

    def poll_tx_logs(self):
        now = time.time()
        for p in glob.glob(os.path.join(self.dir, "per_*_tx.csv")):
            try:
                st = os.stat(p)
            except OSError:
                continue
            pos = self._pos.get(p)
            if pos is None:
                if st.st_mtime < self.t_start - 2:   # run from before this launcher start: spectrum/rx gone
                    self._pos[p] = st.st_size
                    continue
                pos = 0
            if st.st_size <= pos:
                continue
            with open(p, "r", encoding="utf-8", newline="") as f:
                f.seek(pos)
                data = f.read()
                cut = data.rfind("\n") + 1
                self._pos[p] = pos + len(data[:cut].encode("utf-8"))
            for row in csv.reader(data[:cut].splitlines()):
                if not row or row[0] == "run":
                    continue
                try:
                    run = self._run(row[0])
                    if row[1] == "END":
                        run.ended = True; run.dirty = True
                        continue
                    seq = int(row[1])
                    run.tx[seq] = {"tx_t": float(row[2]), "channel": int(row[3]),
                                   "txpower": int(row[4]) if row[4].lstrip("-").isdigit() else None,
                                   "size": int(row[5]), "dst": row[6], "node": row[7] if len(row) > 7 else ""}
                    run.last = time.time(); run.dirty = True
                except Exception:
                    pass

    def on_packet(self, pkt: dict):
        per = pkt.get("per")
        if not per:
            return
        run = self._run(per["run"])
        seq = per["seq"]
        r = run.rx.get(seq)
        if r:
            r["count"] += 1
        else:
            run.rx[seq] = {"t": pkt["t"], "count": 1, "pkt_id": pkt.get("id"), "rssi": pkt.get("rssi"),
                           "lqi": pkt.get("lqi"), "channel": pkt.get("channel"), "pair": None}
            if seq in run.miss:
                run.miss[seq]["late"] = True
            run.offsets.append(pkt["t"] - per["tx_ms"] / 1000.0)
        run.last = time.time(); run.dirty = True

    def on_frame(self, pkt: dict):
        """Every decoded frame with a security frame counter (key not needed)."""
        fc = pkt.get("fc")
        src = pkt.get("src")
        if fc is None or not src:
            return
        key = (src, pkt.get("fc_stream") or "mac")
        s = self.fc.get(key)
        if s is None:
            s = self.fc[key] = FcSource(key)
        dsn, t = pkt.get("seq"), pkt["t"]
        if s.last_fc is None:
            s.first_fc = fc
        else:
            d = (fc - s.last_fc) & 0xFFFFFFFF
            if d == 0:
                s.retx += 1                                   # retransmission / duplicate
            elif d > 0x80000000 or d > self.max_gap:
                s.resets += 1                                 # counter went back or jumped: new epoch
            elif d > 1:
                s.missed += d - 1
                for k in range(1, d):                         # interpolate the missing frames' air times
                    te = s.last_t + (t - s.last_t) * k / d
                    self.fc_pending.append((key, s.last_fc + k, te, s.last_t, t, s.last_dsn, dsn))
            if dsn is not None and s.last_dsn is not None and d == 1 and (dsn - s.last_dsn) & 0xFF != 1:
                s.dsn_gaps += 1
        s.rx += 1
        s.last_fc, s.last_dsn, s.last_t = fc, dsn, t
        self.fc_dirty = True

    def _fc_tick(self, save_async):
        now = time.time()
        keep = []
        for item in self.fc_pending:
            key, fc, te, ta, tb, da, db_ = item
            if now - te < 0.4:
                keep.append(item); continue
            src = self.fc[key]
            ch = self.channel_at(te) or 15
            f = 2405.0 + 5.0 * (ch - 11)
            ev = {"t": round(te, 4), "src": key[0], "stream": key[1], "fc": fc, "prev_t": round(ta, 4),
                  "next_t": round(tb, 4), "uncert_ms": round((tb - ta) * 500, 1), "dsn_prev": da, "dsn_next": db_,
                  "dsn_skip": ((db_ - da) & 0xFF) - 1 if da is not None and db_ is not None else None,
                  "channel": ch, "label": None, "snippet": None, "excess_db": None, "offset_ms": None}
            cut = None
            if tb - ta <= 2 * self.half_s and now - te < 8.0:       # exact enough and still in the ring
                try:
                    cut = self.ring_fn().cut(te, max(self.half_s, (tb - ta) / 2), f, self.half_mhz)
                except Exception:
                    cut = None
            if cut is None:
                ev["label"] = "lost-time-unknown" if tb - ta > 2 * self.half_s else "lost-nospec"
            else:
                db, t0, t1, fr = cut
                win = max(0.008, min(WINDOW_S, (tb - ta) / 2 - 0.008))   # stay clear of the neighbour frames' bursts
                res = rfpair.pair(db, t0, t1, fr, f, te, match_window_s=win)
                ev["excess_db"], ev["offset_ms"] = res.get("excess_db"), res.get("offset_ms")
                ev["label"] = "lost-with-burst" if res.get("quality") == "matched" else "lost-no-burst"
                sid = "fc_%s_%s_%d" % (key[0].replace(":", "")[-8:], key[1], fc)
                ev["snippet"] = sid
                res = dict(res); res["snippet"] = sid; res["per_label"] = ev["label"]
                meta = {"id": sid, "t": te, "kind": "FC lost: " + ev["label"],
                        "info": "src %s %s frame counter %d missing (between frames %.1f ms apart)" % (key[0], key[1], fc, (tb - ta) * 1e3),
                        "src": key[0], "dst": "", "channel": ch, "freq_mhz": f, "seq": None, "fc": ev,
                        "spectrum": self.center_info()}
                save_async(os.path.join(self.snippets, sid + ".npz"), db, t0, t1, fr, te, meta, res)
            src.labels[ev["label"]] = src.labels.get(ev["label"], 0) + 1
            self.fc_events.append(ev)
            try:
                new = not os.path.exists(self.fc_path)
                with open(self.fc_path, "a", newline="", encoding="utf-8") as fh:
                    w = csv.DictWriter(fh, fieldnames=list(ev.keys()))
                    if new:
                        w.writeheader()
                    w.writerow(ev)
            except OSError:
                pass
            self.fc_dirty = True
        self.fc_pending = keep

    def fc_summary(self):
        return sorted((s.summary() for s in self.fc.values()), key=lambda x: -x["rx"])

    def on_pair(self, pkt: dict, res: dict):
        per = pkt.get("per")
        if not per:
            return
        run = self.runs.get(per["run"])
        if run and per["seq"] in run.rx:
            run.rx[per["seq"]]["pair"] = res.get("quality"); run.dirty = True

    # -------------------------------------------------- loss classification
    def tick(self, save_async: Callable):
        self.poll_tx_logs()
        self._fc_tick(save_async)
        now = time.time()
        for run in list(self.runs.values()):
            seqs = set(run.tx) | set(run.rx)
            if not seqs:
                continue
            cand = set(run.tx) if run.tx else set(range(min(run.rx), max(run.rx) + 1))
            for seq in sorted(cand - set(run.rx) - set(run.miss)):
                te = run.expected(seq)
                if te is None or now - te < GRACE_S:
                    continue
                run.miss[seq] = self._classify(run, seq, te, save_async)
                run.dirty = True
        if now - self._last_write > 1.0:
            self._last_write = now
            if self.fc_dirty:
                self.fc_dirty = False
                self.on_update({"fc": self.fc_summary(), "fc_events": list(self.fc_events)[-50:]})
                try:
                    with open(os.path.join(self.dir, "fc_summary.json"), "w", encoding="utf-8") as fh:
                        json.dump(self.fc_summary(), fh, indent=1)
                except OSError:
                    pass
            for run in self.runs.values():
                if run.dirty:
                    run.dirty = False
                    self._write(run)
                    self.on_update(run.summary())

    def _classify(self, run, seq, te, save_async):
        t = run.tx.get(seq, {})
        ch = t.get("channel") or next((r["channel"] for r in run.rx.values() if r.get("channel")), None) or 15
        f = 2405.0 + 5.0 * (ch - 11)
        m = {"expected_t": round(te, 4), "label": None, "snippet": None, "excess_db": None, "offset_ms": None}
        sniff_ch = self.channel_at(te)
        ring = self.ring_fn()
        cut = None
        try:
            cut = ring.cut(te, self.half_s, f, self.half_mhz)
        except Exception:
            pass
        res = {}
        if cut is not None:
            db, t0, t1, fr = cut
            res = rfpair.pair(db, t0, t1, fr, f, te, match_window_s=WINDOW_S)
            m["excess_db"], m["offset_ms"] = res.get("excess_db"), res.get("offset_ms")
        if sniff_ch is not None and sniff_ch != ch:
            m["label"] = "sniffer-blind"
        elif cut is None:
            m["label"] = "lost-nospec"
        elif res.get("quality") == "matched":
            m["label"] = "lost-with-burst"
        else:
            m["label"] = "lost-no-burst"
        if cut is not None:
            sid = f"per_{run.id}_{seq}"
            m["snippet"] = sid
            res = dict(res); res["snippet"] = sid; res["per_label"] = m["label"]
            meta = {"id": sid, "t": te, "kind": "PER lost: " + m["label"], "info": f"run {run.id} seq {seq} (expected time)",
                    "src": t.get("node") or "", "dst": t.get("dst") or "", "channel": ch, "freq_mhz": f,
                    "len": t.get("size"), "seq": seq, "per": {"run": run.id, "seq": seq, "label": m["label"],
                    "txpower": t.get("txpower"), "tx_t": t.get("tx_t"), "sniffer_channel": sniff_ch},
                    "spectrum": self.center_info()}
            save_async(os.path.join(self.snippets, sid + ".npz"), db, t0, t1, fr, te, meta, res)
        new = not os.path.exists(self.labels_path)
        try:
            with open(self.labels_path, "a", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                if new:
                    w.writerow(["run", "seq", "label", "expected_t", "tx_t", "channel", "sniffer_channel", "txpower",
                                "size", "excess_db", "burst_offset_ms", "snippet"])
                w.writerow([run.id, seq, m["label"], "%.4f" % te, t.get("tx_t", ""), ch, sniff_ch, t.get("txpower", ""),
                            t.get("size", ""), m["excess_db"], m["offset_ms"], m["snippet"] or ""])
        except OSError:
            pass
        return m

    def _write(self, run):
        try:
            rows = run.rows()
            p = os.path.join(self.dir, f"per_{run.id}_ledger.csv")
            with open(p, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["seq"])
                w.writeheader(); w.writerows(rows)
            with open(os.path.join(self.dir, f"per_{run.id}_summary.json"), "w", encoding="utf-8") as fh:
                json.dump(run.summary(), fh, indent=1)
        except (OSError, IndexError):
            pass

    # -------------------------------------------------- API
    def summaries(self):
        return sorted((r.summary() for r in self.runs.values()), key=lambda s: s["last"], reverse=True)

    def detail(self, rid):
        r = self.runs.get(rid)
        if r:
            return {"summary": r.summary(), "rows": r.rows()}
        p = os.path.join(self.dir, f"per_{rid}_ledger.csv")
        if os.path.isfile(p) and all(c.isalnum() or c in "-_" for c in rid):
            with open(p, encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            s = {}
            sp = os.path.join(self.dir, f"per_{rid}_summary.json")
            if os.path.isfile(sp):
                with open(sp, encoding="utf-8") as fh:
                    s = json.load(fh)
            return {"summary": s, "rows": rows}
        return None

    def archived(self):
        out = []
        for p in sorted(glob.glob(os.path.join(self.dir, "per_*_summary.json")), key=os.path.getmtime, reverse=True)[:100]:
            rid = os.path.basename(p)[4:-13]
            if rid in self.runs:
                continue
            try:
                with open(p, encoding="utf-8") as fh:
                    out.append(json.load(fh))
            except Exception:
                pass
        return out
