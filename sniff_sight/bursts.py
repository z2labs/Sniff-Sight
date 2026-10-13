"""RF burst detector, feature extraction and first rule-based classifier.

Runs in its own thread on every spectrum frame (ESP-SDR SPEC, ~4.5 ms per frame at 80 MHz span).
Per bin a slow noise floor is tracked; bins more than THR_DB above it form segments per frame;
segments that overlap in frequency in consecutive frames are tracked as one burst.  When a burst
ends its features are computed and it is classified:

  ieee802154      ~2 MHz wide, centre on the 2405 + 5(k-11) MHz grid (ch 11..26)
  ble             <= ~2.5 MHz, centre on an advertising channel (2402 / 2426 / 2480 MHz), short
  wifi            >= ~12 MHz, flat top (OFDM), centre on the 2412 + 5(k-1) MHz grid (ch 1..13)
  microwave_oven  wide-ish, non-flat, drifting / swept, upper band, ~50 Hz on/off (≈10 ms on / 10 ms off)
  unknown

Matched 802.15.4 packets (rfpair) are attached as ground truth.  Records go to
captures/bursts/bursts_YYYYMMDD.csv, a rate-limited subset of spectrum snippets to
captures/bursts/snips/burst_<id>.npz (rfpair snippet format, opens in the dashboard).
Time resolution is one spectrum frame (~4.5 ms): a 0.4 ms BLE advertisement is smeared over
a whole frame and its level diluted (mean detector) -> use the max detector for short bursts.
"""
import collections
import csv
import os
import queue
import threading
import time
from typing import Callable, Optional

import numpy as np

from . import rfpair

THR_DB = 8.0            # bin above floor
MIN_BINS_MHZ = 0.5      # minimum segment width
FLOOR_STEP = 0.25       # dB per frame for the percentile tracker
MERGE_GAP_MHZ = 1.0     # bridge gaps inside one emission
MAX_GAP_FRAMES = 1      # a burst may miss one frame
MAX_FRAMES = 400        # force-close very long emissions (~1.8 s)
FINALIZE_DELAY_S = 0.6
ASK_EVERY_S = 4.0       # at most one "What is this?" question per 4 s
LEGACY_LABELS = {"zaj": "noise", "mikr\u00f3": "microwave_oven", "mikro": "microwave_oven", "egy\u00e9b": "other", "egyeb": "other"}
USER_LABELS = ["ieee802154", "ble", "wifi", "microwave_oven", "noise", "other"]  # wait for packet pairing (ground truth) before classifying

CLASSES = ["ieee802154", "ble", "wifi", "microwave_oven", "unknown"]
ZB = np.array([2405.0 + 5 * (k - 11) for k in range(11, 27)])
BLE_ADV = np.array([2402.0, 2426.0, 2480.0])
WIFI = np.array([2412.0 + 5 * (k - 1) for k in range(1, 14)])

FIELDS = ["id", "t0", "t1", "duration_ms", "frames", "f_center_mhz", "f_lo_mhz", "f_hi_mhz", "bw10_mhz", "bw20_mhz", "f_mid20_mhz",
          "peak_excess_db", "mean_excess_db", "peak_dbfs", "floor_dbfs", "rise_ms", "fall_ms", "flatness",
          "occupied_bins", "symmetry", "drift_mhz_s", "drift_range_mhz", "ibi_ms", "ibi_med_ms", "ibi_std_ms",
          "cls", "confidence", "reason", "gt", "gt_pkt", "snippet"]


class _Burst:
    __slots__ = ("lo", "hi", "rows", "t0", "t1", "gap", "id")

    def __init__(self, lo, hi, t0, t1, row):
        self.lo, self.hi, self.t0, self.t1, self.gap = lo, hi, t0, t1, 0
        self.rows = [(t0, t1, lo, hi, row)]


class BurstEngine:
    def __init__(self, out_dir: str, on_burst: Callable[[dict], None], snip_per_class_min: int = 20):
        self.dir = out_dir
        self.snip_dir = os.path.join(out_dir, "snips")
        os.makedirs(self.snip_dir, exist_ok=True)
        self.on_burst = on_burst
        self.q: "queue.Queue" = queue.Queue(maxsize=4000)
        self.key = None
        self.floor = None
        self.active: list = []
        self.pending = collections.deque()          # closed bursts waiting for ground truth
        self.pkts = collections.deque(maxlen=500)   # (t, f_mhz, quality, id) from rfpair
        self.starts = collections.defaultdict(lambda: collections.deque(maxlen=40))   # 1 MHz cell -> start times
        self.counts = collections.Counter()
        self.recent = collections.deque(maxlen=300)
        self.window = collections.deque(maxlen=20000)   # (t, cls) for rates
        self.gt = collections.Counter()                 # (gt, cls)
        self.dropped = 0
        self.user_labels = collections.Counter()
        self.frames = 0
        self.seq = 0
        self.snip_budget = collections.defaultdict(lambda: [0.0, 0])
        self.snip_per_class_min = snip_per_class_min
        self._csv_day = None
        self._last_ask = 0.0
        self.labels_path = os.path.join(out_dir, "labels.csv")
        self._csv = None
        self._run = True
        self.th = threading.Thread(target=self._loop, daemon=True, name="bursts")
        self.th.start()

    # ------------------------------------------------ inputs (any thread)
    def feed(self, t0, t1, center_hz, span_hz, dbfs):
        try:
            self.q.put_nowait((t0, t1, center_hz, span_hz, dbfs))
        except queue.Full:
            self.dropped += 1

    def note_packet(self, t, f_mhz, quality, pid):
        self.pkts.append((t, f_mhz, quality, pid))

    def stop(self):
        self._run = False

    # ------------------------------------------------ worker
    def _loop(self):
        while self._run:
            try:
                item = self.q.get(timeout=0.2)
            except queue.Empty:
                self._finalize(time.time())
                continue
            try:
                self._frame(*item)
            except Exception as e:
                print("[bursts] frame error", repr(e), flush=True)
            if self.frames % 20 == 0:
                self._finalize(time.time())

    def _frame(self, t0, t1, center_hz, span_hz, dbfs):
        db = np.maximum(np.asarray(dbfs, dtype=np.float32), -125.0)
        n = db.size
        key = (round(center_hz), round(span_hz), n)
        if key != self.key:                       # retune: reset everything
            self.key = key
            self.freqs = (center_hz + (np.arange(n) - n / 2) * span_hz / n) / 1e6
            self.df = span_hz / n / 1e6
            self.kern = np.ones(5) / 5
            self.kern_wide = np.ones(15) / 15
            self.floor = db.copy()
            self.active = []
            self.minb = max(2, int(MIN_BINS_MHZ / self.df))
            self.gapb = max(1, int(MERGE_GAP_MHZ / self.df))
            self.edge = max(2, int(0.02 * n))         # ignore the outer 2 % (filter roll-off)
            self.n_warm = 0
        self.frames += 1
        # noise floor: per-bin 20th-percentile tracker (robust to bursts and to single deep bins)
        dbs = np.convolve(db, self.kern, mode="same")
        dbs[:2] = db[:2]; dbs[-2:] = db[-2:]
        self.floor += np.where(dbs < self.floor, -0.8 * FLOOR_STEP, 0.2 * FLOOR_STEP)
        if self.n_warm < 50:
            self.floor += 0.2 * (np.minimum(dbs, self.floor + 3) - self.floor)
        fl = np.convolve(self.floor, self.kern_wide, mode="same")
        fl[:8] = self.floor[:8]; fl[-8:] = self.floor[-8:]
        exc = dbs - fl
        self.n_warm += 1
        if self.n_warm < 50:
            return
        hot = exc > THR_DB
        hot[:self.edge] = False
        hot[-self.edge:] = False
        # segments with small gaps bridged
        idx = np.flatnonzero(hot)
        segs = []
        if idx.size:
            br = np.flatnonzero(np.diff(idx) > self.gapb)
            starts = np.r_[idx[0], idx[br + 1]]
            ends = np.r_[idx[br], idx[-1]]
            segs = [(a, b) for a, b in zip(starts, ends) if b - a + 1 >= self.minb]
        used = set()
        for bst in self.active:
            hit = None
            for k, (a, b) in enumerate(segs):
                if k not in used and a <= bst.hi + self.gapb and b >= bst.lo - self.gapb:
                    hit = k
                    break
            if hit is None:
                bst.gap += 1
                continue
            used.add(hit)
            a, b = segs[hit]
            bst.lo, bst.hi = min(bst.lo, a), max(bst.hi, b)
            bst.t1, bst.gap = t1, 0
            bst.rows.append((t0, t1, a, b, exc.copy()))
        for k, (a, b) in enumerate(segs):
            if k not in used:
                self.active.append(_Burst(a, b, t0, t1, exc.copy()))
        still = []
        for bst in self.active:
            if bst.gap > MAX_GAP_FRAMES or len(bst.rows) >= MAX_FRAMES:
                self.pending.append((time.time(), bst, self.floor.copy(), self.freqs, self.df))
            else:
                still.append(bst)
        self.active = still

    # ------------------------------------------------ features + class
    def _finalize(self, now):
        while self.pending and now - self.pending[0][0] >= FINALIZE_DELAY_S:
            _, bst, floor, freqs, df = self.pending.popleft()
            try:
                rec, cut = self._features(bst, floor, freqs, df)
                self._classify(rec)
                self._emit(rec, bst, cut, freqs, floor)
            except Exception as e:
                print("[bursts] finalize error", repr(e), flush=True)

    def _features(self, bst, floor, freqs, df):
        pad = max(3, int(3.0 / df))
        lo, hi = max(0, bst.lo - pad), min(freqs.size, bst.hi + pad + 1)
        E = np.array([r[4][lo:hi] for r in bst.rows])                  # excess dB, frames x bins
        F = freqs[lo:hi]
        t0s = np.array([r[0] for r in bst.rows]); t1s = np.array([r[1] for r in bst.rows])
        lin = 10 ** (E / 10.0)
        mx = E.max(axis=0)                                               # max-hold over the burst
        pk = float(mx.max()); j = int(mx.argmax())
        def width(level):
            m = mx >= pk - level
            a = j
            while a > 0 and m[a - 1]:
                a -= 1
            b = j
            while b < m.size - 1 and m[b + 1]:
                b += 1
            return (b - a + 1) * df, a, b
        bw10, a10, b10 = width(10.0)
        bw20, a20, b20 = width(20.0)
        f_mid20 = float(0.5 * (F[a20] + F[b20]))
        p = 10 ** (mx[a10:b10 + 1] / 10.0)
        flat = float(np.exp(np.mean(np.log(p + 1e-12))) / (np.mean(p) + 1e-12))
        w = 10 ** (mx / 10.0); w = np.where(mx >= pk - 10.0, w, 0)       # centroid of the -10 dB core only
        fc = float((F * w).sum() / w.sum()) if w.sum() > 0 else float(F[j])
        left = w[F < fc].sum(); right = w[F > fc].sum()
        sym = float((left - right) / (left + right)) if left + right > 0 else 0.0
        # per-frame centroid -> drift
        cents = []
        for i in range(E.shape[0]):
            wi = np.where(E[i] >= max(THR_DB, E[i].max() - 10.0), lin[i], 0)
            cents.append((F * wi).sum() / wi.sum() if wi.sum() > 0 else np.nan)
        cents = np.array(cents); ok = ~np.isnan(cents)
        tc = 0.5 * (t0s + t1s)
        drift = float(np.polyfit(tc[ok] - tc[0], cents[ok], 1)[0]) if ok.sum() >= 3 else 0.0
        drange = float(np.nanmax(cents) - np.nanmin(cents)) if ok.any() else 0.0
        band = (mx >= pk - 10)
        lvl = np.array([10 * np.log10(lin[i, band].mean() + 1e-12) for i in range(E.shape[0])])
        ip = int(lvl.argmax())
        dt = float(np.median(t1s - t0s)) if t1s.size else 0.0045
        rise = ip * dt * 1e3
        fall = (lvl.size - 1 - ip) * dt * 1e3
        cell = int(round(fc))
        st = self.starts[cell]
        ibi = (bst.rows[0][0] - st[-1]) * 1e3 if st else None
        st.append(bst.rows[0][0])
        iv = np.diff(np.array(st)) * 1e3 if len(st) >= 3 else np.array([])
        iv = iv[iv < 2000]
        self.seq += 1
        rec = {"id": "%d_%05d" % (int(bst.t0), self.seq % 100000), "t0": round(bst.t0, 4), "t1": round(bst.t1, 4),
               "duration_ms": round((bst.t1 - bst.t0) * 1e3, 2), "frames": len(bst.rows),
               "f_center_mhz": round(fc, 3), "f_lo_mhz": round(float(freqs[bst.lo]), 3), "f_hi_mhz": round(float(freqs[bst.hi]), 3),
               "bw10_mhz": round(bw10, 3), "bw20_mhz": round(bw20, 3), "f_mid20_mhz": round(f_mid20, 3), "peak_excess_db": round(pk, 1),
               "mean_excess_db": round(float(10 * np.log10(lin[:, band].mean() + 1e-12)), 1),
               "peak_dbfs": round(float(floor[lo:hi][j] + pk), 1), "floor_dbfs": round(float(np.median(floor[lo:hi])), 1),
               "rise_ms": round(rise, 2), "fall_ms": round(fall, 2), "flatness": round(flat, 3),
               "occupied_bins": int((mx > THR_DB).sum()), "symmetry": round(sym, 3),
               "drift_mhz_s": round(drift, 1), "drift_range_mhz": round(drange, 3),
               "ibi_ms": round(ibi, 1) if ibi is not None else None,
               "ibi_med_ms": round(float(np.median(iv)), 1) if iv.size else None,
               "ibi_std_ms": round(float(np.std(iv)), 1) if iv.size else None,
               "gt": None, "gt_pkt": None, "snippet": None}
        # ground truth: a matched 802.15.4 packet inside the burst (+-6 ms) on the same channel
        for (t, f, q, pid) in self.pkts:
            if q == "matched" and bst.t0 - 0.006 <= t <= bst.t1 + 0.006 and abs(f - fc) < 1.5:
                rec["gt"], rec["gt_pkt"] = "ieee802154", pid
                break
        return rec, (E, F, t0s, t1s)

    @staticmethod
    def _classify(r):
        fc, bw, bw20, flat, dur = r["f_center_mhz"], r["bw10_mhz"], r["bw20_mhz"], r["flatness"], r["duration_ms"]
        fm = r["f_mid20_mhz"]
        dz = float(np.abs(ZB - fc).min()); db_ = float(np.abs(BLE_ADV - fc).min())
        dw = float(min(np.abs(WIFI - fm).min(), np.abs(WIFI - fc).min()))
        per, drng = r["ibi_med_ms"], r["drift_range_mhz"]
        mw_period = per is not None and 14 <= per <= 24 and (r["ibi_std_ms"] or 99) < 4
        cls, conf, why = "unknown", 0.2, "no rule"
        if bw20 >= 9 and dw <= 3.0 and not mw_period:
            cls, conf, why = "wifi", 0.45 + min(0.3, 0.02 * (bw20 - 9)) + (0.15 if flat >= 0.85 else 0), "wide (-20 dB >= 9 MHz) on Wi-Fi grid"
        elif bw20 >= 4 and fc >= 2430 and (mw_period or (drng >= 3.0 and dw > 3.0)):
            cls, conf, why = "microwave_oven", 0.35 + (0.35 if mw_period else 0) + (0.15 if drng >= 2 else 0), \
                "wide drifting upper band" + (", ~50 Hz period" if mw_period else "")
        elif (bw <= 3.5 and dz <= 0.7 and dz <= db_) or (1.2 <= bw <= 3.5 and dz <= 1.2):   # BLE is ~1 MHz wide
            cls, conf, why = "ieee802154", 0.5 + (0.2 if 1.0 <= bw <= 3.0 else 0) + (0.15 if dz <= 0.3 else 0), "~2 MHz on 15.4 grid"
        elif bw <= 3.0 and db_ <= 0.7 and dur <= 15:
            cls, conf, why = "ble", 0.4 + (0.2 if dur <= 6 else 0) + (0.15 if db_ <= 0.3 else 0), "narrow short on BLE adv ch"
        if r["gt"]:
            if cls == "ieee802154":
                conf = 0.99
                why += " | confirmed by sniffer packet"
            else:
                why += " | GT says 802.15.4"
        r["cls"], r["confidence"], r["reason"] = cls, round(min(conf, 0.99), 2), why

    def _emit(self, rec, bst, cut, freqs, floor):
        now = time.time()
        cls = rec["cls"]
        self.counts[cls] += 1
        self.window.append((now, cls))
        if rec["gt"]:
            self.gt[(rec["gt"], cls)] += 1
        # snippet budget per class per minute (+ always ground-truth disagreements)
        b = self.snip_budget[cls]
        if now - b[0] > 60:
            b[0], b[1] = now, 0
        # active learning: ask the user about low-confidence bursts (rate limited, snippet saved now,
        # because the spectrum ring only holds ~10 s)
        rec["ask"] = bool((cls == "unknown" or rec["confidence"] < 0.45 or (rec["gt"] and cls != rec["gt"]))
                          and rec["peak_excess_db"] >= 12 and now - self._last_ask >= ASK_EVERY_S)
        if rec["ask"]:
            self._last_ask = now
        if rec["ask"] or b[1] < self.snip_per_class_min or (rec["gt"] and cls != rec["gt"]):
            b[1] += 1
            E, F, t0s, t1s = cut
            sid = "burst_" + rec["id"]
            rec["snippet"] = sid
            tm = 0.5 * (bst.t0 + bst.t1)
            fl = np.median(floor)
            meta = {"id": sid, "t": tm, "kind": "burst: %s (%.2f)" % (cls, rec["confidence"]), "info": rec["reason"],
                    "src": "", "dst": "", "channel": None, "freq_mhz": rec["f_center_mhz"], "len": None, "burst": rec}
            res = {"quality": "burst", "floor_dbfs": round(float(fl), 1), "noise_sigma_db": 0, "per_label": cls,
                   "offset_ms": 0.0, "peak_dbfs": rec["peak_dbfs"], "excess_db": rec["peak_excess_db"],
                   "burst_t0_ms": round((bst.t0 - tm) * 1e3, 1), "burst_t1_ms": round((bst.t1 - tm) * 1e3, 1)}
            try:
                rfpair.save(os.path.join(self.snip_dir, sid + ".npz"), E + fl, t0s, t1s, F, tm, meta, res)
            except Exception as e:
                print("[bursts] snippet error", repr(e), flush=True)
        self._write(rec)
        self.recent.append(rec)
        self.on_burst(rec)

    def _write(self, rec):
        day = time.strftime("%Y%m%d")
        if day != self._csv_day:
            if self._csv:
                self._csv.close()
            p = os.path.join(self.dir, "bursts_%s.csv" % day)
            k = 1
            while os.path.exists(p):                     # never append rows to a file with another header
                with open(p, encoding="utf-8") as fh:
                    if fh.readline().strip() == ",".join(FIELDS):
                        break
                k += 1
                p = os.path.join(self.dir, "bursts_%s_%d.csv" % (day, k))
            new = not os.path.exists(p)
            self._csv = open(p, "a", newline="", encoding="utf-8")
            self._w = csv.DictWriter(self._csv, fieldnames=FIELDS, extrasaction="ignore")
            if new:
                self._w.writeheader()
            self._csv_day = day
        self._w.writerow(rec)
        self._csv.flush()

    def find(self, bid):
        for r in reversed(self.recent):
            if r["id"] == bid:
                return r
        p = os.path.join(self.snip_dir, "burst_%s.npz" % bid)
        if os.path.isfile(p):
            try:
                return rfpair.load(p)["meta"].get("burst")
            except Exception:
                return None
        return None

    def add_label(self, bid: str, label: str, text: str = "") -> dict:
        rec = self.find(bid)
        if rec is None:
            raise KeyError(bid)
        label = LEGACY_LABELS.get((label or "").strip().lower(), label)   # old Hungarian UI labels -> stable English keys
        row = {"labelled_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "id": bid, "label": label, "text": text,
               "model_cls": rec.get("cls"), "model_conf": rec.get("confidence")}
        row.update({k: rec.get(k) for k in FIELDS if k not in ("id", "cls", "confidence")})
        new = not os.path.exists(self.labels_path)
        with open(self.labels_path, "a", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(row.keys()))
            if new:
                w.writeheader()
            w.writerow(row)
        rec["user_label"] = label
        self.user_labels[label] += 1
        return row

    # ------------------------------------------------ stats
    def stats(self):
        now = time.time()
        last60 = collections.Counter(c for t, c in self.window if now - t <= 60)
        gt = {}
        for (g, c), v in self.gt.items():
            gt.setdefault(g, {})[c] = v
        return {"type": "burst_stats", "total": dict(self.counts), "last60": dict(last60), "ground_truth": gt,
                "frames": self.frames, "dropped": self.dropped, "queue": self.q.qsize(), "user_labels": dict(self.user_labels)}
