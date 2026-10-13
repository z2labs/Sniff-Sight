"""Packet <-> RF burst pairing.

FrameClock  maps the firmware sample index of each SPC1 frame to host time
            (time.time(), the same clock the sniffer stamps packets with).
SpecRing    keeps the last ~10 s of spectrum frames (int16, 0.1 dB steps).
cut()/pair() take a +-4 MHz / +-100 ms snippet around a packet and find
            the burst nearest the packet time in its 2 MHz channel band.
"""
import collections
import json
import os
import time
from typing import Optional

import numpy as np


class FrameClock:
    """Device time = sample_index / sample_rate.  Host arrival = device end time
    + transport latency (USB/serial/asyncio, always >= 0, jittery).  The offset
    estimate is the minimum of (arrival - device end) over a sliding window:
    the frames that arrived fastest define it, which removes most jitter and
    still follows slow crystal drift."""

    def __init__(self, window_s: float = 4.0):
        self.window_s = window_s
        self.reset(0)

    def reset(self, rate):
        self.rate = float(rate)
        self.last_idx = None
        self.win = collections.deque()      # (arrival, offset)
        self.offset = None
        self.frames = 0
        self.resets = getattr(self, "resets", -1) + 1
        self.fallback = False
        self.last_arr = None
        self.period = None
        self.jitter_ms = None

    def update(self, idx: int, spanned: int, rate: float, t_arr: float):
        """Return (t_start, t_end) of the frame in host time."""
        if rate != self.rate or (self.last_idx is not None and idx <= self.last_idx):
            self.reset(rate)
        if self.last_arr is not None:
            d = t_arr - self.last_arr
            self.period = d if self.period is None else 0.98 * self.period + 0.02 * d
        self.last_arr = t_arr
        dur = (spanned / rate) if (spanned and rate) else (self.period or 0.0)
        if not rate or (idx == 0 and self.last_idx in (None, 0) and self.frames > 3):
            self.fallback = True                 # no usable sample index
            self.frames += 1
            return t_arr - dur, t_arr
        self.last_idx = idx
        dev_end = (idx + spanned) / rate
        off = t_arr - dev_end
        self.win.append((t_arr, off))
        while self.win and t_arr - self.win[0][0] > self.window_s:
            self.win.popleft()
        self.offset = min(o for _, o in self.win)
        self.jitter_ms = (off - self.offset) * 1e3
        self.frames += 1
        return idx / rate + self.offset, dev_end + self.offset

    def info(self):
        return {"frames": self.frames, "resets": self.resets, "fallback": self.fallback,
                "frame_ms": round(self.period * 1e3, 2) if self.period else None,
                "latency_jitter_ms": round(self.jitter_ms, 2) if self.jitter_ms is not None else None}


class SpecRing:
    def __init__(self, seconds: float = 10.0, max_frames: int = 4096):
        self.seconds, self.max_frames = seconds, max_frames
        self.key = None
        self.n = 0
        self.lock = None

    def configure(self, center_hz: float, span_hz: float, n: int, fps_hint: float = 100.0):
        key = (round(center_hz), round(span_hz), n)
        if key == self.key:
            return
        self.key, self.n = key, n
        self.center_hz, self.span_hz = center_hz, span_hz
        cap = int(min(self.max_frames, max(256, self.seconds * fps_hint * 1.5)))
        self.cap = cap
        self.db = np.full((cap, n), -1400, dtype=np.int16)
        self.t0 = np.zeros(cap)
        self.t1 = np.zeros(cap)
        self.count = 0          # total frames written
        self.freqs = (center_hz + (np.arange(n) - n / 2) * span_hz / n) / 1e6

    def add(self, t0: float, t1: float, dbfs):
        i = self.count % self.cap
        self.db[i] = np.clip(np.rint(np.asarray(dbfs, dtype=np.float32) * 10), -32000, 32000)
        self.t0[i], self.t1[i] = t0, t1
        self.count += 1
        # grow the capacity if 10 s does not fit (fast frame rates)
        if self.count == self.cap and self.cap < self.max_frames:
            span_s = self.t1[self.cap - 1] - self.t0[0]
            if span_s < self.seconds:
                new = int(min(self.max_frames, self.cap * self.seconds / max(span_s, 1e-3) * 1.2))
                self.db = np.concatenate([self.db, np.full((new - self.cap, self.n), -1400, np.int16)])
                self.t0 = np.concatenate([self.t0, np.zeros(new - self.cap)])
                self.t1 = np.concatenate([self.t1, np.zeros(new - self.cap)])
                self.cap = new

    def newest(self) -> float:
        if not self.count:
            return 0.0
        return float(self.t1[(self.count - 1) % self.cap])

    def oldest(self) -> float:
        if not self.count:
            return 0.0
        return float(self.t0[0 if self.count < self.cap else self.count % self.cap])

    def cut(self, t_center: float, half_s: float, f_mhz: float, half_mhz: float):
        """Frames overlapping [t-half, t+half], bins within f +- half_mhz.
        Returns (db float32 [k, m], t0 [k], t1 [k], freqs [m]) or None."""
        if not self.count or self.n == 0:
            return None
        m = (self.freqs >= f_mhz - half_mhz) & (self.freqs <= f_mhz + half_mhz)
        if m.sum() < 3:
            return None
        k = min(self.count, self.cap)
        order = (np.arange(k) + (self.count - k)) % self.cap
        t0, t1 = self.t0[order], self.t1[order]
        sel = (t1 >= t_center - half_s) & (t0 <= t_center + half_s)
        if sel.sum() < 2:
            return None
        rows = order[sel]
        return (self.db[rows][:, m].astype(np.float32) / 10.0, t0[sel].copy(), t1[sel].copy(), self.freqs[m].copy())


def band_level(db, freqs, f_ch, half_bw=1.0):
    """Mean power (dBFS) per frame inside the channel's 2 MHz."""
    b = np.abs(freqs - f_ch) <= half_bw
    p = 10 ** (db[:, b] / 10.0)
    return 10 * np.log10(p.mean(axis=1) + 1e-30)


def pair(db, t0, t1, freqs, f_ch, t_pkt, weak_db=3.0, match_db=6.0, match_window_s=0.05):
    lvl = band_level(db, freqs, f_ch)
    tc = 0.5 * (t0 + t1)
    floor = float(np.median(lvl))
    mad = float(np.median(np.abs(lvl - floor))) * 1.4826
    exc = lvl - floor
    thr = max(weak_db, 3 * mad)
    res = {"floor_dbfs": round(floor, 1), "noise_sigma_db": round(mad, 2), "frames": int(len(lvl)),
           "quality": "none", "offset_ms": None, "peak_dbfs": None, "excess_db": None, "burst_frames": 0}
    hot = exc >= thr
    if not hot.any():
        j = int(np.argmax(exc))
        res.update(peak_dbfs=round(float(lvl[j]), 1), excess_db=round(float(exc[j]), 1))
        return res
    # group contiguous hot frames into bursts; peak of each burst
    bursts, i = [], 0
    while i < len(hot):
        if hot[i]:
            j = i
            while j + 1 < len(hot) and hot[j + 1]:
                j += 1
            pk = i + int(np.argmax(exc[i:j + 1]))
            # distance: 0 if the packet time lies inside the burst
            d = 0.0 if t0[i] <= t_pkt <= t1[j] else min(abs(t0[i] - t_pkt), abs(t1[j] - t_pkt))
            bursts.append((d, -exc[pk], pk, i, j))
            i = j + 1
        else:
            i += 1
    d, _, pk, i, j = min(bursts)
    e = float(exc[pk])
    q = "matched" if (e >= max(match_db, thr) and d <= match_window_s) else "weak"
    res.update(quality=q, offset_ms=round((tc[pk] - t_pkt) * 1e3, 1), peak_dbfs=round(float(lvl[pk]), 1),
               excess_db=round(e, 1), burst_frames=int(j - i + 1), burst_index=int(pk),
               burst_t0_ms=round((t0[i] - t_pkt) * 1e3, 1), burst_t1_ms=round((t1[j] - t_pkt) * 1e3, 1),
               bursts_in_snippet=len(bursts))
    return res


def save(path, db, t0, t1, freqs, t_pkt, meta: dict, result: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp.npz"
    np.savez_compressed(tmp, db=db.astype(np.float32), freqs_mhz=freqs, t0_s=t0 - t_pkt, t1_s=t1 - t_pkt,
                        times_s=0.5 * (t0 + t1) - t_pkt, t_packet=np.float64(t_pkt),
                        meta=json.dumps(meta), pair=json.dumps(result))
    os.replace(tmp, path)


def load(path) -> dict:
    with np.load(path, allow_pickle=False) as z:
        return {"db": np.round(z["db"], 1).tolist(), "freqs_mhz": np.round(z["freqs_mhz"], 4).tolist(),
                "t0_ms": np.round(z["t0_s"] * 1e3, 2).tolist(), "t1_ms": np.round(z["t1_s"] * 1e3, 2).tolist(),
                "t_packet": float(z["t_packet"]), "meta": json.loads(str(z["meta"])), "pair": json.loads(str(z["pair"]))}
