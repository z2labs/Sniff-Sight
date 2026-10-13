"""Local web dashboard for Sniff-Sight: live ESP32-S3 (ESP-SDR) spectrum.

Protocol handling follows z2-web-sdr (primary reference) and
sdrpp-esp-sdr-source: GAIN MANUAL (hardware AGC off), BANDWIDTH 0 above
16 MS/s, DC 0 with the centre bin filled, SPEC profile from SPECINFO?, bins
fftshifted + mirrored, dBFS = code/step - 84.3. On exit: BANDWIDTH 20, DC 1.

Env vars (defaults as in z2-web-sdr):
  SNIFF_PORT=COM7  SNIFF_BAUD=115200  SNIFF_FREQ_MHZ=2437  SNIFF_SPAN=80000000
  SNIFF_BINS=2048  SNIFF_GAIN=60 (0..82)  SNIFF_MAXHOLD=0  SNIFF_DCFIX=1
  SNIFF_PPM=0  SNIFF_PUSH_HZ=30  SNIFF_NO_SERIAL=1 (run without the device)
  SNIFF_DEMO=1 (serve the canned-data demo player, see --demo)
Gain, centre, span, bins and max hold can also be changed from the page.
"""

import asyncio
import base64
import struct
import json
import threading

import numpy as np
import collections
import os
import time
from contextlib import asynccontextmanager
from typing import Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse

from .esp32_sdr import ESP32SDR, FMIN, FMAX
from .paths import DEFAULT_CAPTURES
from .thread_sniffer import ThreadSniffer, channel_mhz
from . import rfpair
from .per import PerTracker
from .bursts import BurstEngine

PORT = os.environ.get("SNIFF_PORT", "COM7")
BAUD = int(os.environ.get("SNIFF_BAUD", "115200"))
PUSH_HZ = float(os.environ.get("SNIFF_PUSH_HZ", "60"))
WS_JSON = os.environ.get("SNIFF_WS_JSON") == "1"   # legacy JSON spectra (for comparison)
LITE_HZ = float(os.environ.get("SNIFF_LITE_HZ", "25"))       # light stream: max-hold frames per second
RETUNE_MIN_S = 0.35   # SPEC has no in-stream retune: at most one stop/FREQ/FOFS/SPEC per 350 ms, newest centre wins
LITE_BINS = int(os.environ.get("SNIFF_LITE_BINS", "512"))    # light stream: max-pooled bins
CAPTURES = os.environ.get("SNIFF_CAPTURES", DEFAULT_CAPTURES)
SNIPPETS = os.path.join(CAPTURES, "snippets")
BURSTS = os.path.join(CAPTURES, "bursts")
SNIP_HALF_MHZ = 4.0
SNIP_HALF_S = 0.100


def _env_settings() -> dict:
    return {
        "freq_hz": float(os.environ.get("SNIFF_FREQ_MHZ", "2437")) * 1e6,
        "span": int(os.environ.get("SNIFF_SPAN", "80000000")),
        "bins": int(os.environ.get("SNIFF_BINS", "2048")),
        "gain": max(0, min(82, int(os.environ.get("SNIFF_GAIN", "60")))),
        "max_hold": os.environ.get("SNIFF_MAXHOLD", "0") == "1",
        "dc_fix": os.environ.get("SNIFF_DCFIX", "1") == "1",
        "ppm": float(os.environ.get("SNIFF_PPM", "0")),
    }


class SpectrumHub:
    def __init__(self):
        self.clients: Set[WebSocket] = set()
        self.lite: Set[WebSocket] = set()          # clients that get the light spectrum stream
        self.lite_acc = None
        self.lite_last = 0.0
        self.lite_pts = {}   # ws -> wanted points (light stream)
        self.perf = collections.Counter()
        self.bytes_out = collections.Counter()      # "full" / "lite" spectrum bytes sent
        self.settings = _env_settings()
        self.status = {"type": "status", "port": PORT, "state": "idle"}
        self.sdr: Optional[ESP32SDR] = None
        self.task: Optional[asyncio.Task] = None
        self.restart = asyncio.Event()
        self.clock = rfpair.FrameClock()
        self.ring = rfpair.SpecRing(10.0)
        self.bursts: Optional[BurstEngine] = None
        self.loop = None
        self._burst_sent = [0.0, 0]
        self.last_tune = 0.0            # monotonic time of the last SPEC (re)start
        self.released = False           # COM port handed to the browser flasher
        self._release_timer = None

    def _on_burst(self, rec):          # bursts thread
        if self.loop:
            self.loop.call_soon_threadsafe(self._send_burst, rec)

    def _send_burst(self, rec):
        now = time.monotonic()
        if now - self._burst_sent[0] > 1.0:
            self._burst_sent = [now, 0]
        self._burst_sent[1] += 1
        if self._burst_sent[1] > 150:   # cap the websocket load
            return
        asyncio.ensure_future(self.broadcast({"type": "burst", **{k: rec[k] for k in (
            "id", "t0", "t1", "f_lo_mhz", "f_hi_mhz", "f_center_mhz", "bw10_mhz", "duration_ms", "peak_excess_db",
            "cls", "confidence", "gt", "snippet", "reason", "drift_range_mhz", "flatness", "ibi_med_ms", "ask", "bw20_mhz")}}))

    async def broadcast(self, msg: dict):
        for ws in list(self.clients):
            try:
                await ws.send_json(msg)
            except Exception:
                self.clients.discard(ws)

    async def set_status(self, **kw):
        self.status.update(kw)
        await self.broadcast(self.status)

    def update(self, msg: dict):
        s = dict(self.settings)
        if "gain" in msg:
            s["gain"] = max(0, min(82, int(msg["gain"])))
        if "freq_mhz" in msg:
            s["freq_hz"] = max(FMIN, min(FMAX, float(msg["freq_mhz"]) * 1e6))
        if "span" in msg and int(msg["span"]) in (16_000_000, 40_000_000, 80_000_000):
            s["span"] = int(msg["span"])
        if "bins" in msg and int(msg["bins"]) in (256, 512, 1024, 2048, 4096):
            s["bins"] = int(msg["bins"])
        if "max_hold" in msg:
            s["max_hold"] = bool(msg["max_hold"])
        if s != self.settings:
            self.settings = s
            self.restart.set()

    async def run(self):
        while True:
            try:
                await self.set_status(state="connecting", error=None)
                self.sdr = ESP32SDR(PORT, BAUD)
                await self.sdr.connect()
                hs = await self.sdr.handshake()
                await self.set_status(info=hs.get("info"), version=hs.get("version"), specinfo=hs.get("specinfo"))
                while True:
                    s = dict(self.settings)
                    self.restart.clear()
                    self.last_tune = time.monotonic()
                    reply = await self.sdr.start_spectrum(**s)
                    if reply.startswith("SPEC "):   # firmware may have fallen back (e.g. 4096 -> 2048)
                        try:
                            s["bins"] = int(reply.split()[1])
                        except ValueError:
                            pass
                    # reply: SPEC <bins> <sample_rate_hz> <unit_pairs> <MHz>
                    await self.set_status(state="streaming", spec=reply, settings=self._pub(s),
                                          center_hz=self.sdr.spec_center_hz, span_hz=s["span"])
                    pump = asyncio.create_task(self._pump(s))
                    waiter = asyncio.create_task(self._restart_due())
                    done, _ = await asyncio.wait({pump, waiter}, return_when=asyncio.FIRST_COMPLETED)
                    for t in (pump, waiter):
                        t.cancel()
                    for t in (pump, waiter):
                        try:
                            await t
                        except (asyncio.CancelledError, Exception):
                            if t in done and t is pump and t.exception():
                                raise t.exception()
                    await self.sdr.stop_stream()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                await self.set_status(state="error", error=f"{type(e).__name__}: {e}")
            finally:
                await self._close()
            await asyncio.sleep(2)

    async def _restart_due(self):
        """Settings changed. The firmware cannot retune inside a SPEC run, so a retune is
        newline -> SPECEND -> FREQ/FOFS -> SPEC. Keep streaming until RETUNE_MIN_S after the
        previous start; the loop then applies the newest settings (intermediate drag centres
        are dropped, the final one is always applied)."""
        await self.restart.wait()
        await asyncio.sleep(max(0.0, self.last_tune + RETUNE_MIN_S - time.monotonic()))

    async def release(self, timeout: float = 180.0):
        """Stop streaming and close the SDR port (for the Web Serial flasher)."""
        self.released = True
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):
                pass
            self.task = None
        await self._close()
        await self.set_status(state="released", error=None, spec=None)
        if self._release_timer:
            self._release_timer.cancel()
        # safety net: a closed browser tab must not leave the spectrum off for good
        self._release_timer = asyncio.get_running_loop().call_later(timeout, lambda: asyncio.ensure_future(self.reconnect()))

    async def reconnect(self):
        if self._release_timer:
            self._release_timer.cancel()
            self._release_timer = None
        self.released = False
        if os.environ.get("SNIFF_NO_SERIAL") != "1" and (not self.task or self.task.done()):
            self.task = asyncio.create_task(self.run())

    @staticmethod
    def _pub(s):
        return {"freq_mhz": s["freq_hz"] / 1e6, "span": s["span"], "bins": s["bins"],
                "gain": s["gain"], "max_hold": s["max_hold"], "dc_fix": s["dc_fix"]}

    @staticmethod
    def _binmsg(meta: dict, payload: bytes) -> bytes:
        """binary spectrum: u32 len | JSON meta (space-padded to even) | quantised dB"""
        mb = json.dumps(meta).encode()
        mb += b" " * ((-(4 + len(mb))) % 2)
        return struct.pack("<I", len(mb)) + mb + payload

    async def _pump(self, s):
        period = 1.0 / PUSH_HZ
        last_push = 0.0
        last_seq = None
        gaps = 0
        t_rate, f_rate, rate = time.monotonic(), 0, 0.0
        pf = self.perf
        t_wait = time.perf_counter()
        async for sp in self.sdr.read_spectra_dbfs():
            _t0 = time.perf_counter(); pf["wait_ms"] += (_t0 - t_wait) * 1e3
            if sp.n != s["bins"]:
                t_wait = time.perf_counter()
                continue
            pf["frames"] += 1
            if sp.t_arrival - pf.get("_last_arr", 0) > 0.002:
                pf["batches"] += 1
            pf["_last_arr"] = sp.t_arrival
            f_rate += 1
            if last_seq is not None and sp.sequence != (last_seq + 1) & 0xFFFFFFFF:
                gaps += 1
            last_seq = sp.sequence
            t0, t1 = self.clock.update(sp.sample_index, sp.spanned, float(s["span"]), sp.t_arrival)
            self.ring.configure(self.sdr.spec_center_hz, s["span"], sp.n, max(rate, 50.0))
            self.ring.add(t0, t1, sp.dbfs)
            if self.bursts:
                self.bursts.feed(t0, t1, self.sdr.spec_center_hz, s["span"], sp.dbfs)
            _t1 = time.perf_counter(); pf["proc_ms"] += (_t1 - _t0) * 1e3
            now = time.monotonic()
            if now - t_rate >= 1.0:
                rate, t_rate, f_rate = f_rate / (now - t_rate), now, 0
            db_np = np.asarray(sp.dbfs, dtype=np.float32)
            if self.lite:
                self.lite_acc = db_np.copy() if self.lite_acc is None or self.lite_acc.size != db_np.size else np.maximum(self.lite_acc, db_np)
                if now >= self.lite_last:
                    self.lite_last = max(self.lite_last + 1.0 / LITE_HZ, now - 1.0 / LITE_HZ)
                    acc, self.lite_acc = self.lite_acc, None
                    meta = {"type": "spec", "lite": 1, "seq": sp.sequence, "drops": sp.drops, "ffts": sp.ffts,
                            "frame_ms": round(sp.spanned / s["span"] * 1e3, 3), "gain": sp.gain, "fps": round(rate, 1),
                            "gaps": gaps, "crc_errors": self.sdr.crc_errors, "center_hz": self.sdr.spec_center_hz,
                            "span_hz": s["span"], "n_full": int(acc.size), "t": t1, "clock": self.clock.info(), "enc": "u8"}
                    cache = {}
                    for ws in list(self.lite):
                        k = max(1, acc.size // max(16, int(self.lite_pts.get(ws, LITE_BINS))))   # never coarser than the screen needs
                        if k not in cache:
                            pooled = acc[: acc.size // k * k].reshape(-1, k).max(axis=1) if k > 1 else acc
                            q = np.clip(np.rint((pooled + 140.0) * 2), 0, 255).astype(np.uint8)
                            cache[k] = self._binmsg(dict(meta, n=int(q.size)), q.tobytes())
                        msg = cache[k]
                        try:
                            await ws.send_bytes(msg)
                            self.bytes_out["lite"] += len(msg); pf["lite_msgs"] += 1
                        except Exception:
                            self.lite.discard(ws); self.clients.discard(ws)
            full = [ws for ws in self.clients if ws not in self.lite]
            if full and now >= last_push:   # newest spectrum; the page averages. Tick schedule (not "now + period"):
                last_push = max(last_push + period, now - period)   # frames arrive in USB/poll clumps, this keeps the mean rate
                meta = {"type": "spec", "seq": sp.sequence, "gain": sp.gain, "drops": sp.drops,
                        "ffts": sp.ffts, "frame_ms": round(sp.spanned / s["span"] * 1e3, 3), "fps": round(rate, 1), "gaps": gaps,
                        "crc_errors": self.sdr.crc_errors, "center_hz": self.sdr.spec_center_hz,
                        "span_hz": s["span"], "clock": self.clock.info(), "t": t1}
                if WS_JSON:
                    msg = json.dumps(dict(meta, db=np.round(db_np, 1).tolist()))
                else:
                    q = np.clip(np.rint((db_np + 140.0) * 100), 0, 65535).astype("<u2")   # 0.01 dB steps
                    msg = self._binmsg(dict(meta, enc="u16", n=int(q.size)), q.tobytes())
                for ws in full:
                    try:
                        await (ws.send_text(msg) if WS_JSON else ws.send_bytes(msg))
                        self.bytes_out["full"] += len(msg); pf["full_msgs"] += 1
                    except Exception:
                        self.clients.discard(ws)
            t_wait = time.perf_counter(); pf["push_ms"] += (t_wait - _t1) * 1e3

    async def _close(self):
        if self.sdr:
            try:
                if self.sdr.writer:
                    await asyncio.wait_for(self.sdr.stop_stream(), 3)
                    await asyncio.wait_for(self.sdr.restore_defaults(), 3)
            except Exception:
                pass
            await self.sdr.close()
            self.sdr = None

    async def start(self):
        self.loop = asyncio.get_running_loop()
        self.bursts = BurstEngine(BURSTS, self._on_burst)
        if os.environ.get("SNIFF_NO_SERIAL") != "1":
            self.task = asyncio.create_task(self.run())

    async def shutdown(self):
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):
                pass
        await self._close()
        if self.bursts:
            self.bursts.stop()


hub = SpectrumHub()


class PacketHub:
    """802.15.4 sniffer (COM16) -> packet list for the browsers."""

    def __init__(self):
        self.enabled = os.environ.get("SNIFF_THREAD", "1") == "1"
        self.channel = int(os.environ.get("SNIFF_THREAD_CHANNEL", "15"))
        hop = os.environ.get("SNIFF_HOP", "")
        self.hop = [int(c) for c in hop.split(",") if c.strip()] or None
        self.dwell = float(os.environ.get("SNIFF_DWELL", "2.0"))
        self.per_channel = collections.Counter()
        self.sniffer: Optional[ThreadSniffer] = None
        self.recent = collections.deque(maxlen=300)
        self.per_source = collections.Counter()
        self.total = 0
        self.pair_counts = collections.Counter()
        self.offsets = collections.deque(maxlen=200)          # burst - corrected packet time (after calibration)
        self.offsets_raw = collections.deque(maxlen=200)      # burst - raw packet host timestamp (before)
        self.resid = collections.deque(maxlen=200)            # burst - airtime-corrected time (feeds auto-cal)
        self.cal_s = 0.0
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.task: Optional[asyncio.Task] = None
        self.ch_hist = collections.deque(maxlen=5000)       # (t, sniffer channel) for PER blind detection
        self.per: Optional[PerTracker] = None
        self.per_task: Optional[asyncio.Task] = None

    def channel_at(self, t: float):
        ch = None
        for tt, c in self.ch_hist:
            if tt <= t:
                ch = c
            else:
                break
        if ch is None and self.sniffer:
            ch = self.sniffer.current_channel
        return ch

    def _note_channel(self, ch):
        self.ch_hist.append((time.time(), int(ch)))
        asyncio.ensure_future(hub.broadcast(self.info()))

    async def _per_loop(self):
        def save_async(*a):
            self.loop.run_in_executor(None, rfpair.save, *a)
        while True:
            await asyncio.sleep(0.25)
            try:
                self.per.tick(save_async)
            except Exception as e:
                print("[per] tick error", repr(e), flush=True)

    def _per_update(self, summary: dict):
        if "fc" in summary:
            asyncio.ensure_future(hub.broadcast({"type": "fc", **summary}))
        else:
            asyncio.ensure_future(hub.broadcast({"type": "per", "run": summary}))

    def info(self) -> dict:
        st = self.sniffer.status() if self.sniffer else {}
        ch = self.sniffer.current_channel if self.sniffer else self.channel
        return {"type": "thread", "enabled": self.enabled, "channel": ch,
                "channel_mhz": channel_mhz(ch), "hop": self.hop, "dwell": self.dwell,
                "per_channel": {str(k): v for k, v in sorted(self.per_channel.items())}, "total": self.total,
                "per_source": dict(self.per_source.most_common(20)),
                "records": st.get("records"), "file": st.get("file"),
                "wireshark_connected": st.get("wireshark_connected"),
                "wireshark_packets": st.get("wireshark_packets"), "running": st.get("running"),
                "pairing": dict(self.pair_counts),
                "offset_median_ms": round(float(sorted(self.offsets)[len(self.offsets) // 2]), 1) if self.offsets else None,
                "timing": {"after": self._dist(self.offsets), "before": self._dist(self.offsets_raw),
                           "cal_ms": round(self.cal_s * 1e3, 2), "auto_cal_n": len(self.resid)}}

    @staticmethod
    def _dist(d):
        if not d:
            return None
        a = sorted(d)
        q = lambda f: a[min(len(a) - 1, int(f * len(a)))]
        return {"n": len(a), "median_ms": round(q(0.5), 2), "iqr_ms": round(q(0.75) - q(0.25), 2),
                "p05_ms": round(q(0.05), 2), "p95_ms": round(q(0.95), 2)}

    def t_ref(self, pkt: dict) -> float:
        """Packet time aligned to the RF burst centre: host timestamp (frame end + UART/USB latency)
        minus half the on-air time, plus the running auto-calibration residual."""
        air = (pkt.get("airtime_ms") or 0.0) / 1e3
        return pkt["t"] - air / 2 + self.cal_s

    def _on_packet(self, pkt: dict):          # sniffer thread
        if self.loop:
            self.loop.call_soon_threadsafe(self._deliver, pkt)

    def _deliver(self, pkt: dict):            # event loop
        self.total += 1
        self.per_source[pkt.get("src") or "?"] += 1
        self.per_channel[pkt.get("channel")] += 1
        self.recent.append(pkt)
        pkt["pair"] = None
        if self.per:
            self.per.on_frame(pkt)
            if pkt.get("per"):
                self.per.on_packet(pkt)
        asyncio.ensure_future(hub.broadcast(pkt))
        self.loop.call_later(SNIP_HALF_S + 0.15, self._pair, pkt, 0)

    def _pair(self, pkt: dict, tries: int):
        ring = hub.ring
        t = pkt.setdefault("t_ref", self.t_ref(pkt))
        if ring.newest() < t + SNIP_HALF_S and tries < 10:
            self.loop.call_later(0.1, self._pair, pkt, tries + 1)   # spectrum not there yet
            return
        f = pkt.get("freq_mhz") or channel_mhz(pkt.get("channel") or 15)
        try:
            cut = ring.cut(t, SNIP_HALF_S, f, SNIP_HALF_MHZ)
        except Exception as e:
            cut = None
            print("[pair] cut error", e, flush=True)
        if cut is None:
            res = {"quality": "nospec", "reason": "channel outside spectrum view or no frames" if ring.count else "no spectrum"}
        else:
            db, t0, t1, fr = cut
            res = rfpair.pair(db, t0, t1, fr, f, t)
            if pkt.get("id"):
                res["snippet"] = pkt["id"]
                meta = {k: pkt.get(k) for k in ("id", "t", "src", "dst", "pan", "kind", "info", "rssi", "lqi", "len",
                                               "seq", "channel", "freq_mhz", "pcap_file", "frame", "airtime_ms", "psdu_len")}
                meta["t_host"], meta["t"], meta["cal_ms"] = pkt["t"], t, round(self.cal_s * 1e3, 2)
                meta["spectrum"] = {"center_mhz": ring.center_hz / 1e6, "span_mhz": ring.span_hz / 1e6, "bins": ring.n,
                                    "clock": hub.clock.info()}
                path = os.path.join(SNIPPETS, pkt["id"] + ".npz")
                self.loop.run_in_executor(None, rfpair.save, path, db, t0, t1, fr, t, meta, dict(res))
        pkt["pair"] = res
        if hub.bursts and res.get("offset_ms") is not None:
            hub.bursts.note_packet(t + res["offset_ms"] / 1e3, f, res["quality"], pkt.get("id"))
        if pkt.get("per") and self.per:
            self.per.on_pair(pkt, res)
        self.pair_counts[res["quality"]] += 1
        if res.get("offset_ms") is not None and res["quality"] == "matched":
            burst = t + res["offset_ms"] / 1e3
            self.offsets.append(res["offset_ms"])
            self.offsets_raw.append(round((burst - pkt["t"]) * 1e3, 2))
            self.resid.append(burst - (pkt["t"] - (pkt.get("airtime_ms") or 0.0) / 2e3))
            if len(self.resid) >= 20:
                a = sorted(self.resid)
                self.cal_s = max(-0.03, min(0.03, a[len(a) // 2]))
        asyncio.ensure_future(hub.broadcast({"type": "pair", "id": pkt.get("id"), "t": t, "pair": res}))

    async def _status_loop(self):
        while True:
            await asyncio.sleep(2)
            await hub.broadcast(self.info())
            if hub.bursts:
                await hub.broadcast(hub.bursts.stats())

    async def start(self):
        if not self.enabled:
            return
        self.loop = asyncio.get_running_loop()
        self.sniffer = ThreadSniffer(
            port=os.environ.get("SNIFF_THREAD_PORT", "COM16"),
            baud=int(os.environ.get("SNIFF_THREAD_BAUD", "460800")),
            channel=self.channel, hop=self.hop, dwell=self.dwell,
            on_channel=lambda ch: self.loop and self.loop.call_soon_threadsafe(self._note_channel, ch),
            captures_dir=os.environ.get("SNIFF_CAPTURES", DEFAULT_CAPTURES),
            wireshark=os.environ.get("SNIFF_WIRESHARK", "1") == "1",
            on_packet=self._on_packet,
            on_log=lambda m: print("[thread]", m, flush=True),
        )
        self.ch_hist.append((time.time(), self.sniffer.current_channel))
        cap = os.environ.get("SNIFF_CAPTURES", DEFAULT_CAPTURES)
        self.per = PerTracker(cap, SNIPPETS, lambda: hub.ring, self.channel_at,
                              lambda: {"center_mhz": hub.ring.center_hz / 1e6, "span_mhz": hub.ring.span_hz / 1e6,
                                       "bins": hub.ring.n, "clock": hub.clock.info()},
                              self._per_update, SNIP_HALF_S, SNIP_HALF_MHZ)
        await asyncio.get_running_loop().run_in_executor(None, self.sniffer.start)
        self.task = asyncio.create_task(self._status_loop())
        self.per_task = asyncio.create_task(self._per_loop())

    async def shutdown(self):
        if self.task:
            self.task.cancel()
        if self.per_task:
            self.per_task.cancel()
        if self.sniffer:
            await asyncio.get_running_loop().run_in_executor(None, self.sniffer.stop)
            self.sniffer = None


pkts = PacketHub()


_emergency_lock = threading.Lock()


def emergency_cleanup():
    """Synchronous last-resort cleanup for a forced exit (second Ctrl+C or hard
    timeout): stop the SPEC stream and restore BANDWIDTH 20 / DC 1 through the
    serial handle, close COM7, kill the sniffer/tshark/Wireshark children
    (which frees COM16). Safe to call from any thread, runs once."""
    if not _emergency_lock.acquire(blocking=False):
        return
    import serial  # pyserial
    ser = None
    try:
        sdr = hub.sdr
        tr = sdr.writer.transport if sdr and sdr.writer else None
        ser = (getattr(tr, "serial", None) or getattr(tr, "_serial", None)) if tr else None
        if ser is None or not ser.is_open:
            ser = serial.Serial(PORT, BAUD, timeout=0.3, write_timeout=1) if os.environ.get("SNIFF_NO_SERIAL") != "1" else None
        if ser is not None:
            ser.write(b"\n"); ser.flush(); time.sleep(0.5)
            try:
                ser.reset_input_buffer()
            except Exception:
                pass
            for c in (b"BANDWIDTH 20\n", b"DC 1\n"):
                ser.write(c); ser.flush(); time.sleep(0.2)
            print("[sniff-sight] emergency: SPEC stopped, BANDWIDTH 20 / DC 1 sent", flush=True)
    except Exception as e:
        print(f"[sniff-sight] emergency: device reset failed: {e}", flush=True)
    finally:
        try:
            if ser is not None:
                ser.close()
        except Exception:
            pass
    sn = pkts.sniffer
    if sn:
        for p in sn.procs.values():
            try:
                p.kill()
            except Exception:
                pass
    print("[sniff-sight] emergency: ports closed, child processes killed", flush=True)


def _quiet_connection_reset(loop):
    """On Windows the Proactor loop logs 'Exception in callback
    _ProactorBasePipeTransport._call_connection_lost ... ConnectionResetError
    [WinError 10054]' whenever a browser drops a socket. Ignore exactly that,
    pass everything else to the default handler."""
    def handler(lp, ctx):
        exc = ctx.get("exception")
        if isinstance(exc, ConnectionResetError) and "_call_connection_lost" in repr(ctx.get("handle") or ctx.get("message", "")):
            return
        lp.default_exception_handler(ctx)
    loop.set_exception_handler(handler)


@asynccontextmanager
async def lifespan(app):
    _quiet_connection_reset(asyncio.get_running_loop())
    await hub.start()
    await pkts.start()
    try:
        yield
    finally:
        print("[sniff-sight] shutting down: stopping SPEC stream, restoring device, closing ports", flush=True)
        if os.environ.get("SNIFF_TEST_SHUTDOWN_HANG"):   # test hook: simulate a stuck shutdown
            await asyncio.sleep(float(os.environ["SNIFF_TEST_SHUTDOWN_HANG"]))
        await pkts.shutdown()
        await hub.shutdown()
        print("[sniff-sight] shutdown complete", flush=True)


app = FastAPI(title="Sniff-Sight", lifespan=lifespan)

HTML = r"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Sniff-Sight</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, sans-serif; margin: .8rem 1.2rem; background: #111; color: #eee; }
    h1 { color: #7cf; margin: 0 .8rem 0 0; font-size: 1.3rem; display: inline-block; }
    #status, #tstatus { font-family: monospace; font-size: 12px; color: #aaa; margin: .2rem 0; }
    #liveTop { display: flex; flex-direction: column; }
    #rfbar summary { cursor: pointer; color: #7cf; font-size: 12px; }
    #rfbar .ctl { gap: .5rem .9rem; }
    .ro { display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 1px 12px; font: 11.5px/1.45 ui-monospace, Consolas, monospace; background: #0b0b0b; border: 1px solid #222; padding: 4px 8px; margin: 2px 0 4px; color: #ddd; }
    .ro div { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .ro b { color: #888; font-weight: normal; display: inline-block; min-width: 6.6em; }
    .ctl { display: flex; flex-wrap: wrap; gap: .9rem; align-items: center; font-size: 13px; margin: .4rem 0; }
    .ctl input[type=number] { width: 6rem; background: #222; color: #eee; border: 1px solid #444; }
    select, button { background: #222; color: #eee; border: 1px solid #444; padding: 2px 6px; }
    button:hover { background: #333; }
    canvas { display: block; background: #000; border: 1px solid #333; width: 100%; touch-action: none; }
    #spectrum, #waterfall { cursor: grab; } #spectrum.drag, #waterfall.drag { cursor: grabbing; }
    .row2 { display: grid; grid-template-columns: 1fr 300px; gap: 10px; margin-top: 8px; }
    .box { border: 1px solid #333; background: #161616; padding: 6px; font-size: 12px; min-width: 0; }
    .box h3 { margin: 0 0 4px 0; font-size: 13px; color: #7cf; }
    #pktwrap { max-height: 300px; overflow-y: auto; }
    table { border-collapse: collapse; width: 100%; font-family: monospace; font-size: 12px; }
    th { position: sticky; top: 0; background: #222; text-align: left; padding: 2px 5px; }
    td { padding: 1px 5px; border-bottom: 1px solid #222; white-space: nowrap; }
    tr.new td { background: #2a2040; }
    .bad { color: #f66; } .ok { color: #6d6; }
    #tune { font-family: monospace; font-size: 12px; color: #fc6; }
    #pkts tr { cursor: pointer; } #pkts tr:hover td { background: #222a33; } #pkts tr.sel td { background: #233848; }
    .q-matched { color: #6d6; } .q-weak { color: #fc6; } .q-none, .q-nospec { color: #888; }
    #snip { position: fixed; inset: 4vh 4vw auto auto; width: min(760px, 92vw); max-height: 92vh; overflow-y: auto; z-index: 10;
            background: #141a20; border: 1px solid #456; box-shadow: 0 6px 30px #000c; padding: 8px 10px; font-size: 12px; display: none; }
    #snip.open { display: block; }
    #snip h3 { margin: 0 0 4px 0; color: #7cf; font-size: 14px; display: flex; justify-content: space-between; gap: 8px; }
    #snip .meta { font-family: monospace; font-size: 11.5px; color: #ccc; margin-bottom: 6px; line-height: 1.45; overflow-wrap: anywhere; }
    #snip canvas { cursor: default; margin-top: 4px; }
    #snipClose { font-size: 14px; padding: 0 10px; }
    @media (max-width: 760px) {
      #rfbar { order: 2; } #spectrum { order: 1; } #readout { order: 3; } #waterfall { order: 4; }
      .ro { grid-template-columns: 1fr 1fr; font-size: 10.5px; } .ro b { min-width: 7.2em; }
      #snip { inset: 0 0 auto 0; width: 100vw; max-height: 100vh; height: 100vh; border: 0; padding: 6px; box-sizing: border-box; }
      #pktwrap th:nth-child(12), #pktwrap td:nth-child(12) { display: none; }
      body { margin: .4rem .4rem; }
      h1 { font-size: 1.1rem; }
      .ctl { gap: .35rem .6rem; font-size: 12px; }
      .ctl label { white-space: nowrap; }
      .ctl input[type=number] { width: 5.2rem; }
      .ctl input[type=range] { width: 5.5rem; }
      select, button { padding: 3px 6px; font-size: 12px; }
      #status, #tstatus { font-size: 11px; overflow-wrap: anywhere; }
      #spectrum { height: 200px; } #waterfall { height: 190px; }
      .row2 { grid-template-columns: 1fr; }
      #pktwrap { max-height: 240px; overflow-x: auto; }
      table { font-size: 11px; }
      /* hide less important columns: Dst, PAN, Len, FCS */
      #pktwrap th:nth-child(3), #pktwrap td:nth-child(3),
      #pktwrap th:nth-child(4), #pktwrap td:nth-child(4),
      #pktwrap th:nth-child(8), #pktwrap td:nth-child(8),
      #pktwrap th:nth-child(9), #pktwrap td:nth-child(9) { display: none; }
    }
    #top { position: sticky; top: 0; z-index: 5; background: #111; display: flex; flex-wrap: wrap; align-items: center; gap: .4rem .8rem; padding: .3rem 0 .4rem; border-bottom: 1px solid #2a2a2a; margin-bottom: .4rem; }
    .pills { display: flex; flex-wrap: wrap; gap: .35rem; }
    .pill { font: 12px monospace; padding: 1px 8px; border-radius: 10px; background: #1b1b1b; border: 1px solid #3a3a3a; color: #aaa; white-space: nowrap; }
    .pill.ok { color: #6d6; border-color: #2b5a2b; } .pill.warn { color: #fc6; border-color: #6a5420; } .pill.bad { color: #f66; border-color: #6a2a2a; } .pill.info { color: #c8f; border-color: #4a3560; }
    #tabs { margin-left: auto; display: flex; gap: 2px; }
    #tabs button, #bnav button { background: transparent; border: 0; border-bottom: 2px solid transparent; color: #aaa; padding: 4px 10px; font-size: 13px; cursor: pointer; }
    #tabs button.active, #bnav button.active { color: #7cf; border-bottom-color: #7cf; }
    #bnav { display: none; }
    .legend { display: flex; flex-wrap: wrap; gap: .3rem .8rem; font-size: 12px; margin: 3px 0; align-items: center; }
    .c-ieee802154 { color: #5f5; } .c-ble { color: #4cf; } .c-wifi { color: #fa4; } .c-microwave_oven { color: #f55; } .c-unknown { color: #aaa; }
    .row2b { display: grid; grid-template-columns: 360px 1fr; gap: 10px; }
    #ask { position: fixed; right: 12px; bottom: 12px; z-index: 9; width: 340px; background: #141a20; border: 1px solid #456; box-shadow: 0 6px 30px #000c; padding: 6px 8px; font-size: 12px; display: none; }
    #ask.open { display: block; }
    .askhead { display: flex; gap: 6px; align-items: center; } #askWf { width: 100%; height: 90px; margin: 4px 0; cursor: pointer; }
    .askbtns { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; } .askbtns button { flex: 1; padding: 6px 4px; }
    .askbtns input { background: #222; color: #eee; border: 1px solid #444; padding: 4px; }
    .tab { display: none; } .tab.active { display: block; }
    .sub { color: #888; font-size: 11.5px; font-weight: normal; }
    .scroll { overflow: auto; max-height: 320px; }
    tr.click { cursor: pointer; } tr.click:hover td { background: #222a33; } tr.sel td { background: #233848; }
    #perStrip { height: 46px; margin: 6px 0; cursor: default; }
    .l-lost-with-burst { color: #fc6; } .l-lost-no-burst { color: #f66; } .l-sniffer-blind { color: #c8f; } .l-lost-nospec, .l-lost-time-unknown { color: #888; }
    code { color: #ccc; }
    @media (max-width: 760px) {
      #tabs { display: none; }
      #bnav { display: flex; position: fixed; left: 0; right: 0; bottom: 0; z-index: 6; background: #161616; border-top: 1px solid #333; justify-content: space-around; padding-bottom: env(safe-area-inset-bottom); }
      #bnav button { flex: 1; padding: 10px 0; font-size: 13px; border-bottom: 0; border-top: 2px solid transparent; }
      #bnav button.active { border-top-color: #7cf; }
      body { padding-bottom: 52px; }
      .row2b { grid-template-columns: 1fr; }
      #ask { left: 0; right: 0; bottom: 46px; width: auto; }
      .pill { font-size: 11px; padding: 0 6px; }
      #top h1 { display: none; }
    }
  </style>
</head>
<body>
  <header id="top">
    <h1>Sniff-Sight</h1>
    <span class="pills"><span class="pill" id="pEsp">ESP</span><span class="pill" id="pSn">Sniffer</span><span class="pill" id="pWs">Wireshark</span><span class="pill" id="pCh">ch -</span><span class="pill" id="pPer" title="frame-counter loss % (all sources, last 2 min) / last SSPR run">PER -</span><span class="pill" id="pRate">0 pkt/s</span><span class="pill" id="pStream" title="stream mode, displayed spectra per second (measured in this browser) / points per spectrum">Stream -</span></span>
    <nav id="tabs"><button data-tab="live" class="active">Live</button><button data-tab="set">Settings</button><button data-tab="per">PER / Test</button><button data-tab="bursts">Bursts</button><button data-tab="snip">Snippets</button></nav>
  </header>
  <section class="tab active" id="tab-live">
    <div id="liveTop">
    <details id="rfbar" open><summary>RF controls</summary><div class="ctl rf">
      <label>Centre <input id="freq" type="number" step="0.001" min="2204" max="2804"> MHz</label>
      <span id="tune" class="sub"></span>
      <label>Span <select id="span"><option value="16000000">16 MHz</option><option value="40000000">40 MHz</option><option value="80000000">80 MHz</option></select></label>
      <label>Bins <select id="bins"><option>256</option><option>512</option><option>1024</option><option>2048</option><option value="4096">4096 (exp.)</option></select></label>
      <label title="Full: every spectrum (~30/s, all bins). Light: max-hold 20/s, max-pooled to 512 points, 8-bit (for remote / Funnel). Auto: Light over https or from another host">Stream <select id="lite"><option value="auto">Auto</option><option value="0">Full</option><option value="1">Light</option></select></label> <span id="liteInfo" class="sub"></span>
      <label>Gain <input id="gain" type="range" min="0" max="82" step="1"> <span id="gainVal"></span></label>
      <label title="Device detector per frame (SPEC): mean power or maximum power over the FFTs in each frame">Detector <select id="det"><option value="0">mean</option><option value="1">max</option></select></label>
      <label>Avg <input id="avg" type="range" min="0" max="0.97" step="0.01" value="0.3"> <span id="avgVal">0.30</span></label>
      <label title="Auto: follow the trace (5th percentile - 8 dB .. max + 6 dB)"><input id="auto" type="checkbox" checked> Auto range</label> <label title="Reference level (top of the plot) when Auto range is off">Ref <input id="ref" type="number" step="1" value="-20" style="width:4.2em"> dBFS</label> <label>Scale <select id="div"><option>2</option><option>5</option><option selected>10</option></select> dB/div</label>
      <label title="Hold the highest level per bin (client side), reset on retune"><input id="ph" type="checkbox"> Peak hold</label> <button id="phClear" title="Reset the held trace">Clear</button>
      <button id="mkPeak" title="Marker follows the highest point of the trace">Mkr &rarr; peak</button> <button id="mkDelta" title="Set the delta reference at the current marker (again = off)">&Delta; mkr</button>
      <button id="centreThread">Centre on Thread ch</button>
    </div></details>
    <canvas id="spectrum" height="260"></canvas>
    <div id="readout" class="ro"></div>
    <canvas id="waterfall" height="300"></canvas>
    </div>
    <div class="legend"><label><input id="bov" type="checkbox" checked> burst overlay</label>
      <span class="c-ieee802154">&#9632; 802.15.4</span><span class="c-ble">&#9632; BLE</span><span class="c-wifi">&#9632; Wi-Fi</span><span class="c-microwave_oven">&#9632; microwave</span><span class="c-unknown">&#9632; unknown</span><span class="sub" id="bLegendStats"></span></div>
    <div class="row2">
      <div class="box"><h3>802.15.4 packets</h3><div id="pktwrap"><table>
        <thead><tr><th>Time</th><th>Src</th><th>Dst</th><th>PAN</th><th>Type</th><th>RSSI</th><th>LQI</th><th>Len</th><th>FCS</th><th>Ch</th><th title="burst time minus packet time">&Delta;t ms</th><th title="band level of the burst">Peak</th><th>RF</th></tr></thead>
        <tbody id="pkts"></tbody></table></div></div>
      <div class="box"><h3>Stats</h3><div id="stats"></div></div>
    </div>
  </section>
  <section class="tab" id="tab-per">
    <div class="box"><h3>Frame-counter ledger <span class="sub">key-independent: per source, gaps in the aux-security frame counter = frames the sniffer missed (retx = same counter again)</span></h3>
      <div class="scroll"><table><thead><tr><th>Source</th><th>Stream</th><th>Rx</th><th>Missed</th><th>Loss %</th><th>Retx</th><th>DSN gaps</th><th>Resets</th><th>Last FC</th><th>Labels</th></tr></thead><tbody id="fcTable"></tbody></table></div>
      <h3 style="margin-top:8px">Missed frames <span class="sub">newest first, click = spectrum at interpolated air time</span></h3>
      <div class="scroll" style="max-height:260px"><table><thead><tr><th>Time</th><th>Source</th><th>Stream</th><th>FC</th><th>&plusmn;ms</th><th>Label</th><th>Excess dB</th></tr></thead><tbody id="fcEv"></tbody></table></div>
    </div>
    <div class="box" style="margin-top:10px"><h3>SSPR test runs <span class="sub">secondary layer, needs decryption: UDP payload seq from tools/traffic/traffic_test.py --phases per</span></h3>
      <div class="scroll"><table><thead><tr><th>Run</th><th>Ch</th><th>TX dBm</th><th>Size</th><th>TX</th><th>Rx</th><th>Lost</th><th>Pend.</th><th>Dup</th><th>Late</th><th>PER %</th><th>RSSI</th><th>Labels</th></tr></thead><tbody id="perRuns"></tbody></table></div>
      <div id="perDetail" class="sub" style="margin-top:6px">select a run</div>
      <canvas id="perStrip" height="46"></canvas>
      <div class="scroll" style="max-height:240px"><table><thead><tr><th>Seq</th><th>Status</th><th>Label</th><th>Expected</th><th>Excess dB</th><th>RSSI</th><th>RF</th></tr></thead><tbody id="perRows"></tbody></table></div>
    </div>
  </section>
  <section class="tab" id="tab-bursts">
    <div class="row2b">
      <div class="box"><h3>Burst classes <span class="sub">rule-based, see docs/BURST_CLASSES.md</span></h3><table><thead><tr><th>Class</th><th>Total</th><th>Last 60 s</th><th>User labels</th></tr></thead><tbody id="bStats"></tbody></table>
        <h3 style="margin-top:8px">Ground truth <span class="sub">matched 802.15.4 packets -> classified as</span></h3><div id="bGt" class="sub"></div>
        <h3 style="margin-top:8px">Packet / burst timing</h3><div id="bTiming" class="sub"></div></div>
      <div class="box"><h3>Recent bursts <span class="sub">click = spectrum snippet (if saved)</span></h3>
        <div class="ctl"><select id="bF"><option value="">all classes</option><option>ieee802154</option><option>ble</option><option>wifi</option><option>microwave_oven</option><option>unknown</option></select><label><input id="bPause" type="checkbox"> pause</label></div>
        <div class="scroll" style="max-height:60vh"><table><thead><tr><th>Time</th><th>Class</th><th>Conf</th><th>MHz</th><th>BW10</th><th>BW20</th><th>ms</th><th>dB</th><th>Drift</th><th>IBI</th><th>GT</th></tr></thead><tbody id="bList"></tbody></table></div></div>
    </div>
  </section>
  <section class="tab" id="tab-snip">
    <div class="ctl"><input id="snipQ" type="search" placeholder="search id / kind / source" style="flex:1;min-width:10rem">
      <select id="snipF"><option value="">all</option><option value="lost">losses (per_ / fc_)</option><option value="matched">matched</option><option value="weak">weak</option><option value="none">no burst</option></select>
      <button id="snipRefresh">Refresh</button><span id="snipCount" class="sub"></span></div>
    <div class="box"><div class="scroll" style="max-height:calc(100vh - 190px)"><table><thead><tr><th>Snippet</th><th>Time</th><th>Kind</th><th>Src</th><th>Ch</th><th>RF</th></tr></thead><tbody id="snipList"></tbody></table></div></div>
  </section>
  <section class="tab" id="tab-set">
    <div class="box"><h3>Spectrum (ESP32-S3)</h3><div class="sub">The RF controls (centre, span, bins, gain, detector, averaging, range, stream mode) are on the Live tab, above the plot (on a phone: under the plot).</div><div id="status">Connecting...</div></div>
    <div class="box" style="margin-top:10px"><h3>Firmware (ESP32-S3 SDR)</h3>
      <div class="sub">Board: <b id="fwBoard">-</b><br>Bundled: <b id="fwBundled">-</b> <span id="fwCmp"></span></div>
      <div class="ctl" style="margin-top:6px"><button id="fwInstall">Install firmware</button> <span id="fwState" class="sub"></span></div>
      <progress id="fwProg" max="1" value="0" style="width:100%;display:none"></progress>
      <pre id="fwLog" class="sub" style="max-height:160px;overflow:auto;white-space:pre-wrap;margin:4px 0 0"></pre>
      <div class="sub" style="margin-top:4px">Flashing uses Web Serial in this browser: desktop Chrome / Edge on the PC the board is plugged into, opened via http://localhost:8000 (or https). The dashboard releases the SDR port first and reconnects when done.</div></div>
    <div class="box" style="margin-top:10px"><h3>802.15.4 sniffer (xG24 RCP)</h3><div id="tstatus"></div>
      <div class="sub" id="hopInfo" style="margin-top:4px"></div>
      <div class="sub" style="margin-top:4px">Channel / hop list / dwell are launcher options (restart): <code>python -m sniff_sight --channel 20</code> or <code>--hop 15,20 --dwell 2</code>. Frames with bad FCS are dropped inside the RCP; losses show up as frame-counter gaps and unmatched RF bursts.</div></div>
  </section>
  <nav id="bnav"><button data-tab="live" class="active">Live</button><button data-tab="set">Settings</button><button data-tab="per">PER</button><button data-tab="bursts">Bursts</button><button data-tab="snip">Snippets</button></nav>
  <div id="ask"><div class="askhead"><b>What is this?</b> <span id="askInfo" class="sub"></span><span style="flex:1"></span><span id="askQ" class="sub"></span><button id="askSkip" title="skip">&times;</button><button id="askOff" title="stop asking for 10 min">mute</button></div>
    <canvas id="askWf" height="90"></canvas>
    <div class="askbtns"><button data-l="ieee802154">802.15.4</button><button data-l="ble">BLE</button><button data-l="wifi">Wi-Fi</button><button data-l="microwave_oven">Microwave</button><button data-l="noise">Noise</button><button data-l="other">Other</button></div>
    <div class="askbtns"><input id="askText" placeholder="note / custom label" style="flex:1"><button id="askSend">OK</button></div></div>
  <div id="snip"><h3><span id="snipTitle">Packet</span><button id="snipClose" title="Close (Esc)">&times;</button></h3>
    <div class="meta" id="snipMeta"></div>
    <canvas id="snipWf" height="220"></canvas>
    <canvas id="snipLvl" height="110"></canvas>
    <canvas id="snipSp" height="150"></canvas>
    <div class="meta" id="snipFoot"></div>
  </div>
  <script src="/static/flasher.js"></script>
  <script>
    "use strict";
    const $ = (id) => document.getElementById(id);
    const sc = $('spectrum'), sx = sc.getContext('2d'), wc = $('waterfall'), wx = wc.getContext('2d', { willReadFrequently: true });
    const L = 52, B = 22, FMIN = 2204e6, FMAX = 2804e6;
    // Model as in z2-web-sdr: state.freqHz (here viewHz) is the wanted centre and defines the
    // view; every frame is drawn at the centre it was captured at (m.center_hz), so the trace,
    // channel band and markers move with the axis while dragging and line up again by
    // themselves once frames at the new centre arrive. The device follows, throttled to one
    // retune per 350 ms during a drag and once more on release.
    let mk = { peak: true, hz: null }, mkRef = null, cur = {}, streamLight = null, specInfo = '', dispT = [], dispFps = 0, gridDs = 10;
    let peak = null, ws, info = '', avg = null, avgKey = '', dbMin = -85, dbMax = -20, lastN = 0, last = null;
    let viewHz = null, spanHz = 80e6, deviceHz = null, sentHz = null, tuneSent = 0, tuneTimer = null, drag = null;
    let lastViewA = null;                // left edge of the view the waterfall was drawn for
    let thread = { channel: 15, channel_mhz: 2425 }, pending = [], pktTimes = [], perSrc = {}, total = 0;
    window.ssDebug = () => ({ peakOn: $('ph').checked, peakAboveLive: peak && avg ? Array.from(avg).every((v, i) => peak[i] >= v) : null, peakMax: peak ? Math.max(...peak) : null, liveMax: avg ? Math.max(...avg) : null, viewHz, deviceHz, sentHz, spanHz, dragging: !!drag, lastCenter: last && last.center_hz, freqInput: $('freq').value });
    function fit() { let ch = false; for (const c of [sc, wc]) if (c.clientWidth && c.width !== c.clientWidth) { c.width = c.clientWidth; ch = true; } if (ch) lastViewA = null; }
    fit(); window.addEventListener('resize', () => { fit(); if (last) render(); });
    function niceStep(range, px) {
      const raw = range / Math.max(2, px / 90), p = Math.pow(10, Math.floor(Math.log10(raw)));
      for (const m of [1, 2, 5, 10]) if (m * p >= raw) return m * p; return 10 * p;
    }
    function heat(t) {
      t = Math.max(0, Math.min(1, t));
      const k = [[0,0,0],[0,0,160],[0,170,255],[255,230,0],[255,255,255]], p = t * 4, i = Math.min(3, Math.floor(p)), f = p - i;
      return [0,1,2].map(c => k[i][c] + (k[i+1][c] - k[i][c]) * f);
    }
    const PW = () => sc.width - L;
    const viewA = () => viewHz - spanHz / 2;
    const xOfHz = (f) => L + (f - viewA()) / spanHz * PW();
    const hzOfX = (x) => viewA() + (x - L) / PW() * spanHz;
    // z2-web-sdr shiftWaterfall(): when the view moves, move the existing rows by the same
    // number of pixels so old rows stay at their frequencies
    function shiftWaterfall() {
      const a = viewA();
      if (lastViewA !== null && a !== lastViewA) {
        const dx = Math.round((lastViewA - a) / spanHz * PW());
        if (Math.abs(dx) >= PW()) { wx.fillStyle = '#000'; wx.fillRect(0, 0, wc.width, wc.height); }
        else if (dx) {
          const img = wx.getImageData(L, 0, PW(), wc.height);
          wx.fillStyle = '#000'; wx.fillRect(L, 0, PW(), wc.height);
          wx.putImageData(img, L + dx, 0, Math.max(0, -dx), 0, PW() - Math.abs(dx), wc.height);
        }
      }
      lastViewA = a;
    }
    function render() {          // spectrum plot from the latest frame, in the current view
      const m = last; if (!m || viewHz === null) return;
      shiftWaterfall();
      const n = m.db.length, W = sc.width, H = sc.height, PH = H - B;
      const f0 = viewA(), f1 = f0 + spanHz, dataF0 = m.center_hz - m.span_hz / 2;
      const Xb = (i) => xOfHz(dataF0 + i * m.span_hz / n), Y = (v) => (dbMax - v) / (dbMax - dbMin) * PH;
      sx.fillStyle = '#000'; sx.fillRect(0, 0, W, H);
      const cx0 = xOfHz(thread.channel_mhz * 1e6 - 1e6), cx1 = xOfHz(thread.channel_mhz * 1e6 + 1e6);
      sx.fillStyle = 'rgba(200,80,255,0.15)'; sx.fillRect(Math.max(L, cx0), 0, Math.max(0, Math.min(W, cx1) - Math.max(L, cx0)), PH);
      sx.font = '11px monospace'; sx.fillStyle = '#999'; sx.strokeStyle = '#262626'; sx.lineWidth = 1;
      const ds = $('auto').checked ? niceStep(dbMax - dbMin, PH * 1.6) : +$('div').value; gridDs = ds;
      sx.beginPath(); sx.textAlign = 'right'; sx.textBaseline = 'middle';
      for (let v = Math.ceil(dbMin / ds) * ds; v <= dbMax; v += ds) { const y = Y(v); sx.moveTo(L, y); sx.lineTo(W, y); sx.fillText(v.toFixed(0), L - 4, y); }
      const fs = niceStep(spanHz, PW()); sx.textAlign = 'center'; sx.textBaseline = 'top';
      const dec = fs >= 1e6 ? 0 : fs >= 1e5 ? 1 : 2;
      for (let f = Math.ceil(f0 / fs) * fs; f <= f1; f += fs) { const x = xOfHz(f); sx.moveTo(x, 0); sx.lineTo(x, PH); sx.fillText((f / 1e6).toFixed(dec), x, PH + 5); }
      sx.stroke();
      sx.fillStyle = '#c8f'; sx.textAlign = 'left'; sx.textBaseline = 'top';
      if (cx1 > L && cx0 < W) sx.fillText('ch ' + thread.channel, Math.max(L, cx0) + 2, 2);
      sx.fillStyle = '#999'; sx.save(); sx.translate(10, PH / 2); sx.rotate(-Math.PI / 2); sx.textAlign = 'center'; sx.fillText('dBFS', 0, 0); sx.restore();
      sx.textAlign = 'right'; sx.fillText('MHz', W - 2, PH + 5);
      sx.save(); sx.beginPath(); sx.rect(L, 0, PW(), PH); sx.clip();
      sx.strokeStyle = '#7cf'; sx.beginPath();
      for (let i = 0; i < n; i++) { const x = Xb(i + 0.5), y = Y(avg[i]); i ? sx.lineTo(x, y) : sx.moveTo(x, y); }
      sx.stroke();
      if ($('ph').checked && peak && peak.length === n) {   // peak hold (z2-web-sdr: drawn over the live trace)
        sx.strokeStyle = '#e7c35a'; sx.beginPath();
        for (let i = 0; i < n; i++) { const x = Xb(i + 0.5), y = Y(peak[i]); i ? sx.lineTo(x, y) : sx.moveTo(x, y); }
        sx.stroke();
      }
      drawMarkers(m, Xb, Y, n);
      sx.restore();
      // centre tick (wanted frequency) on the axis, like z2-web-sdr
      const cx = xOfHz(viewHz); sx.fillStyle = '#f0a443'; sx.beginPath(); sx.moveTo(cx - 5, H); sx.lineTo(cx + 5, H); sx.lineTo(cx, H - 6); sx.closePath(); sx.fill();
      $('status').textContent = `${info} | seq ${m.seq} | ${m.fps} spectra/s | gain ${m.gain} | gaps ${m.gaps} | CRC err ${m.crc_errors}`;
      updateTune(); readout(m);
    }
    function addRow(m) {         // one waterfall row for frame m, drawn at its own centre in the current view
      const db = m.db, n = db.length, dataF0 = m.center_hz - m.span_hz / 2;
      if (lastN !== n) { wx.fillStyle = '#000'; wx.fillRect(0, 0, wc.width, wc.height); lastN = n; }
      shiftWaterfall();
      wx.drawImage(wc, 0, 0, wc.width, wc.height - 1, 0, 1, wc.width, wc.height - 1);
      const row = wx.createImageData(wc.width, 1);
      for (let x = 0; x < wc.width; x++) {
        const i = Math.floor((hzOfX(x) - dataF0) / m.span_hz * n);
        const c = (x < L || i < 0 || i >= n) ? [0, 0, 0] : heat((db[i] - dbMin) / (dbMax - dbMin));
        row.data.set([c[0], c[1], c[2], 255], x * 4);
      }
      wx.putImageData(row, 0, 0);
      rowTimes.unshift(m.t || performance.now() / 1000); if (rowTimes.length > wc.height) rowTimes.length = wc.height;
      while (pending.length) {
        const p = pending.shift(), a = xOfHz(p.freq_mhz * 1e6 - 1e6), b = xOfHz(p.freq_mhz * 1e6 + 1e6);
        wx.fillStyle = '#f0f'; wx.fillRect(a, 0, Math.max(2, b - a), 3);
        wx.fillStyle = '#fff'; wx.font = '10px monospace'; wx.textBaseline = 'top'; wx.fillText((p.kind || '').slice(0, 24), b + 3, 0);
      }
      wx.fillStyle = '#000'; wx.fillRect(0, 0, L, wc.height);
    }
    const rowTimes = [];
    const BCOL = { ieee802154: '#5f5', ble: '#4cf', wifi: '#fa4', microwave_oven: '#f55', unknown: '#aaa' };
    function overlayBurst(b) {         // outline the burst at the waterfall rows that cover its time
      if (!$('bov').checked || !rowTimes.length || viewHz === null) return;
      let y0 = rowTimes.findIndex(t => t <= b.t1), y1 = rowTimes.findIndex(t => t <= b.t0);
      if (y0 < 0) return; if (y1 < 0) y1 = rowTimes.length; if (y1 <= y0) y1 = y0 + 1;
      const xa = xOfHz(b.f_lo_mhz * 1e6), xb = xOfHz(b.f_hi_mhz * 1e6); if (xb < L || xa > wc.width) return;
      wx.strokeStyle = BCOL[b.cls] || '#aaa'; wx.globalAlpha = 0.35 + 0.6 * (b.confidence || 0); wx.lineWidth = 1;
      wx.strokeRect(Math.max(L, xa) - 1.5, y0 - 0.5, Math.max(3, xb - xa) + 3, Math.max(2, y1 - y0) + 1); wx.globalAlpha = 1;
    }
    function onSpec(m) {
      last = m; deviceHz = m.center_hz;
      if (viewHz === null) { viewHz = m.center_hz; spanHz = m.span_hz; showFreq(); }
      if (m.span_hz !== spanHz) { spanHz = m.span_hz; lastViewA = null; wx.fillStyle = '#000'; wx.fillRect(0, 0, wc.width, wc.height); }
      const n = m.db.length, key = n + '/' + m.center_hz + '/' + m.span_hz;
      const a = Math.max(0, Math.min(0.97, +$('avg').value));
      if (!avg || avgKey !== key) { avg = Float32Array.from(m.db); peak = Float32Array.from(m.db); avgKey = key; }   // new centre/span/bins: restart averaging and peak hold
      else for (let i = 0; i < n; i++) { avg[i] = a * avg[i] + (1 - a) * m.db[i]; if (m.db[i] > peak[i]) peak[i] = m.db[i]; }
      dispT.push(performance.now()); while (dispT.length && dispT[0] < performance.now() - 2000) dispT.shift();
      dispFps = dispT.length > 1 ? (dispT.length - 1) * 1000 / (dispT[dispT.length - 1] - dispT[0]) : 0;
      if (!$('auto').checked) { dbMax = +$('ref').value; dbMin = dbMax - 10 * +$('div').value; }
      else if (true) {
        const s = Array.from(avg).filter(v => v > -139).sort((x, y) => x - y);
        if (s.length) { const lo = s[Math.floor(s.length * 0.05)] - 8, hi = s[s.length - 1] + 6;
          dbMin += 0.1 * (lo - dbMin); dbMax += 0.1 * (Math.max(hi, lo + 20) - dbMax); }
      }
      rowQ.push(m); if (rowQ.length > 64) rowQ.shift();
      if (!rafOn) { rafOn = true; requestAnimationFrame(drawFrame); }
    }
    let rowQ = [], rafOn = false, drawT = [], drawFps = 0;
    function drawFrame() {
      rafOn = false; const q = rowQ; rowQ = [];
      for (const m of q) addRow(m);
      render();
      drawT.push(performance.now()); while (drawT.length && drawT[0] < performance.now() - 2000) drawT.shift();
      drawFps = drawT.length > 1 ? (drawT.length - 1) * 1000 / (drawT[drawT.length - 1] - drawT[0]) : 0;
    }

    // ---- markers + spectrum-analyzer style readout
    const trace = () => ($('ph').checked && peak) ? peak : avg;
    function mkIndex(m, n) {
      const t = trace(); if (!t) return -1;
      if (mk.peak) { let b = 0; for (let i = 1; i < n; i++) if (t[i] > t[b]) b = i; return b; }
      const i = Math.floor((mk.hz - (m.center_hz - m.span_hz / 2)) / m.span_hz * n); return i >= 0 && i < n ? i : -1;
    }
    const binHz = (m, i, n) => m.center_hz - m.span_hz / 2 + (i + 0.5) * m.span_hz / n;
    function drawMarkers(m, Xb, Y, n) {
      const t = trace(), i = mkIndex(m, n); if (!t || i < 0) return;
      const tri = (x, y, col, lab) => { sx.fillStyle = col; sx.beginPath(); sx.moveTo(x, y - 1); sx.lineTo(x - 5, y - 10); sx.lineTo(x + 5, y - 10); sx.closePath(); sx.fill(); sx.font = '10px monospace'; sx.textAlign = 'center'; sx.textBaseline = 'bottom'; sx.fillText(lab, x, y - 11); };
      if (mkRef) { const x = xOfHz(mkRef.hz); tri(x, Y(mkRef.db), '#9f9', 'R'); }
      tri(Xb(i + 0.5), Y(t[i]), '#f5f', '1');
    }
    const fHz = (h) => h == null || !isFinite(h) ? '-' : (h / 1e6).toFixed(3) + ' MHz';
    const fK = (h) => h == null || !isFinite(h) ? '-' : h >= 1e6 ? (h / 1e6).toFixed(3) + ' MHz' : (h / 1e3).toFixed(1) + ' kHz';
    const fx = (v, d, u) => v == null || !isFinite(v) ? '-' : (+v).toFixed(d) + (u || '');
    function streamText(m) {
      if (!m) return 'Stream -';
      return `${m.lite ? 'LIGHT' : 'FULL'} ${dispFps.toFixed(0)} fps / ${m.db.length} pts`;   // spectra received per second / points per spectrum
    }
    function readout(m) {
      const n = m.db.length, nFull = m.n_full || n, fs = m.span_hz, t = trace();
      const i = mkIndex(m, n), mHz = i >= 0 ? binHz(m, i, n) : null, mDb = i >= 0 ? t[i] : null;
      const srt = Array.from(avg).filter(v => v > -139).sort((a, b) => a - b), nf = srt.length ? srt[Math.floor(srt.length * 0.2)] : null;
      const a = +$('avg').value, det = cur.max_hold === undefined ? '-' : cur.max_hold ? 'max (device)' : 'mean (device)';
      const ifbw = cur.span === undefined ? '-' : `BANDWIDTH ${cur.span > 16e6 ? 0 : 20}`;
      const rows = [
        ['Center', fHz(m.center_hz)], ['Span', fK(m.span_hz)],
        ['Start', fHz(m.center_hz - m.span_hz / 2)], ['Stop', fHz(m.center_hz + m.span_hz / 2)],
        ['RBW', fK(1.5 * fs / nFull) + ' (Hann)'], ['Bin step', fK(fs / nFull) + (n !== nFull ? ` (shown ${fK(fs / n)})` : '')],
        ['VBW/Avg', a > 0 ? `EMA a=${a.toFixed(2)} (~${((1 + a) / (1 - a)).toFixed(1)} fr)` : 'off'],
        ['Bins', n !== nFull ? `${nFull} -> ${n} pts` : `${n}`],
        ['Sample rate', fx(fs / 1e6, 1, ' MS/s')], ['IF filter', ifbw],
        ['Frame time', m.frame_ms ? fx(m.frame_ms, 2, ' ms') : (m.fps ? fx(1000 / m.fps, 2, ' ms') : '-')],
        ['FFT acq.', fx(nFull / fs * 1e6, 1, ' us')], ['FFTs/frame', m.ffts ?? '-'],
        ['Device rate', fx(m.fps, 1, ' fps')], ['Received', fx(dispFps, 1, ' sp/s')], ['Drawn', fx(drawFps, 1, ' fps')],
        ['Detector', det], ['Gain', m.gain != null ? `${m.gain} (manual, AGC off)` : '-'],
        ['Ref level', fx(dbMax, 1, ' dBFS')], ['Scale', fx(gridDs, 0, ' dB/div') + ($('auto').checked ? ' auto' : '')],
        ['DC fix', cur.dc_fix === undefined ? '-' : cur.dc_fix ? 'on (DC 0)' : 'off (DC 1)'], ['Peak hold', $('ph').checked ? 'on' : 'off'],
        ['Mkr 1' + (mk.peak ? ' pk' : ''), mHz == null ? '-' : `${(mHz / 1e6).toFixed(3)} MHz ${mDb.toFixed(1)} dBFS`],
        ['Delta', mkRef && mHz != null ? `${((mHz - mkRef.hz) / 1e3).toFixed(1)} kHz ${(mDb - mkRef.db).toFixed(1)} dB` : '-'],
        ['Noise floor', nf == null ? '-' : fx(nf, 1, ' dBFS') + ' (p20)'],
        ['CRC/gaps/drp', `${m.crc_errors ?? '-'} / ${m.gaps ?? '-'} / ${m.drops ?? '-'}`],
        ['Stream', streamText(m)],
      ];
      $('readout').innerHTML = rows.map(([k, v]) => `<div><b>${k}</b>${esc(String(v))}</div>`).join('');
      pill('pStream', 'Stream ' + streamText(m), m.lite ? 'warn' : 'ok');
    }
    $('mkPeak').onclick = () => { mk = { peak: true, hz: null }; render(); };
    $('mkDelta').onclick = () => {
      if (mkRef) { mkRef = null; render(); return; }
      const m = last; if (!m) return; const n = m.db.length, i = mkIndex(m, n); if (i < 0) return;
      mkRef = { hz: binHz(m, i, n), db: trace()[i] }; render();
    };
    for (const id of ['ref', 'div']) $(id).onchange = () => { if (id === 'ref' || !$('auto').checked) $('auto').checked = false; render(); };
    if (window.innerWidth <= 760) $('rfbar').open = false;
    function showFreq() { if (document.activeElement !== $('freq')) $('freq').value = (viewHz / 1e6).toFixed(3); }
    function updateTune() {
      const pend = deviceHz !== null && Math.abs(deviceHz - viewHz) >= 1e3;
      $('tune').textContent = deviceHz === null ? '' : pend ? `retuning... device at ${(deviceHz / 1e6).toFixed(3)} MHz` : `device at ${(deviceHz / 1e6).toFixed(3)} MHz`;
    }
    // ---- tuning (z2-web-sdr setFreq + its 350 ms apply throttle; drag = state change only)
    function setFreq(hz, why) {
      hz = Math.round(hz / 1e3) * 1e3; hz = Math.max(FMIN, Math.min(FMAX, hz));
      if (hz !== viewHz) { viewHz = hz; showFreq(); if (!rafOn) { rafOn = true; requestAnimationFrame(drawFrame); } }   // one redraw per display frame while dragging (smooth on Android touch)
      requestTune(why === 'drag');
    }
    function requestTune(throttled) {
      const fire = () => { tuneTimer = null; if (viewHz === sentHz) return; sentHz = viewHz; tuneSent = performance.now(); send({ freq_mhz: viewHz / 1e6 }); };
      if (throttled) { if (!tuneTimer) tuneTimer = setTimeout(fire, Math.max(0, 350 - (performance.now() - tuneSent))); }
      else { if (tuneTimer) { clearTimeout(tuneTimer); tuneTimer = null; } fire(); }
    }
    for (const cv of [sc, wc]) {
      cv.addEventListener('pointerdown', (e) => {
        if (viewHz === null) return;
        if (document.activeElement && document.activeElement.blur) document.activeElement.blur();   // let the Centre box follow
        cv.setPointerCapture(e.pointerId); drag = { x0: e.clientX, f0: viewHz, moved: false };
      });
      cv.addEventListener('pointermove', (e) => {
        if (!drag) return; const r = cv.getBoundingClientRect(), dx = (e.clientX - drag.x0) * cv.width / r.width;
        if (Math.abs(dx) > 4) { drag.moved = true; cv.classList.add('drag'); }
        if (drag.moved) setFreq(drag.f0 - dx / PW() * spanHz, 'drag');
      });
      const end = (e) => { if (drag && drag.moved) requestTune(false); else if (drag && cv === sc && e && e.type === 'pointerup' && last) { const r = cv.getBoundingClientRect(), x = (e.clientX - r.left) * cv.width / r.width; if (x > L) { mk = { peak: false, hz: hzOfX(x) }; render(); } } drag = null; cv.classList.remove('drag'); };
      cv.addEventListener('pointerup', end); cv.addEventListener('pointercancel', end);
      cv.addEventListener('dblclick', (e) => { const r = cv.getBoundingClientRect(); setFreq(hzOfX((e.clientX - r.left) * cv.width / r.width)); });
      cv.addEventListener('wheel', (e) => { e.preventDefault(); setFreq(viewHz + Math.sign(-e.deltaY || e.deltaX) * 1e6, 'drag'); }, { passive: false });
    }
    // ---- packets
    function addPacket(p, live) {
      total++; perSrc[p.src || '?'] = (perSrc[p.src || '?'] || 0) + 1;
      if (live) { pktTimes.push(performance.now()); pending.push(p); }
      const tr = document.createElement('tr'); if (live) { tr.className = 'new'; setTimeout(() => tr.className = '', 1500); }
      const t = new Date(p.t * 1000).toLocaleTimeString([], { hour12: false }) + '.' + String(Math.floor((p.t % 1) * 1000)).padStart(3, '0');
      const fcs = p.fcs_ok === null ? '' : p.fcs_ok ? '<span class="ok">ok</span>' : '<span class="bad">bad</span>';
      tr.innerHTML = `<td>${t}</td><td>${p.src}</td><td>${p.dst}</td><td>${p.pan || ''}</td><td title="${(p.info || '').replace(/"/g, '&quot;')}">${p.kind}</td><td>${p.rssi ?? ''}</td><td>${p.lqi ?? ''}</td><td>${p.len ?? ''}</td><td>${fcs}</td><td>${p.channel}</td><td></td><td></td><td></td>`;
      tr.onclick = () => openSnippet(p, tr);
      const key = p.id || ('t' + p.t); pktById.set(key, { p, tr }); setPair(key, p.pair);
      const tb = $('pkts'); tb.insertBefore(tr, tb.firstChild);
      while (tb.rows.length > 300) { const r = tb.rows[tb.rows.length - 1]; for (const [k, v] of pktById) if (v.tr === r) pktById.delete(k); tb.deleteRow(-1); }
    }
    const pktById = new Map();
    function setPair(key, r) {
      const e = pktById.get(key); if (!e) return; e.p.pair = r || null; const c = e.tr.cells;
      if (!r) { c[12].textContent = '...'; return; }
      c[10].textContent = r.offset_ms ?? ''; c[11].textContent = r.peak_dbfs ?? '';
      c[12].innerHTML = `<span class="q-${r.quality}">${r.quality}</span>`;
      if (snipKey === key) openSnippet(e.p, e.tr);
    }
    // ---- snippet panel
    let snipKey = null;
    $('snipClose').onclick = () => { $('snip').classList.remove('open'); snipKey = null; document.querySelectorAll('#pkts tr.sel').forEach(r => r.classList.remove('sel')); };
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $('snipClose').onclick(); });
    async function openSnippet(p, tr) {
      snipKey = p.id || ('t' + p.t);
      document.querySelectorAll('#pkts tr.sel').forEach(r => r.classList.remove('sel')); if (tr) tr.classList.add('sel');
      const r = p.pair, when = new Date(p.t * 1000).toLocaleTimeString([], { hour12: false }) + '.' + String(Math.floor((p.t % 1) * 1000)).padStart(3, '0');
      $('snipTitle').textContent = `${p.kind} from ${p.src || '?'}`;
      $('snipMeta').innerHTML = `${when} | ch ${p.channel} (${p.freq_mhz} MHz) | RSSI ${p.rssi ?? '-'} dBm, LQI ${p.lqi ?? '-'} | ${p.len ?? '?'} B | PAN ${p.pan || '-'}<br>` +
        `Wireshark: <b>${p.pcap_file || '?'}</b> frame <b>#${p.frame ?? '?'}</b><br>` +
        (r ? `RF burst: <span class="q-${r.quality}">${r.quality}</span>` + (r.offset_ms !== null && r.offset_ms !== undefined ? ` | &Delta;t ${r.offset_ms} ms | peak ${r.peak_dbfs} dBFS (+${r.excess_db} dB over ${r.floor_dbfs})` : (r.reason ? ' | ' + r.reason : (r.excess_db !== undefined && r.excess_db !== null ? ` | best +${r.excess_db} dB` : ''))) : 'RF burst: pairing...');
      const clear = () => { for (const id of ['snipWf', 'snipLvl', 'snipSp']) { const c = $(id); c.width = c.clientWidth; c.getContext('2d').clearRect(0, 0, c.width, c.height); } };
      $('snip').classList.add('open'); clear();
      if (!r || !r.snippet) { $('snipFoot').textContent = r ? 'no snippet (' + (r.reason || r.quality) + ')' : 'waiting for spectrum...'; return; }
      const key = snipKey;
      try {
        const res = await fetch('/api/snippets/' + encodeURIComponent(r.snippet)); if (!res.ok) throw new Error(res.status);
        const s = await res.json(); if (key !== snipKey) return;
        drawSnippet(s); window.ssSnippet = { id: r.snippet, frames: s.db.length, bins: s.freqs_mhz.length, pair: s.pair };
        $('snipFoot').innerHTML = `snippet ${r.snippet}.npz | ${s.db.length} frames x ${s.freqs_mhz.length} bins | <a href="/api/snippets/${encodeURIComponent(r.snippet)}.npz" style="color:#7cf">download npz</a>`;
      } catch (e) { $('snipFoot').textContent = 'snippet not available yet (' + e.message + ')'; }
    }
    function drawSnippet(s) {
      const pr = s.pair, fr = s.freqs_mhz, n = s.db.length, m = fr.length, fc = s.meta.freq_mhz;
      const T0 = Math.min(-100, s.t0_ms[0]), T1 = Math.max(100, s.t1_ms[n - 1]);
      let lo = Infinity, hi = -Infinity; for (const row of s.db) for (const v of row) { if (v > -139) { if (v < lo) lo = v; if (v > hi) hi = v; } }
      lo = Math.max(lo, (pr.floor_dbfs ?? lo) - 6); hi = Math.max(hi, lo + 10);
      const Lm = 46, Rm = 8;
      // waterfall: x freq, y time (down = later)
      const wf = $('snipWf'), w = wf.getContext('2d'); wf.width = wf.clientWidth; const W = wf.width, H = wf.height, Bm = 16;
      const xf = (f) => Lm + (f - fr[0]) / (fr[m - 1] - fr[0]) * (W - Lm - Rm), yt = (t) => (t - T0) / (T1 - T0) * (H - Bm);
      w.fillStyle = '#000'; w.fillRect(0, 0, W, H);
      const cw = (W - Lm - Rm) / m;
      for (let i = 0; i < n; i++) { const y0 = yt(s.t0_ms[i]), y1 = Math.max(y0 + 1, yt(s.t1_ms[i]));
        for (let j = 0; j < m; j++) { const c = heat((s.db[i][j] - lo) / (hi - lo)); w.fillStyle = `rgb(${c[0] | 0},${c[1] | 0},${c[2] | 0})`; w.fillRect(Lm + j * cw, y0, cw + 0.6, y1 - y0); } }
      w.strokeStyle = '#c8f'; w.setLineDash([3, 3]); for (const f of [fc - 1, fc + 1]) { w.beginPath(); w.moveTo(xf(f), 0); w.lineTo(xf(f), H - Bm); w.stroke(); } w.setLineDash([]);
      w.strokeStyle = '#ff4060'; w.lineWidth = 2; w.beginPath(); w.moveTo(Lm, yt(0)); w.lineTo(W - Rm, yt(0)); w.stroke(); w.lineWidth = 1;
      if (pr.burst_t0_ms !== undefined) { w.strokeStyle = pr.quality === 'matched' ? '#6f6' : '#fc6'; w.lineWidth = 2; w.strokeRect(xf(fc - 1.1), yt(pr.burst_t0_ms), xf(fc + 1.1) - xf(fc - 1.1), Math.max(3, yt(pr.burst_t1_ms) - yt(pr.burst_t0_ms))); w.lineWidth = 1; }
      w.fillStyle = '#ccc'; w.font = '11px monospace'; w.textAlign = 'right';
      for (let t = -100; t <= 100; t += 50) w.fillText(t + ' ms', Lm - 3, Math.min(H - Bm - 2, Math.max(10, yt(t) + 4)));
      w.textAlign = 'center'; for (let f = Math.ceil(fr[0]); f <= fr[m - 1]; f += 2) w.fillText(f, xf(f), H - 3);
      w.textAlign = 'left'; w.fillStyle = '#ff4060'; w.fillText('packet', Lm + 3, yt(0) - 3);
      // band level vs time
      const lv = $('snipLvl'), l = lv.getContext('2d'); lv.width = lv.clientWidth; const LW = lv.width, LH = lv.height;
      const band = fr.map((f, j) => Math.abs(f - fc) <= 1 ? j : -1).filter(j => j >= 0);
      const lev = s.db.map(row => 10 * Math.log10(band.reduce((a, j) => a + Math.pow(10, row[j] / 10), 0) / band.length));
      const lmin = Math.min(...lev) - 2, lmax = Math.max(...lev, (pr.floor_dbfs ?? 0) + 8) + 2;
      const xt = (t) => Lm + (t - T0) / (T1 - T0) * (LW - Lm - Rm), yl = (v) => (LH - 14) - (v - lmin) / (lmax - lmin) * (LH - 20);
      l.fillStyle = '#000'; l.fillRect(0, 0, LW, LH);
      if (pr.floor_dbfs !== undefined) { l.strokeStyle = '#666'; l.setLineDash([4, 3]); l.beginPath(); l.moveTo(Lm, yl(pr.floor_dbfs)); l.lineTo(LW - Rm, yl(pr.floor_dbfs)); l.stroke();
        l.strokeStyle = '#a80'; const th = pr.floor_dbfs + Math.max(3, 3 * (pr.noise_sigma_db || 0)); l.beginPath(); l.moveTo(Lm, yl(th)); l.lineTo(LW - Rm, yl(th)); l.stroke(); l.setLineDash([]); }
      l.strokeStyle = '#4af'; l.beginPath(); lev.forEach((v, i) => { const x = xt(0.5 * (s.t0_ms[i] + s.t1_ms[i])); i ? l.lineTo(x, yl(v)) : l.moveTo(x, yl(v)); }); l.stroke();
      l.strokeStyle = '#ff4060'; l.lineWidth = 2; l.beginPath(); l.moveTo(xt(0), 0); l.lineTo(xt(0), LH - 14); l.stroke(); l.lineWidth = 1;
      if (pr.burst_index !== undefined) { const i = pr.burst_index; l.fillStyle = pr.quality === 'matched' ? '#6f6' : '#fc6'; l.beginPath(); l.arc(xt(0.5 * (s.t0_ms[i] + s.t1_ms[i])), yl(lev[i]), 4, 0, 7); l.fill(); }
      l.fillStyle = '#ccc'; l.font = '11px monospace'; l.textAlign = 'right'; l.fillText(lmax.toFixed(0), Lm - 3, 10); l.fillText(lmin.toFixed(0), Lm - 3, LH - 16);
      l.textAlign = 'left'; l.fillText(`ch band level (dBFS) vs time, ${T0.toFixed(0)}..${T1.toFixed(0)} ms`, Lm + 4, 11);
      // spectrum: max over snippet, burst frame
      const sp = $('snipSp'), g = sp.getContext('2d'); sp.width = sp.clientWidth; const SW = sp.width, SH = sp.height;
      const mx = fr.map((_, j) => Math.max(...s.db.map(row => row[j]))), md = fr.map((_, j) => { const c = s.db.map(row => row[j]).sort((a, b) => a - b); return c[c.length >> 1]; });
      const ys = (v) => (SH - 16) - (v - lo) / (hi - lo) * (SH - 22), xs = (f) => Lm + (f - fr[0]) / (fr[m - 1] - fr[0]) * (SW - Lm - Rm);
      g.fillStyle = '#000'; g.fillRect(0, 0, SW, SH);
      g.strokeStyle = '#c8f'; g.setLineDash([3, 3]); for (const f of [fc - 1, fc + 1]) { g.beginPath(); g.moveTo(xs(f), 0); g.lineTo(xs(f), SH - 16); g.stroke(); } g.setLineDash([]);
      const line = (arr, col) => { g.strokeStyle = col; g.beginPath(); arr.forEach((v, j) => j ? g.lineTo(xs(fr[j]), ys(v)) : g.moveTo(xs(fr[j]), ys(v))); g.stroke(); };
      line(md, '#4a6a88'); line(mx, '#e7c35a'); if (pr.burst_index !== undefined) line(s.db[pr.burst_index], pr.quality === 'matched' ? '#6f6' : '#fc6');
      g.fillStyle = '#ccc'; g.font = '11px monospace'; g.textAlign = 'right'; g.fillText(hi.toFixed(0), Lm - 3, 10); g.fillText(lo.toFixed(0), Lm - 3, SH - 18);
      g.textAlign = 'center'; for (let f = Math.ceil(fr[0]); f <= fr[m - 1]; f += 2) g.fillText(f + '', xs(f), SH - 3);
      g.textAlign = 'left'; g.fillStyle = '#e7c35a'; g.fillText('max', Lm + 4, 11); g.fillStyle = '#6f6'; g.fillText('burst frame', Lm + 34, 11); g.fillStyle = '#4a6a88'; g.fillText('median', Lm + 120, 11);
    }
    function renderStats() {
      const now = performance.now(); while (pktTimes.length && now - pktTimes[0] > 10000) pktTimes.shift();
      const chs = Object.entries(thread.per_channel || {}).map(([k, v]) => `<tr${+k === thread.channel ? ' style="color:#c8f"' : ''}><td>${k}</td><td>${2405 + 5 * (k - 11)}</td><td>${v}</td></tr>`).join('');
      const src = Object.entries(perSrc).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('');
      $('stats').innerHTML = `packets: ${total}<br>packets/s (10 s): ${(pktTimes.length / 10).toFixed(2)}<br>channel ${thread.channel} (${thread.channel_mhz} MHz)${thread.hop ? ' - hopping ' + thread.hop.join(',') + ', ' + thread.dwell + ' s dwell' : ''}<br><br><table><tr><th>source</th><th>count</th></tr>${src}</table><br><table><tr><th>channel</th><th>MHz</th><th>count</th></tr>${chs}</table>`;
    }
    setInterval(renderStats, 1000);
    setInterval(() => { const now = performance.now(); pill('pRate', (pktTimes.filter(t => now - t < 10000).length / 10).toFixed(1) + ' pkt/s'); }, 1000);
    function pill(id, text, cls) { const e = $(id); e.textContent = text; e.className = 'pill' + (cls ? ' ' + cls : ''); }
    const esc = (v) => String(v ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
    const hms = (t) => t ? new Date(t * 1000).toLocaleTimeString([], { hour12: false }) + '.' + String(Math.floor((t % 1) * 1000)).padStart(3, '0') : '';
    const labs = (o) => Object.entries(o || {}).map(([k, v]) => `<span class="l-${k}">${k} ${v}</span>`).join(' ');
    // ---- tabs (only visibility changes: websocket, waterfall and packet list keep running in the background)
    let tab = 'live';
    function showTab(t) {
      tab = t; localStorage.setItem('ss-tab', t);
      document.querySelectorAll('.tab').forEach(e => e.classList.toggle('active', e.id === 'tab-' + t));
      document.querySelectorAll('#tabs button, #bnav button').forEach(b => b.classList.toggle('active', b.dataset.tab === t));
      if (t === 'live') { fit(); render(); }
      if (t === 'per') { renderFc(); renderRuns(); if (perSel) loadRun(perSel); }
      if (t === 'snip') loadSnips();
      if (t === 'bursts') renderBursts();
    }
    document.querySelectorAll('#tabs button, #bnav button').forEach(b => b.onclick = () => showTab(b.dataset.tab));
    // ---- PER / frame-counter ledgers
    const perRuns = new Map(); let fcSum = [], fcEv = [], perSel = null, perTimer = null;
    function onPer(r) { perRuns.set(r.run, r); updPerPill(); if (tab === 'per') { renderRuns(); if (r.run === perSel && !perTimer) perTimer = setTimeout(() => { perTimer = null; loadRun(perSel); }, 800); } }
    function onFc(m) { fcSum = m.fc || []; fcEv = m.fc_events || fcEv; updPerPill(); if (tab === 'per') renderFc(); }
    function updPerPill() {
      const now = Date.now() / 1000, act = fcSum.filter(s => now - s.last < 120 && s.stream === 'mac');
      const rx = act.reduce((a, s) => a + s.rx, 0), ms = act.reduce((a, s) => a + s.missed, 0);
      const last = [...perRuns.values()].sort((a, b) => b.last - a.last)[0];
      const fcp = rx + ms ? 100 * ms / (rx + ms) : null;
      const txt = 'PER ' + (fcp === null ? '-' : fcp.toFixed(1) + '%') + (last && last.per_pct !== null ? ' | run ' + last.per_pct.toFixed(1) + '%' : '');
      const worst = Math.max(fcp ?? 0, last && now - last.last < 300 ? last.per_pct ?? 0 : 0);
      pill('pPer', txt, fcp === null && !last ? '' : worst > 5 ? 'bad' : worst > 1 ? 'warn' : 'ok');
    }
    function renderFc() {
      $('fcTable').innerHTML = fcSum.map(s => `<tr><td>${esc(s.src)}</td><td>${s.stream}</td><td>${s.rx}</td><td>${s.missed}</td><td>${s.per_pct ?? ''}</td><td>${s.retx}</td><td>${s.dsn_gaps}</td><td>${s.resets}</td><td>${s.last_fc ?? ''}</td><td>${labs(s.labels)}</td></tr>`).join('') || '<tr><td colspan="10" class="sub">no secured frames yet</td></tr>';
      const tb = $('fcEv'); tb.innerHTML = '';
      for (const e of [...fcEv].reverse()) {
        const tr = document.createElement('tr'); if (e.snippet) { tr.className = 'click'; tr.onclick = () => openSnippetById(e.snippet, tr); }
        tr.innerHTML = `<td>${hms(e.t)}</td><td>${esc(e.src)}</td><td>${e.stream}</td><td>${e.fc}</td><td>${e.uncert_ms}</td><td class="l-${e.label}">${e.label}</td><td>${e.excess_db ?? ''}</td>`; tb.appendChild(tr);
      }
    }
    function renderRuns() {
      const tb = $('perRuns'); tb.innerHTML = '';
      for (const r of [...perRuns.values()].sort((a, b) => b.last - a.last)) {
        const tr = document.createElement('tr'); tr.className = 'click' + (r.run === perSel ? ' sel' : ''); tr.onclick = () => { perSel = r.run; renderRuns(); loadRun(r.run); };
        tr.innerHTML = `<td>${esc(r.run)}</td><td>${r.channel ?? ''}</td><td>${r.txpower ?? ''}</td><td>${r.size ?? ''}</td><td>${r.tx}</td><td>${r.rx}</td><td>${r.lost}</td><td>${r.pending}</td><td>${r.dup}</td><td>${r.late}</td><td>${r.per_pct ?? ''}</td><td>${r.rssi_mean ?? ''}</td><td>${labs(r.labels)}</td>`; tb.appendChild(tr);
      }
      if (!perRuns.size) tb.innerHTML = '<tr><td colspan="13" class="sub">no SSPR runs yet</td></tr>';
    }
    async function loadRun(id) {
      try {
        const d = await (await fetch('/api/per/' + encodeURIComponent(id))).json(); if (id !== perSel || !d.rows) return;
        const s = d.summary || {};
        $('perDetail').textContent = `run ${id}: ${s.rx}/${s.expected} received, ${s.lost} lost, PER ${s.per_pct ?? '-'} %, tx->sniffer offset ${s.offset_ms} ms`;
        const cv = $('perStrip'), g = cv.getContext('2d'); cv.width = cv.clientWidth || 600; const n = d.rows.length, w = cv.width / Math.max(1, n);
        const col = (r) => r.status.startsWith('rx') ? '#2d6a2d' : r.status.startsWith('late') ? '#7cf' : r.status === 'pending' ? '#444' : ({ 'lost-with-burst': '#fc6', 'lost-no-burst': '#f44', 'sniffer-blind': '#c8f' })[r.label] || '#888';
        g.fillStyle = '#000'; g.fillRect(0, 0, cv.width, cv.height); d.rows.forEach((r, i) => { g.fillStyle = col(r); g.fillRect(i * w, 4, Math.max(1, w - (w > 3 ? 1 : 0)), cv.height - 18); });
        g.fillStyle = '#888'; g.font = '10px monospace'; g.fillText('seq ' + (d.rows[0]?.seq ?? '') + ' .. ' + (d.rows[n - 1]?.seq ?? '') + '   green rx, yellow lost+burst, red lost no burst, violet blind, blue late', 2, cv.height - 3);
        const tb = $('perRows'); tb.innerHTML = '';
        const rows = d.rows.filter(r => !String(r.status).startsWith('rx')).concat(d.rows.filter(r => String(r.status).startsWith('rx')).slice(0, 200));
        for (const r of rows) {
          const tr = document.createElement('tr'); const sid = r.snippet; if (sid) { tr.className = 'click'; tr.onclick = () => openSnippetById(sid, tr); }
          tr.innerHTML = `<td>${r.seq}</td><td>${r.status}</td><td class="l-${r.label || ''}">${r.label || ''}</td><td>${hms(+r.expected_t || +r.rx_t)}</td><td>${r.excess_db ?? ''}</td><td>${r.rssi ?? ''}</td><td>${r.rf ?? ''}</td>`; tb.appendChild(tr);
        }
      } catch (e) { $('perDetail').textContent = 'run ' + id + ': ' + e.message; }
    }
    fetch('/api/per').then(r => r.json()).then(d => { for (const r of d.runs.concat(d.archived || [])) if (!perRuns.has(r.run)) perRuns.set(r.run, r); onFc(d); renderRuns(); }).catch(() => {});
    // ---- bursts
    const bRecent = []; let bStats = null, bTimer = null;
    function onBurst(b) {
      overlayBurst(b); bRecent.unshift(b); if (bRecent.length > 300) bRecent.length = 300;
      if (b.ask && b.snippet) askPush(b);
      if (tab === 'bursts' && !$('bPause').checked && !bTimer) bTimer = setTimeout(() => { bTimer = null; renderBurstList(); }, 500);
    }
    function legendStats() { if (!bStats) return; const l = bStats.last60 || {}; $('bLegendStats').textContent = 'last 60 s: ' + Object.entries(l).map(([k, v]) => k + ' ' + v).join(', '); }
    function renderBursts() {
      if (bStats) {
        const cls = ['ieee802154', 'ble', 'wifi', 'microwave_oven', 'unknown'];
        $('bStats').innerHTML = cls.map(c => `<tr><td class="c-${c}">${c}</td><td>${(bStats.total || {})[c] || 0}</td><td>${(bStats.last60 || {})[c] || 0}</td><td>${(bStats.user_labels || {})[c] || ''}</td></tr>`).join('') +
          `<tr><td class="sub">frames ${bStats.frames}, dropped ${bStats.dropped}</td><td colspan="3" class="sub">user labels: ${Object.entries(bStats.user_labels || {}).map(([k, v]) => k + ' ' + v).join(', ') || '-'}</td></tr>`;
        $('bGt').innerHTML = Object.entries(bStats.ground_truth || {}).map(([g, o]) => { const n = Object.values(o).reduce((a, b) => a + b, 0); return `${g} (${n}): ` + Object.entries(o).map(([c, v]) => `<span class="c-${c}">${c} ${v} (${(100 * v / n).toFixed(0)}%)</span>`).join(', '); }).join('<br>') || 'no matched packets yet';
      }
      const tm = thread.timing; const f = (d) => d ? `median ${d.median_ms} ms, IQR ${d.iqr_ms} ms, p5..p95 ${d.p05_ms}..${d.p95_ms} ms (n ${d.n})` : '-';
      $('bTiming').innerHTML = tm ? `burst minus packet timestamp<br>raw host timestamp: ${f(tm.before)}<br>corrected (airtime/2 + auto-cal ${tm.cal_ms} ms): ${f(tm.after)}` : '-';
      renderBurstList();
    }
    function renderBurstList() {
      const flt = $('bF').value, tb = $('bList'); tb.innerHTML = '';
      for (const b of bRecent) {
        if (flt && b.cls !== flt) continue;
        const tr = document.createElement('tr'); if (b.snippet) { tr.className = 'click'; tr.onclick = () => openSnippetById(b.snippet, tr); }
        tr.innerHTML = `<td>${hms(b.t0)}</td><td class="c-${b.cls}">${b.cls}</td><td>${b.confidence}</td><td>${b.f_center_mhz.toFixed(2)}</td><td>${b.bw10_mhz}</td><td>${b.bw20_mhz ?? ''}</td><td>${b.duration_ms}</td><td>${b.peak_excess_db}</td><td>${b.drift_range_mhz}</td><td>${b.ibi_med_ms ?? ''}</td><td>${b.gt ? 'Y' : ''}</td>`; tb.appendChild(tr);
      }
    }
    $('bF').onchange = renderBurstList;
    fetch('/api/bursts?n=200').then(r => r.json()).then(d => { bStats = d.stats; for (const b of d.recent) bRecent.unshift(b); legendStats(); }).catch(() => {});
    // ---- "What is this?" active-learning card
    const askQ = []; let askCur = null, askMuteUntil = 0;
    function askPush(b) { if (Date.now() < askMuteUntil || askQ.length >= 5 || (askCur && askCur.id === b.id)) return; askQ.push(b); if (!askCur) askNext(); else askBadge(); }
    function askBadge() { $('askQ').textContent = askQ.length ? '+' + askQ.length + ' waiting' : ''; }
    async function askNext() {
      askCur = askQ.shift() || null; askBadge(); $('askText').value = '';
      if (!askCur) { $('ask').classList.remove('open'); return; }
      const b = askCur; $('ask').classList.add('open');
      $('askInfo').textContent = `${hms(b.t0)} ${b.f_center_mhz.toFixed(1)} MHz, ${b.bw10_mhz}/${b.bw20_mhz ?? '?'} MHz, ${b.duration_ms} ms, model: ${b.cls} ${b.confidence}`;
      const cv = $('askWf'), g = cv.getContext('2d'); cv.width = cv.clientWidth || 320; g.fillStyle = '#000'; g.fillRect(0, 0, cv.width, cv.height);
      try {
        const s = await (await fetch('/api/snippets/' + encodeURIComponent(b.snippet))).json(); if (askCur !== b) return;
        let lo = Infinity, hi = -Infinity; for (const r of s.db) for (const v of r) { if (v < lo) lo = v; if (v > hi) hi = v; }
        const n = s.db.length, m = s.freqs_mhz.length, cw = cv.width / m, rh = cv.height / n;
        for (let i = 0; i < n; i++) for (let j = 0; j < m; j++) { const c = heat((s.db[i][j] - lo) / Math.max(1, hi - lo)); g.fillStyle = `rgb(${c[0] | 0},${c[1] | 0},${c[2] | 0})`; g.fillRect(j * cw, i * rh, cw + 0.6, rh + 0.6); }
        g.fillStyle = '#ccc'; g.font = '10px monospace'; g.fillText(s.freqs_mhz[0].toFixed(1) + ' .. ' + s.freqs_mhz[m - 1].toFixed(1) + ' MHz, ' + n + ' frames', 3, cv.height - 3);
      } catch (e) { g.fillStyle = '#888'; g.fillText('snippet: ' + e.message, 4, 14); }
    }
    async function askAnswer(label) {
      const b = askCur; if (!b) return; const text = $('askText').value.trim();
      try { await fetch('/api/bursts/label', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: b.id, label: label || text || 'other', text }) }); } catch (e) {}
      askNext();
    }
    document.querySelectorAll('#ask button[data-l]').forEach(x => x.onclick = () => askAnswer(x.dataset.l));
    $('askSend').onclick = () => askAnswer($('askText').value.trim() || 'other');
    $('askSkip').onclick = () => askNext();
    $('askOff').onclick = () => { askMuteUntil = Date.now() + 600000; askQ.length = 0; askNext(); };
    $('askWf').onclick = () => askCur && openSnippetById(askCur.snippet);
    // ---- snippet archive
    let snipData = { recent: [], files: [] };
    async function loadSnips() { try { snipData = await (await fetch('/api/snippets')).json(); renderSnips(); } catch (e) { $('snipCount').textContent = e.message; } }
    function renderSnips() {
      const q = $('snipQ').value.trim().toLowerCase(), f = $('snipF').value;
      const rec = new Map(snipData.recent.map(r => [r.id, r]));
      let all = snipData.recent.map(r => r.id).concat(snipData.files);
      const rows = [];
      for (const id of all) {
        const r = rec.get(id) || {}, q2 = (r.pair && r.pair.quality) || '', lost = id.startsWith('per_') || id.startsWith('fc_');
        if (f === 'lost' && !lost) continue; if (f && f !== 'lost' && q2 !== f) continue;
        if (q && !(id + ' ' + (r.kind || '') + ' ' + (r.src || '')).toLowerCase().includes(q)) continue;
        rows.push([id, r, q2, lost]); if (rows.length >= 400) break;
      }
      $('snipCount').textContent = `${rows.length} shown / ${all.length} (${baseName(snipData.dir)})`;
      const tb = $('snipList'); tb.innerHTML = '';
      for (const [id, r, q2, lost] of rows) {
        const tr = document.createElement('tr'); tr.className = 'click'; tr.onclick = () => openSnippetById(id, tr);
        tr.innerHTML = `<td>${esc(id)}</td><td>${hms(r.t)}</td><td>${esc(r.kind || (lost ? (id.startsWith('fc_') ? 'FC lost' : 'PER lost') : ''))}</td><td>${esc(r.src || '')}</td><td>${r.channel ?? ''}</td><td class="q-${q2}">${q2}</td>`; tb.appendChild(tr);
      }
    }
    $('snipQ').oninput = renderSnips; $('snipF').onchange = renderSnips; $('snipRefresh').onclick = loadSnips;
    async function openSnippetById(id, tr) {
      snipKey = 'snip:' + id;
      document.querySelectorAll('tr.sel').forEach(r => r.classList.remove('sel')); if (tr) tr.classList.add('sel');
      $('snip').classList.add('open'); $('snipTitle').textContent = id; $('snipMeta').textContent = 'loading...'; $('snipFoot').textContent = '';
      try {
        const res = await fetch('/api/snippets/' + encodeURIComponent(id)); if (!res.ok) throw new Error(res.status === 404 ? 'not saved (yet)' : res.status);
        const s = await res.json(); if (snipKey !== 'snip:' + id) return;
        const m = s.meta || {}, r = s.pair || {};
        $('snipTitle').textContent = `${m.kind || 'snippet'}${m.src ? ' from ' + m.src : ''}`;
        $('snipMeta').innerHTML = `${hms(m.t || s.t_packet)} | ch ${m.channel ?? '?'} (${m.freq_mhz ?? '?'} MHz)${m.rssi !== undefined && m.rssi !== null ? ' | RSSI ' + m.rssi + ' dBm' : ''}${m.len ? ' | ' + m.len + ' B' : ''}<br>` +
          (m.pcap_file ? `Wireshark: <b>${esc(m.pcap_file)}</b> frame <b>#${m.frame ?? '?'}</b><br>` : '') + (m.info ? esc(m.info) + '<br>' : '') +
          `RF burst: <span class="q-${r.quality}">${r.quality || '?'}</span>${r.per_label ? ' | label <span class="l-' + r.per_label + '">' + r.per_label + '</span>' : ''}${r.offset_ms !== null && r.offset_ms !== undefined ? ` | &Delta;t ${r.offset_ms} ms | peak ${r.peak_dbfs} dBFS (+${r.excess_db} dB over ${r.floor_dbfs})` : ''}`;
        if (!s.meta || s.meta.freq_mhz === undefined) s.meta = Object.assign({}, s.meta, { freq_mhz: m.freq_mhz || 2425 });
        drawSnippet(s); window.ssSnippet = { id, frames: s.db.length, bins: s.freqs_mhz.length, pair: s.pair };
        $('snipFoot').innerHTML = `snippet ${esc(id)}.npz | ${s.db.length} frames x ${s.freqs_mhz.length} bins | <a href="/api/snippets/${encodeURIComponent(id)}.npz" style="color:#7cf">download npz</a>`;
      } catch (e) { $('snipMeta').textContent = 'snippet ' + id + ': ' + e.message; }
    }
    function applyThread(m) {
      thread = m;
      const run = m.running || {};
      pill('pSn', m.enabled ? 'Sniffer ' + (run.sniffer === false ? 'down' : 'ok') : 'Sniffer off', !m.enabled ? '' : run.sniffer === false || run.tshark === false ? 'bad' : 'ok');
      pill('pWs', m.wireshark_connected ? 'Wireshark ' + m.wireshark_packets : 'Wireshark -', m.wireshark_connected ? 'ok' : '');
      pill('pCh', m.hop ? 'hop ' + m.hop.join(',') + ' @' + m.channel : 'ch ' + m.channel, 'info');
      $('hopInfo').textContent = `channel ${m.channel} (${m.channel_mhz} MHz)` + (m.hop ? `, hopping ${m.hop.join(',')} / ${m.dwell} s` : ', fixed');
      $('tstatus').textContent = m.enabled ? `802.15.4 ch ${m.channel} (${m.channel_mhz} MHz)${m.hop ? ' [hop ' + m.hop.join(',') + ' / ' + m.dwell + ' s]' : ''} | records ${m.records ?? 0} | file ${baseName(m.file) || '-'} | Wireshark ${m.wireshark_connected ? 'connected (' + m.wireshark_packets + ' pkts)' : 'not connected'}${m.pairing ? ' | RF pairing ' + Object.entries(m.pairing).map(([k, v]) => k + ' ' + v).join(', ') + (m.offset_median_ms !== null ? ' (median \u0394t ' + m.offset_median_ms + ' ms)' : '') : ''}` : '802.15.4 sniffer disabled';
    }
    function applyStatus(m) {
      const s = m.settings;
      if (s) {
        // adopt a centre set elsewhere (another browser, env) only when we are not tuning ourselves
        const hz = Math.round(s.freq_mhz * 1e6);
        if (!drag && !tuneTimer && (sentHz === null || hz === sentHz)) {
          if (viewHz !== hz) { viewHz = hz; showFreq(); render(); }
          sentHz = hz;
        }
        $('span').value = s.span; $('bins').value = s.bins; $('gain').value = s.gain; $('gainVal').textContent = s.gain; $('det').value = s.max_hold ? '1' : '0'; cur = s;
      }
      if (m.version !== undefined) fwBoardSet(m.version);
      pill('pEsp', 'ESP ' + m.state, m.state === 'streaming' ? 'ok' : m.state === 'error' ? 'bad' : 'warn');
      info = `${m.port} ${m.state}${m.spec ? ' [' + m.spec + ']' : ''}${m.error ? ' ERROR ' + m.error : ''}`;
      $('status').textContent = info;
    }
    const send = (o) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); };
    $('gain').oninput = () => $('gainVal').textContent = $('gain').value;
    $('gain').onchange = () => send({ gain: +$('gain').value });
    $('freq').onchange = () => setFreq(+$('freq').value * 1e6);
    $('span').onchange = () => send({ span: +$('span').value });
    $('bins').onchange = () => send({ bins: +$('bins').value });
    const resetTraces = () => { avg = null; peak = null; avgKey = ''; };
    $('det').onchange = () => { resetTraces(); send({ max_hold: $('det').value === '1' }); };
    $('ph').checked = localStorage.getItem('ss-peakhold') === '1';
    $('ph').onchange = () => { localStorage.setItem('ss-peakhold', $('ph').checked ? '1' : '0'); if (peak && avg) peak.set(avg); render(); };
    $('phClear').onclick = () => { if (peak && avg) peak.set(avg); render(); };
    $('avg').oninput = () => $('avgVal').textContent = (+$('avg').value).toFixed(2);
    $('centreThread').onclick = () => setFreq(thread.channel_mhz * 1e6);
    const baseName = (p) => (p || '').split(/[\\/]/).pop();   // never show host paths in the UI
    const tdec = new TextDecoder();
    function decodeSpec(buf) {          // u32 len | JSON meta | u16 (0.01 dB) or u8 (0.5 dB) codes, dB = code/scale - 140
      const ml = new DataView(buf).getUint32(0, true), m = JSON.parse(tdec.decode(new Uint8Array(buf, 4, ml))), off = 4 + ml;
      const q = m.enc === 'u16' ? new Uint16Array(buf, off, m.n) : new Uint8Array(buf, off, m.n), sc_ = m.enc === 'u16' ? 0.01 : 0.5;
      const db = new Float32Array(m.n); for (let i = 0; i < m.n; i++) db[i] = q[i] * sc_ - 140;
      m.db = db; return m;
    }
    function connect() {
      ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
      let backlog = true; setTimeout(() => backlog = false, 500);
      ws.onopen = () => sendStream();
      ws.binaryType = 'arraybuffer';
      ws.onmessage = (ev) => {
        if (ev.data instanceof ArrayBuffer) { const m = decodeSpec(ev.data); if (m) onSpec(m); return; }
        const m = JSON.parse(ev.data);
        if (m.type === 'spec' && m.q) { const b = atob(m.q), d = new Array(b.length); for (let i = 0; i < b.length; i++) d[i] = b.charCodeAt(i) / 2 - 140; m.db = d; }
        if (m.type === 'stream') { $('liteInfo').textContent = m.light ? `Light: max-hold, ${m.lite_hz}/s, up to ${m.lite_pts} pts (screen), 8-bit` : `Full: ${m.full_hz}/s, all bins, ${m.binary ? '16-bit binary' : 'JSON'}`; streamLight = !!m.light; }
        if (m.type === 'spec') onSpec(m);
        else if (m.type === 'pkt') addPacket(m, !backlog);
        else if (m.type === 'pair') setPair(m.id || ('t' + m.t), m.pair);
        else if (m.type === 'thread') { applyThread(m); render(); }
        else if (m.type === 'status') applyStatus(m);
        else if (m.type === 'per') onPer(m.run);
        else if (m.type === 'fc') onFc(m);
        else if (m.type === 'burst') onBurst(m);
        else if (m.type === 'burst_stats') { bStats = m; if (tab === 'bursts') renderBursts(); legendStats(); }
      };
      ws.onclose = () => { $('status').textContent = 'Disconnected - retrying...'; setTimeout(connect, 1000); };
    }
    function liteWanted() {
      const v = localStorage.getItem('ss-lite') || 'auto';
      if (v !== 'auto') return v === '1';
      return location.protocol === 'https:' || !['localhost', '127.0.0.1', '::1', '[::1]'].includes(location.hostname);
    }
    const wantPts = () => Math.max(64, Math.ceil(Math.max(100, sc.clientWidth - L) * (window.devicePixelRatio || 1)));
    function sendStream() { send({ type: 'stream', light: liteWanted(), pts: wantPts() }); }
    window.addEventListener('resize', () => { clearTimeout(window.__rs); window.__rs = setTimeout(sendStream, 400); });
    $('lite').value = localStorage.getItem('ss-lite') || 'auto';
    $('lite').onchange = () => { localStorage.setItem('ss-lite', $('lite').value); sendStream(); };
    // ---- firmware (Settings): board VERSION vs the bundled build, Web Serial installer (/static/flasher.js)
    let fwBundledRev = null, fwBoardRev = null;
    const fwShort = (v) => v && v.revision ? `${v.revision.slice(0, 7)} (${v.build_date || '?'})` : '-';
    function fwCompare() { $('fwCmp').textContent = fwBundledRev && fwBoardRev ? (fwBundledRev === fwBoardRev ? '= board (up to date)' : '!= board') : ''; }
    function fwBoardSet(ver) { let v = null; const t = String(ver || ''); try { v = JSON.parse(t.slice(t.indexOf('{'))); } catch (e) {} fwBoardRev = v && v.revision; $('fwBoard').textContent = v ? `${fwShort(v)} ${v.profile || ''}` : (t || '-'); fwCompare(); }
    fetch('/fw/version.json', { cache: 'no-cache' }).then(r => r.json()).then(v => { fwBundledRev = v.revision; $('fwBundled').textContent = `${fwShort(v)} ${v.profile || ''}`; fwCompare(); }).catch(() => { $('fwBundled').textContent = 'none'; });
    const fwLog = (s) => { const e = $('fwLog'); e.textContent += s + String.fromCharCode(10); e.scrollTop = e.scrollHeight; };
    $('fwInstall').onclick = async () => {
      if (!('serial' in navigator) || !window.isSecureContext || typeof EspFlasher === 'undefined') { fwLog('Web Serial is not available here: use desktop Chrome / Edge via http://localhost:8000 or https.'); return; }
      let port;
      try { port = await navigator.serial.requestPort({ filters: [{ usbVendorId: 0x303a }, { usbVendorId: 0x10c4 }, { usbVendorId: 0x1a86 }, { usbVendorId: 0x0403 }] }); }
      catch (e) { fwLog('No port selected.'); return; }
      const btn = $('fwInstall'); btn.disabled = true; $('fwProg').style.display = ''; $('fwProg').value = 0; $('fwLog').textContent = '';
      let released = false;
      try {
        fwLog('Downloading the bundled firmware...');
        const fa = await (await fetch('/fw/flash_args', { cache: 'no-cache' })).text(), images = [];
        for (const it of parseFlashArgs(fa)) {
          const r = await fetch('/fw/' + it.name, { cache: 'no-cache' }); if (!r.ok) throw new Error('missing ' + it.name);
          images.push({ offset: it.offset, name: it.name, data: new Uint8Array(await r.arrayBuffer()) });
        }
        fwLog('Releasing the SDR port in the dashboard...');
        const rr = await fetch('/api/fw/release', { method: 'POST' }); if (!rr.ok) throw new Error('release failed (' + rr.status + ')');
        released = true; await sleep(800);
        const usb = port.getInfo().usbVendorId === 0x303a;   // native USB Serial/JTAG vs USB-UART bridge
        await new EspFlasher(port, fwLog).flash(images, usb, (s, f) => { $('fwProg').value = f; $('fwState').textContent = s; });
        fwLog('Flashed and verified.');
      } catch (e) { fwLog('ERROR: ' + e.message); $('fwState').textContent = 'failed'; }
      finally {
        if (released) { await sleep(1500); fwLog('Dashboard reconnecting to the SDR...'); await fetch('/api/fw/reconnect', { method: 'POST' }).catch(() => {}); }
        btn.disabled = false;
      }
    };
    connect();
    showTab(localStorage.getItem('ss-tab') || 'live');
    window.addEventListener('resize', () => { if (tab === 'per' && perSel) loadRun(perSel); });
  </script>
</body>
</html>
"""


DEMO = os.environ.get("SNIFF_DEMO") == "1"
DEMO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo")
DEMO_TAGS = '<script>window.SS_DEMO_SAMPLE = "/demo/sample.json";</script>\n  <script src="/demo/player.js"></script>\n  '


def demo_html(tags: str = DEMO_TAGS) -> str:
    """Dashboard HTML with the canned-data player injected (it replaces /ws and /api/* in the browser)."""
    return HTML.replace('<script src="/static/flasher.js">', tags + '<script src="/static/flasher.js">', 1)


@app.get("/", response_class=HTMLResponse)
async def index():
    return demo_html() if DEMO else HTML


@app.get("/demo/{name}")
async def demo_file(name: str):
    if not DEMO or name not in ("player.js", "sample.json"):
        return JSONResponse({"error": "not found"}, status_code=404)
    mt = "application/javascript" if name.endswith(".js") else "application/json"
    return FileResponse(os.path.join(DEMO_DIR, name), media_type=mt, headers={"Cache-Control": "no-cache"})


@app.get("/api/snippets")
async def list_snippets():
    out, seen = [], set()
    for p in reversed(list(pkts.recent)):
        if p.get("id"):
            seen.add(p["id"])
            out.append({k: p.get(k) for k in ("id", "t", "src", "kind", "channel", "rssi", "lqi", "pcap_file", "frame", "pair")})
    older = []
    if os.path.isdir(SNIPPETS):
        older = sorted((f[:-4] for f in os.listdir(SNIPPETS) if f.endswith(".npz") and not f.endswith(".tmp.npz") and f[:-4] not in seen), reverse=True)
    return {"dir": SNIPPETS, "recent": out, "files": older[:2000]}


def _snip_path(sid: str):
    if not sid or any(c in sid for c in "/\\:") or sid.startswith("."):
        return None
    p = os.path.join(os.path.join(BURSTS, "snips") if sid.startswith("burst_") else SNIPPETS, sid + ".npz")
    return p if os.path.isfile(p) else None


@app.post("/api/bursts/label")
async def api_burst_label(body: dict):
    b = hub.bursts
    bid, label = str(body.get("id", "")), str(body.get("label", "")).strip()[:40]
    if not b or not bid or not label:
        return JSONResponse({"error": "id and label required"}, status_code=400)
    try:
        row = b.add_label(bid, label, str(body.get("text", ""))[:200])
    except KeyError:
        return JSONResponse({"error": "unknown burst"}, status_code=404)
    return {"ok": True, "row": row}


@app.get("/api/bursts")
async def api_bursts(n: int = 200):
    b = hub.bursts
    if not b:
        return {"stats": None, "recent": []}
    return {"stats": b.stats(), "recent": list(b.recent)[-max(1, min(n, 300)):]}


@app.get("/api/snippets/{sid}")
async def get_snippet(sid: str, format: str = "json"):
    p = _snip_path(sid[:-4] if sid.endswith(".npz") else sid)
    if not p:
        return JSONResponse({"error": "not found"}, status_code=404)
    if format == "npz" or sid.endswith(".npz"):
        return FileResponse(p, media_type="application/octet-stream", filename=os.path.basename(p))
    return await asyncio.get_running_loop().run_in_executor(None, rfpair.load, p)


@app.get("/favicon.ico")
async def favicon():
    from fastapi.responses import Response
    return Response(status_code=204)


@app.get("/api/per")
async def per_runs():
    if not pkts.per:
        return {"runs": [], "archived": [], "fc": [], "fc_events": []}
    return {"runs": pkts.per.summaries(), "archived": pkts.per.archived(), "fc": pkts.per.fc_summary(),
            "fc_events": list(pkts.per.fc_events)[-500:]}


@app.get("/api/per/{rid}")
async def per_run(rid: str):
    d = pkts.per.detail(rid) if pkts.per else None
    return d if d else JSONResponse({"error": "not found"}, status_code=404)


FW_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firmware")
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


@app.get("/fw/{name:path}")
async def fw_file(name: str):
    """Bundled ESP32-S3 SDR firmware: flash_args, images, version.json (for the web flasher)."""
    base = os.path.realpath(FW_DIR)
    p = os.path.realpath(os.path.join(base, name))
    if not p.startswith(base + os.sep) or not os.path.isfile(p):
        return JSONResponse({"error": "not found"}, status_code=404)
    mt = "application/json" if p.endswith(".json") else "text/plain" if os.path.basename(p) == "flash_args" else "application/octet-stream"
    return FileResponse(p, media_type=mt, headers={"Cache-Control": "no-cache"})


@app.get("/static/flasher.js")
async def flasher_js():
    return FileResponse(os.path.join(STATIC_DIR, "flasher.js"), media_type="application/javascript", headers={"Cache-Control": "no-cache"})


@app.post("/api/fw/release")
async def fw_release():
    """Free the SDR COM port so the browser can flash it (auto-reconnect after 3 min)."""
    await hub.release()
    return {"ok": True, "port": PORT}


@app.post("/api/fw/reconnect")
async def fw_reconnect():
    await hub.reconnect()
    return {"ok": True}


@app.get("/api/info")
async def api_info():
    return {"status": hub.status, "thread": pkts.info(), "settings": hub._pub(hub.settings),
            "spec_bytes_out": dict(hub.bytes_out), "perf": dict(hub.perf), "push_hz": PUSH_HZ, "lite_hz": LITE_HZ, "ws_json": WS_JSON, "clients": len(hub.clients), "lite_clients": len(hub.lite),
            "bursts": hub.bursts.stats() if hub.bursts else None}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    hub.clients.add(ws)
    await ws.send_json({"type": "hello", "msg": "Sniff-Sight dashboard ready"})
    await ws.send_json(hub.status)
    await ws.send_json(pkts.info())
    if pkts.per:
        for r in pkts.per.summaries()[:20]:
            await ws.send_json({"type": "per", "run": r})
    for p in list(pkts.recent)[-100:]:
        await ws.send_json(p)
    try:
        while True:
            msg = await ws.receive_json()
            if isinstance(msg, dict) and msg.get("type") == "stream":
                (hub.lite.add if msg.get("light") else hub.lite.discard)(ws)
                if msg.get("pts"):
                    hub.lite_pts[ws] = max(16, min(8192, int(msg["pts"])))
                await ws.send_json({"type": "stream", "light": ws in hub.lite, "lite_hz": LITE_HZ, "lite_pts": hub.lite_pts.get(ws, LITE_BINS),
                                    "full_hz": PUSH_HZ, "binary": not WS_JSON})
            elif isinstance(msg, dict) and msg.get("type") != "ping":
                hub.update(msg)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        hub.clients.discard(ws)
        hub.lite.discard(ws)
        hub.lite_pts.pop(ws, None)


# optional login (SNIFF_AUTH="user:pass"), covers every route incl. /ws and /api
if os.environ.get("SNIFF_AUTH"):
    from .auth import AuthMiddleware
    fastapi_app = app
    app = AuthMiddleware(fastapi_app, os.environ["SNIFF_AUTH"])
