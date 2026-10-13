"""ESP32-S3 ESP-SDR client for IQ and spectrum streaming.

Based on the ESP-SDR protocol (IQS / SPEC commands).
See https://github.com/ESPARGOS/esp-sdr
"""

import asyncio
import math
import re
import struct
import time
import zlib

import numpy as np
from dataclasses import dataclass
from typing import Optional, AsyncIterator

try:
    import serial_asyncio
except ImportError:
    serial_asyncio = None


@dataclass
class IQFrame:
    sequence: int
    sample_index: int
    samples: int
    bits: int
    flags: int
    decimation: int
    gain: int
    shift: int
    iq: bytes  # interleaved I,Q


@dataclass
class SpecFrame:
    sequence: int
    sample_index: int
    samples_spanned: int
    ffts: int
    flags: int
    gain: int
    drops: int
    log2_bins: int
    db_mult: int
    bins: bytes  # power codes (0-255)


@dataclass
class Spectrum:
    sequence: int
    flags: int
    gain: int
    drops: int
    ffts: int
    n: int
    dbfs: list  # low -> high frequency, index n//2 = centre (LO)
    sample_index: int = 0
    spanned: int = 0
    t_arrival: float = 0.0


# 2.2-2.8 GHz tuning range and SPECINFO fallback profiles, as in z2-web-sdr
FMIN, FMAX = 2_204_000_000, 2_804_000_000
SPEC_FALLBACK = [
    [16000000, 6, 256, 2, 1], [16000000, 6, 1024, 2, 4], [16000000, 6, 2048, 3, 7],
    [40000000, 1, 256, 5, 3], [40000000, 1, 1024, 5, 9], [40000000, 1, 2048, 7, 17],
    [80000000, 0, 256, 10, 5], [80000000, 0, 1024, 14, 16], [80000000, 0, 2048, 14, 30],
]


class ESP32SDR:
    def __init__(self, port: str, baud: int = 115200):
        self.port = port
        self.baud = baud
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    async def connect(self):
        if serial_asyncio is None:
            raise RuntimeError("pip install pyserial-asyncio")
        self.reader, self.writer = await serial_asyncio.open_serial_connection(
            url=self.port, baudrate=self.baud
        )
        await asyncio.sleep(0.1)

    async def send_cmd(self, cmd: str):
        if not self.writer:
            raise RuntimeError("not connected")
        self.writer.write((cmd + "\n").encode())
        await self.writer.drain()

    async def start_iq(self, decimation: int = 64, bits: int = 8, rate_code: int = 6, mode: int = 2):
        """Start continuous IQ stream. decimation 64 = 250 kS/s at 16 MS/s."""
        await self.send_cmd(f"IQS 0 {decimation} {bits} {rate_code} 0 {mode}")
        line = await self.reader.readline()
        print("[esp32]", line.decode(errors="replace").strip())

    async def start_spec(self, fft_bins: int = 256, rate_code: int = 0, detector: int = 0):
        """Start spectrum streaming."""
        await self.send_cmd(f"SPEC 0 1 1 {detector} {rate_code} {fft_bins}")
        line = await self.reader.readline()
        print("[esp32]", line.decode(errors="replace").strip())

    async def stop(self):
        if self.writer:
            self.writer.write(b"\n")
            await self.writer.drain()

    async def _sync_to_magic(self, magic: bytes) -> bytes:
        """Read until magic is found, return the magic."""
        buf = b""
        while True:
            b = await self.reader.readexactly(1)
            buf = (buf + b)[-len(magic):]
            if buf == magic:
                return magic

    async def read_spec_frames(self) -> AsyncIterator[SpecFrame]:
        """Yield SpecFrame objects from SPC1 binary frames."""
        while True:
            await self._sync_to_magic(b"SPC1")
            rest = await self.reader.readexactly(24)  # 28-byte header total, we already have 4
            # header: magic(4) + seq(4) + idx(8) + spanned(4) + ffts(2) + flags(1) + gain(1) + drops(2) + log2(1) + dbmult(1)
            seq, idx, spanned, ffts, flags, gain, drops, log2_bins, db_mult = struct.unpack(
                "<IQIHBBHBB", rest
            )
            n_bins = 1 << log2_bins
            bins = await self.reader.readexactly(n_bins)
            crc = await self.reader.readexactly(4)
            # optional CRC check
            # calc = zlib.crc32(b"SPC1" + rest + bins) & 0xffffffff
            yield SpecFrame(seq, idx, spanned, ffts, flags, gain, drops, log2_bins, db_mult, bins)

    async def read_iq_frames(self) -> AsyncIterator[IQFrame]:
        """Yield IQS1 frames."""
        while True:
            await self._sync_to_magic(b"IQS1")
            rest = await self.reader.readexactly(20)
            seq, idx, nsamp, bits, flags, decim, gain, shift = struct.unpack("<IQHBBHBB", rest)
            payload_len = nsamp * (2 if bits == 8 else 4 if bits == 16 else 1)
            payload = await self.reader.readexactly(payload_len)
            crc = await self.reader.readexactly(4)
            yield IQFrame(seq, idx, nsamp, bits, flags, decim, gain, shift, payload)

    # ------------------------------------------------------------------
    # Spectrum setup as in z2-web-sdr (src/index.html, SerialSource) and
    # sdrpp-esp-sdr-source (esp_sdr_client.cpp). Those are the reference.

    async def _quiet(self, quiet: float = 0.25, limit: float = 3.0):
        """Read and discard until the line has been silent for `quiet` s."""
        loop = asyncio.get_running_loop()
        t_end = loop.time() + limit
        while loop.time() < t_end:
            try:
                await asyncio.wait_for(self.reader.read(65536), quiet)
            except asyncio.TimeoutError:
                return

    async def command(self, cmd: str, expect: str = "", timeout: float = 1.5) -> Optional[str]:
        """Send a text command; return the first reply line starting with `expect`
        (any line if expect is empty), or None on timeout."""
        await self.send_cmd(cmd)
        loop = asyncio.get_running_loop()
        t_end = loop.time() + timeout
        while True:
            left = t_end - loop.time()
            if left <= 0:
                return None
            try:
                line = await asyncio.wait_for(self.reader.readline(), left)
            except asyncio.TimeoutError:
                return None
            text = line.decode(errors="replace").strip()
            if not expect or text.startswith(expect):
                return text
            if text.startswith("ERR"):
                return text

    async def handshake(self) -> dict:
        """Stop any running stream, wait for quiet, then CAPS / VERSION? / SPECINFO?."""
        caps = None
        for _ in range(3):
            await self.send_cmd("")
            await self._quiet()
            caps = await self.command("CAPS", "CAPS")
            if caps and caps.startswith("CAPS"):
                break
        if not caps or not caps.startswith("CAPS"):
            raise RuntimeError(f"no ESP-SDR firmware answering on {self.port}")
        if not re.search(r" SPEC( |$)", caps):
            raise RuntimeError("firmware has no SPEC mode")
        info = await self.command("INFO", "S")
        version = await self.command("VERSION?", "VERSION") if " VERSION " in caps + " " else None
        si = await self.command("SPECINFO?", "SPECINFO")
        self.profiles = [
            [int(x) for x in re.split(r"[\s,]+", m.strip()) if x][:5]
            for m in re.findall(r"\[([-\d\s,]+)\]", si or "")
        ]
        self.profiles = [v for v in self.profiles if len(v) >= 5] or SPEC_FALLBACK
        return {"caps": caps, "info": info, "version": version, "specinfo": si}

    def profile(self, rate: int, bins: int):
        for v in list(getattr(self, "profiles", [])) + SPEC_FALLBACK:
            if v[0] == rate and v[2] == bins:
                return v[1], v[3], v[4]  # code, stride, upf
        if bins > 2048:   # experimental: firmware without a 4096 profile in SPECINFO -> derive from 2048
            for v in list(getattr(self, "profiles", [])) + SPEC_FALLBACK:
                if v[0] == rate and v[2] == 2048:
                    return v[1], v[3] * 2, max(1, v[4] // 2)
        return 6, 2, 1

    async def start_spectrum(self, freq_hz: float = 2437e6, span: int = 80_000_000, bins: int = 2048,
                             gain: int = 60, max_hold: bool = False, dc_fix: bool = True, ppm: float = 0.0) -> str:
        """Configure and start SPEC exactly like z2-web-sdr startStream()."""
        fk = round(freq_hz * (1 - ppm * 1e-6) / 1e3)
        fk = max(FMIN // 1000, min(FMAX // 1000, fk))
        note = ""
        if bins > 2048 and not any(v[0] == span and v[2] == bins for v in getattr(self, "profiles", [])):
            # firmware answers "ERR nfft" when SPECINFO has no such profile (verified for 4096) -> stay on 2048
            note = f" ({bins} bins not in firmware SPECINFO -> 2048)"
            bins = 2048
        code, stride, upf = self.profile(span, bins)
        unit_us = int(12288 * 1e6 / span)
        upf = max(upf, min(1000, 20000 // max(1, unit_us)))
        await self.command(f"FREQ {fk // 1000}", "OK")
        await self.command(f"FOFS {fk % 1000}", "OK")
        await self.command(f"GAIN MANUAL {gain}", "OK")
        await self.command(f"BANDWIDTH {0 if span > 16_000_000 else 20}", "OK")
        await self.command("DC 0" if dc_fix else "DC 1", "", 0.8)
        self.spec_dc_fix = dc_fix
        self.spec_center_hz = fk * 1e3 / (1 - ppm * 1e-6)
        await self.send_cmd(f"SPEC 0 {stride} {upf} {1 if max_hold else 0} {code} {bins}")
        line = await asyncio.wait_for(self.reader.readline(), 2.0)
        return line.decode(errors="replace").strip() + note

    async def stop_stream(self, timeout: float = 2.0):
        """Any host byte ends a run; wait for the SPECEND line (or quiet)."""
        await self.send_cmd("")
        loop = asyncio.get_running_loop()
        t_end = loop.time() + timeout
        tail = b""
        while loop.time() < t_end:
            try:
                chunk = await asyncio.wait_for(self.reader.read(65536), 0.25)
            except asyncio.TimeoutError:
                break
            tail = (tail + chunk)[-4096:]
            p = tail.rfind(b"SPECEND")
            if p >= 0 and tail.find(b"\n", p) > p:
                break
        await self._quiet(0.1, 0.5)

    async def restore_defaults(self):
        """Firmware defaults for other clients (as z2-web-sdr close())."""
        await self.command("BANDWIDTH 20", "OK", 0.8)
        await self.command("DC 1", "", 0.8)

    async def read_spectra_dbfs(self) -> AsyncIterator["Spectrum"]:
        """CRC-checked SPC1 frames converted like z2-web-sdr parseSpc1():
        fftshift + mirror (S3: RF above LO is negative), code/step - 84.3 dBFS,
        code 0 -> -140, DC bin filled from neighbours when DC 0 is active.
        Output index j covers centre + (j - n/2) * span / n, low to high."""
        self.crc_errors = 0
        while True:
            await self._sync_to_magic(b"SPC1")
            hdr = await self.reader.readexactly(24)
            log2n = hdr[22]
            if log2n < 6 or log2n > 12:
                continue
            n = 1 << log2n
            body = await self.reader.readexactly(n + 4)
            t_arr = time.time()
            codes, crc = body[:n], struct.unpack("<I", body[n:])[0]
            if zlib.crc32(b"SPC1" + hdr + codes) & 0xFFFFFFFF != crc:
                self.crc_errors += 1
                continue
            seq, idx, spanned, ffts, flags, gain, drops, _, step = struct.unpack("<IQIHBBHBB", hdr)
            step = step or 2
            h = n // 2
            # vectorised (4096 bins at >100 frames/s is too slow per element in Python)
            v = np.frombuffer(codes, dtype=np.uint8)[(h - np.arange(n)) % n].astype(np.float32)
            db = np.where(v > 0, v / step - 84.3, -140.0).astype(np.float32)
            if getattr(self, "spec_dc_fix", False):
                a, b = 10 ** (db[h - 1] / 10), 10 ** (db[h + 1] / 10)
                db[h] = 10 * math.log10(0.5 * (a + b))
            yield Spectrum(seq, flags, gain, drops, ffts, n, db, idx, spanned, t_arr)

    async def close(self, timeout: float = 2.0):
        """Close the port. wait_closed() can hang on Windows while the device
        is still streaming, so bound it and force-close the serial handle."""
        if self.writer:
            transport = self.writer.transport
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), timeout)
            except Exception:
                pass
            ser = getattr(transport, "serial", None) or getattr(transport, "_serial", None)
            try:
                if ser is not None and ser.is_open:
                    ser.close()
            except Exception:
                pass
            try:
                transport.abort()
            except Exception:
                pass
            self.writer = None
            self.reader = None
