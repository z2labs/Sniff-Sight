"""Orchestrator: manages ESP32-S3 SDR and 802.15.4 sniffer, correlates events."""

import asyncio
from dataclasses import dataclass
from typing import Optional

from .esp32_sdr import ESP32SDR, IQFrame, SpecFrame

@dataclass
class SpectrumFrame:
    timestamp: float
    freq_mhz: float
    bins: list[float]  # power values

@dataclass
class PacketEvent:
    timestamp: float
    channel: int
    rssi: Optional[int]
    raw: bytes

class Orchestrator:
    def __init__(self):
        self.spectrum_queue: asyncio.Queue[SpectrumFrame] = asyncio.Queue()
        self.packet_queue: asyncio.Queue[PacketEvent] = asyncio.Queue()
        self.esp: Optional[ESP32SDR] = None

    async def start_esp32(self, port: str, mode: str = "spec"):
        """Connect to ESP32-S3 and stream spectrum or IQ."""
        self.esp = ESP32SDR(port)
        await self.esp.connect()
        if mode == "iq":
            await self.esp.start_iq()
            asyncio.create_task(self._iq_loop())
        else:
            await self.esp.start_spec()
            asyncio.create_task(self._spec_loop())
        print(f"[esp32] started on {port} ({mode})")

    async def _iq_loop(self):
        async for frame in self.esp.read_iq_frames():
            # TODO: convert to spectrum or forward IQ
            print(f"[iq] seq={frame.sequence} samples={frame.samples}")

    async def _spec_loop(self):
        # TODO: implement SpecFrame reader similar to IQ
        while True:
            await asyncio.sleep(0.1)

    async def start_sniffer(self, port: str):
        """Connect to SiLabs/Nordic 802.15.4 sniffer."""
        # TODO: implement packet capture + PCAP/TAP to Wireshark
        print(f"[sniffer] would open {port}")

    async def run(self):
        """Main correlation loop."""
        print("[orchestrator] running")
        while True:
            await asyncio.sleep(1)
