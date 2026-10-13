"""OpenThread RCP sniffer -> pcap (IEEE 802.15.4 TAP, DLT 283) on stdout.

Run with the pyspinel venv's python (it needs the `spinel` package):
    python spinel_sniffer.py -u COM16 -b 460800 --channels 15
    python spinel_sniffer.py -u COM16 -b 460800 --channels 11,15,20,25 --dwell 2

Replaces pyspinel's sniffer.py for Sniff-Sight because:
  * sniffer.py --rssi swaps RSSI/LQI relative to the TI CC24xx layout it
    claims; here each frame gets a TAP header with FCS-type, RSS (dBm, float),
    LQI and channel TLVs, plus the recomputed FCS, so Wireshark/tshark show the
    right values without any wpan.fcs_format setting;
  * it can hop channels (PROP_PHY_CHAN) while streaming.
stderr carries status lines; "CHANNEL <n>" announces each channel change.
"""

import optparse
import struct
import sys
import threading
import time

from spinel.codec import WpanApi
from spinel.const import SPINEL
from spinel.stream import StreamOpen

DLT_IEEE802_15_4_TAP = 283


def crc16_kermit(data: bytes) -> int:
    crc = 0
    for c in data:
        q = (crc ^ c) & 0x0F
        crc = (crc >> 4) ^ (q * 0x1081)
        q = (crc ^ (c >> 4)) & 0x0F
        crc = (crc >> 4) ^ (q * 0x1081)
    return crc


def tlv(t: int, value: bytes) -> bytes:
    pad = (-len(value)) % 4
    return struct.pack("<HH", t, len(value)) + value + b"\0" * pad


def tap_frame(psdu: bytes, rssi: float, lqi: int, channel: int) -> bytes:
    body = bytearray(psdu)
    if len(body) >= 2:   # the RCP does not deliver a valid FCS: recompute it
        c = crc16_kermit(bytes(body[:-2]))
        body[-2], body[-1] = c & 0xFF, c >> 8
    tlvs = (tlv(0, bytes([1]))                          # FCS type: 16-bit CRC
            + tlv(1, struct.pack("<f", float(rssi)))    # RSS in dBm
            + tlv(10, bytes([lqi & 0xFF]))              # LQI
            + tlv(3, struct.pack("<HB", channel, 0)))   # channel, page 0
    return struct.pack("<BBH", 0, 0, 4 + len(tlvs)) + tlvs + bytes(body)


def log(msg: str):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def main():
    op = optparse.OptionParser()
    op.add_option("-u", "--uart", default="COM16")
    op.add_option("-b", "--baudrate", type="int", default=460800)
    op.add_option("--rtscts", action="store_true", default=False)
    op.add_option("--channels", default="15", help="one channel, or a comma list to hop over")
    op.add_option("--dwell", type="float", default=2.0, help="seconds per channel when hopping")
    op.add_option("--no-reset", action="store_true", default=False)
    o, _ = op.parse_args()
    channels = [int(c) for c in o.channels.split(",") if c.strip()]
    if not channels or any(c < 11 or c > 26 for c in channels):
        log("ERROR: channels must be 11..26")
        sys.exit(2)

    api = stream = None
    for attempt in range(1, 6):
        stream = StreamOpen("u", o.uart, False, o.baudrate, o.rtscts)
        if stream is None:
            log(f"attempt {attempt}: cannot open {o.uart}")
        else:
            api = WpanApi(stream, 34)
            api.queue_register(SPINEL.HEADER_DEFAULT)
            api.queue_register(SPINEL.HEADER_ASYNC)
            log(f"Initializing sniffer (attempt {attempt})...")
            if not o.no_reset or attempt > 1:
                api.cmd_send(SPINEL.CMD_RESET)
                time.sleep(1.0 + 0.5 * attempt)
            api.prop_set_value(SPINEL.PROP_PHY_ENABLED, 1)
            ok = (api.prop_set_value(SPINEL.PROP_MAC_FILTER_MODE, SPINEL.MAC_FILTER_MODE_MONITOR) is not None
                  and api.prop_set_value(SPINEL.PROP_PHY_CHAN, channels[0]) is not None
                  and api.prop_set_value(SPINEL.PROP_MAC_RAW_STREAM_ENABLED, 1) is not None)
            if ok:
                break
            log(f"attempt {attempt}: RCP did not answer, resetting and retrying")
            try:
                api._reader_alive = False
                stream.close()
            except Exception:
                pass
            api = None
        time.sleep(min(8.0, 1.0 * 2 ** (attempt - 1)))
    if api is None:
        log("ERROR: failed to initialize sniffer")
        sys.exit(1)
    current = [channels[0]]
    log("SUCCESS: sniffer initialized")
    log(f"CHANNEL {channels[0]}")

    out = sys.stdout.buffer
    out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, DLT_IEEE802_15_4_TAP))
    out.flush()

    if len(channels) > 1:
        def hop():
            i = 0
            while True:
                time.sleep(o.dwell)
                i = (i + 1) % len(channels)
                ch = channels[i]
                if api.prop_set_value(SPINEL.PROP_PHY_CHAN, ch) is not None:
                    current[0] = ch
                    log(f"CHANNEL {ch}")
                else:
                    log(f"WARNING: channel {ch} not set")
        threading.Thread(target=hop, daemon=True).start()

    try:
        while True:
            r = api.queue_wait_for_prop(SPINEL.PROP_STREAM_RAW, SPINEL.HEADER_ASYNC)
            if not r or r.prop != SPINEL.PROP_STREAM_RAW:
                continue
            n = api.parse_S(r.value)
            psdu = r.value[2:2 + n]
            meta = r.value[2 + n:]
            rssi, lqi, ch = 127, 0, current[0]
            try:
                if len(meta) >= 19:
                    m = api.parse_fields(meta[:19], "ccSt(CCX)t(i)")
                    rssi, ch, lqi = m[0], m[3][0] or ch, m[3][1]
                elif len(meta) >= 17:
                    m = api.parse_fields(meta[:17], "ccSt(CCLS)t(i)")
                    rssi, ch, lqi = m[0], m[3][0] or ch, m[3][1]
            except Exception:
                pass
            rec = tap_frame(psdu, rssi, lqi, ch)
            t = time.time()
            out.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(rec), len(rec)) + rec)
            out.flush()
    except (KeyboardInterrupt, BrokenPipeError, OSError):
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
