# Sniff-Sight – Thread test-traffic plan (debug / correlation / snippets)

Tools: `traffic_test.py` (this folder). CSV log: `captures/traffic/traffic_*.csv`
(columns: `host_iso, host_epoch, t_rel_s, node, kind(cmd/rx/mark/error), phase, channel, text`).
The host timestamp of a `cmd` row is taken just before the command is written to the serial port. The radio transmission usually follows 5–30 ms later (USB + CLI + CSMA).
The running launcher does not need to be stopped. The script only uses the C6 consoles (leader, optionally a second node).

## ot_cli observations (ESP-IDF 5.5.5)
* A plain `ot ping` **blocks the console** until its timeout (default 3 s). The script therefore uses `ot ping async <ip> <size> <count> <interval> 64 <timeout>` with a 0.05 s timeout. Only one ping can run at a time (`Error 5: Busy`).
* Ping syntax: `ping [async] <ip> [size] [count] [interval s] [hoplimit] [timeout s]`. Other commands: `udp open / bind / send <ip> <port> <text | -s N> / close`, `scan [ch]`, `scan energy [ms]`, `discover [ch]`, `txpower [dBm]`, `counters mac`.
* Opening the port without DTR/RTS = 0 **resets the C6** (USB-Serial-JTAG). The script handles this; watch out in your own terminal as well.
* Channel change uses a pending dataset (`dataset init active` → `activetimestamp N+1` → `channel X` → `delay 5000` → `commit pending`). Attached nodes follow automatically. The active timestamp grows with every change, which is harmless.
* With a single node, a multicast ping (ff02::1) does go on air (the TxBroadcast counter increases), but nothing answers, so "0 received" is normal.

## Phases (`--phases`, default: all; repeated per channel)
| Phase | What it does | Expected waterfall / pairing |
|---|---|---|
| state | state, addresses, `counters mac` (for before/after comparison) | no RF |
| burst | 3×3 small pings (16 B), ~150 ms apart, 1.5 s pause | clearly separated "III  III  III" pattern; one RF burst (~1 ms) per packet |
| sizes | 16/64/80 B (1 frame), 200/400/1000 B (6LoWPAN fragments: 2/4/9+ frames) every 0.8 s | burst length/count grows; fragments ~4–5 ms apart are at the limit of the 4.5 ms spectrum frame, so pairing can mix them up |
| udp | UDP 5/50/120/300 B to ff02::1:61631 (+ node2 60 B) | like sizes, but UDP |
| density | 32 B ping 10×0.2 s, 20×0.05 s, 30×0.02 s | 5/s → 20/s → 50/s; at 20 ms there are 4–5 spectrum frames per packet, check that there is no double pairing |
| unicast* | to node2 ML-EID 16/100/400/1200 B + a burst of 3 | data + ACK (≈192 µs later, same spectrum frame) + echo reply + ACK; the sniffer sees the ACK as a separate packet, in RF they merge |
| sed* | node2 as SED (mode -, poll 300 ms) for 6 s, then an indirect ping | regular 300 ms "comb" of MAC Data Request + ACK, then back to normal |
| txpower | C6 TX power 20, 10, 0, −10, −15, −20, −24 dBm; 3 pings + 1×400 B per step, restored at the end | burst amplitude steps down; at low levels **RF bursts without packets** appear (the sniffer lost them) |
| scan | `scan` (beacon requests 11–26), `discover` (MLE discovery 11–26), `scan energy 100` | short attempts sweep every channel (~0.3 s/ch); only the sniffer's channel yields packets, the rest are unmatched RF |

\* only with `--port2`.

## Timing (approx.)
A full phase sequence takes ≈1.5–2 min per channel. Suggested: `--channels 15,20` (with the SDR at 2437 MHz / 40 MHz span, channels 14–21 are visible; ch15 = 2425, ch20 = 2450 MHz). Channel 25 (2475 MHz) needs another SDR centre (`--freq`).
A channel change and the return to 15 take about 10 s each. The script always returns to `--home 15` and the original TX power at the end.

## Sniffer channel
* Fixed (`--channel 15`): during ch20 phases the sniffer is "blind", so RF bursts appear without packets (an intentional negative test).
* Following: restart the launcher with `--hop 15,20 --dwell 2`. This gives about 50 % coverage per channel; filter by the CSV `channel` column and the sniffer hop times. For exact comparisons prefer fixed channel = test channel (`--channel 20`).

## Provoking failures (lost packets, FCS/CRC errors, blind periods)
1. **Weak signal:** `txpower` phase plus distance/shielding (move node2 or the sniffer away, metal box, hand on the antenna). Metrics: C6 `counters mac` (RxErrFcs, TxRetry, TxDirectMaxRetryExpiry, TxErrCca) before/after; the `state` phase logs them.
2. **Interference:** Wi-Fi traffic on ch1/ch6 (2412/2437 MHz overlap Thread ch12–13 / ch17–18), e.g. a large download through a nearby AP, with Thread on ch17/18 (`--channels 17`). Expect FCS errors/losses where Wi-Fi bursts overlap. A microwave oven affects ch20 and above.
3. **Blind period:** sniffer on another channel (fixed 15, test 20) or during hop dwell. Every RF burst is unmatched, which validates the unmatched-burst detection.
4. **Collisions:** run density phases on two nodes at once (node2 `ping async` simultaneously). Expect CCA failures and retries; with unicast, missing ACKs cause retry series (same sequence number 3–4×).
5. Expected signs: (a) RF burst without a packet, (b) packet without an RF burst (SDR dynamic range / span limit), (c) retries: the same `wpan.seq_no` repeats, (d) C6 counters increase.

### xG24 RCP sniffer and bad FCS
* `spinel_sniffer.py` **recomputes the FCS** of the PSDU received from the RCP (the RCP does not deliver a valid FCS), so `wpan.fcs_ok` is **always True** in the pcap and dashboard. Host-side FCS errors cannot be detected.
* The OpenThread EFR32 RCP (RAIL) drops frames with CRC errors in the radio by default (RAIL_RX_OPTION_IGNORE_CRC_ERRORS is not set in the platform code; based on the GSDK source, not verified on hardware). Frames with bad CRC therefore **never reach** the host.
* Consequence: the proxy for a CRC error is an **unmatched RF burst** on the Thread channel (seen by the SDR, not by the sniffer) plus the C6 `RxErrFcs` counter. Capturing real bad-FCS frames needs a custom RCP build (IGNORE_CRC_ERRORS + forwarding the original FCS).

## Example commands
```bash
# 0) second C6 setup: SETUP_NODE2.md
# 1) smoke test
python tools/traffic/traffic_test.py --port2 COM9 --phases state,burst
# 2) full sequence on ch15 (sniffer fixed on 15)
python tools/traffic/traffic_test.py --port2 COM9 --channels 15
# 3) channel steps + blind-period test (sniffer stays on 15)
python tools/traffic/traffic_test.py --port2 COM9 --channels 15,20,15 --phases burst,sizes,density
# 4) weak signal / failure provoking
python tools/traffic/traffic_test.py --port2 COM9 --phases state,txpower,unicast,state --repeat 2
# dry run (no serial port): --dry-run
```

## PER measurement (loss ledger)
* **Primary, no keys needed:** per source (src + `mac`/`mle` stream) the aux-security frame counter; a gap = lost frame, the same FC again = retransmission; DSN as a side signal (`dsn_skip`). Works on foreign networks too. Output: `captures/per/fc_missed_YYYYMMDD.csv`, `fc_summary.json`, snippets `fc_<src>_<stream>_<fc>.npz` (interpolated time).
* **Secondary (needs decryption):** `--phases per` / `pertx` → UDP payload `SSPR,<run>,<seq>,<tx_ms>,<ch>,<txp>,...`; TX list `captures/per/per_<run>_tx.csv`; ledger `per_<run>_ledger.csv`, `per_<run>_summary.json`, ML labels `per_labels.csv`, snippets `per_<run>_<seq>.npz`.
* Labels: `lost-with-burst` (an RF burst at the expected time → the sniffer lost it / CRC), `lost-no-burst`, `sniffer-blind` (sniffer on another channel), `lost-nospec`, `lost-time-unknown` (FC: neighbouring frames too far apart).
* Commands: `python tools/traffic/traffic_test.py --phases per --per-count 200 --per-interval 0.1`; TX power steps: `--phases pertx --per-txpowers 20,0,-10,-20,-24`; from node2: `--port2 COM9 --per-node node2 --per-dst <leader ML-EID>`.
* Dashboard: **PER / Test** tab (FC ledger + SSPR runs, sequence strip, click → spectrum snippet).
