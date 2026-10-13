# RF burst classes (sniff_sight/bursts.py)

## How it works
Every frame of the spectrum stream (ESP32-S3 ESP-SDR, default 80 MHz span / 2048 bins, ~4.5 ms/frame) is processed in a separate thread:
1. **Noise floor** per bin: 20th-percentile tracker (0.25 dB/frame), 5-bin smoothing, so bursts and single deep bins do not drag it.
2. **Detection**: bin > floor + 8 dB; adjacent hot bins form segments (gaps up to 1 MHz bridged, min. 0.5 MHz); segments that overlap in frequency in consecutive frames are one burst (1 missing frame allowed, max 400 frames).
3. **Closing**: after the burst ends the engine waits 0.6 s (packet pairing arrives in that time and provides ground truth), then computes the features and the class.

## Features (CSV columns, `captures/bursts/bursts_YYYYMMDD.csv`)
| column | meaning |
|---|---|
| t0, t1, duration_ms, frames | time (host clock), length; resolution = 1 spectrum frame (~4.5 ms) |
| f_center_mhz | power-weighted centre frequency of the -10 dB core |
| f_lo/f_hi_mhz, f_mid20_mhz | detected extent, centre of the -20 dB band |
| bw10_mhz, bw20_mhz | -10 / -20 dB bandwidth of the burst's max-hold spectrum |
| peak/mean_excess_db, peak_dbfs, floor_dbfs | peak/mean above the floor, absolute level |
| rise_ms, fall_ms | time to / after the peak (frame-quantised) |
| flatness | spectral flatness (geometric/arithmetic mean in the -10 dB band; OFDM ~ 1) |
| occupied_bins, symmetry | occupied bins, left/right power asymmetry (-1..1) |
| drift_mhz_s, drift_range_mhz | slope / range of the per-frame centre frequency |
| ibi_ms, ibi_med_ms, ibi_std_ms | inter-burst interval in the same 1 MHz cell (periodicity) |
| cls, confidence, reason | rule-based class, 0..1 confidence, reason |
| gt, gt_pkt | ground truth: a paired (matched) 802.15.4 packet inside the burst (±6 ms, ±1.5 MHz) |
| snippet | `captures/bursts/snips/burst_<id>.npz` (rfpair format, the dashboard opens it) |

Snippets: at most 20 per class per minute, plus every ground-truth contradiction and every "What is this?" question.

## Classes and rules (first version)
* **wifi** - -20 dB band ≥ 9 MHz, centre on the Wi-Fi grid (2412+5(k-1), ±3 MHz), no 50 Hz period. (OFDM 20 MHz; because of the 4.5 ms averaging the -10 dB band is often only 4-8 MHz.)
* **ieee802154** - ~2 MHz (bw10 ≤ 3.5), centre on the 2405+5(k-11) grid ±0.7 MHz, or 1.2-3.5 MHz wide and within ±1.2 MHz.
* **ble** - narrow (bw10 ≤ 3), short (≤ 15 ms), centre on an advertising channel (2402/2426/2480 ±0.7). 2426 (BLE 38) and 2425 (Thread ch 15) are only 1 MHz apart: bandwidth decides (BLE ~1 MHz), but a short single-frame 15.4 burst can also measure narrow, a known confusion.
* **microwave_oven** - ≥ 4 MHz, upper band (≥ 2430), and a ~50 Hz period (IBI 14-24 ms, spread < 4 ms) or strong drift (≥ 3 MHz) off the Wi-Fi grid.
* **unknown** - everything else (BLE data channels, other ISM devices, merged bursts).

Confidence: scoring within each rule; 802.15.4 confirmed by ground truth = 0.99. Low confidence / unknown (≥ 12 dB) raises a "What is this?" card on the dashboard (max 1 per 4 s); the answer is written to `captures/bursts/labels.csv` together with the features (API: `POST /api/bursts/label {id,label,text}`).

## Limits
* **Time resolution ~4.5 ms/frame**: a 0.4 ms BLE advertisement is smeared over a whole frame and its level (mean detector) is diluted by ~10 dB; for short bursts use *Settings > Detector = max*. Burst length is always a multiple of the frame time.
* Packets in quick succession (6LoWPAN fragments, ACKs) merge into one burst (36-90 ms "802.15.4 trains").
* Sidebands of a strong nearby transmitter (the C6 leader) widen bw20 and can shift the centre frequency by ±1 MHz.
* SDR field of view: 80 MHz span @ 2437 → ~2398-2476 MHz (BLE 39 = 2480 MHz is outside).

## Timing calibration (packet ↔ burst)
* The packet host timestamp is the **end** of the frame + UART (460800) + USB/OS latency; the spectrum frame time comes from the sample index, taken at the frame **centre** (rfpair.FrameClock, minimum-latency estimate).
* Correction: (1) packet time - ½ airtime (SHR 160 µs + PHR + PSDU × 32 µs) = frame centre; (2) residual auto-calibration: the running median of matched pairs (burst - corrected time), 200 samples, limited to ±30 ms, is added. The Bursts tab shows "raw" and "corrected" median/IQR.

## Microwave oven as an analogue, non-protocol interferer (ML / data mining)
**Why it is interesting:** no frame structure, preamble or channel grid, a purely physical signal; a good negative/"foreign" class for protocol recognisers and interference detectors.

**Expected signature (magnetron):**
* Half-wave supply: the magnetron radiates only in one half of the mains period → **50 Hz on/off**: ~10 ms on, ~10 ms off (IBI ≈ 20 ms, very stable).
* **Frequency sweep/drift** during the on half-period (anode current changes): several MHz from frame to frame, typically around **2440-2470 MHz**, but anywhere in 2400-2500 depending on the model.
* Wide (5-30+ MHz), not flat (flatness < 0.5), asymmetric spectrum; high power at short range.
* Inverter ovens may differ (more continuous, less 50 Hz-like).
* Expected features: `ibi_med_ms` 19-21, `ibi_std_ms` < 2, `duration_ms` 8-12, `drift_range_mhz` ≥ 2, `bw20_mhz` ≥ 5, `f_center_mhz` ≥ 2440.

**Recording a labelled capture:**
1. Dashboard: span 80 MHz, centre 2450 MHz (to see 2410-2490), Detector = max, gain low enough to avoid saturation (peak < -20 dBFS).
2. Note: oven type (inverter?), power level, distance, load (a glass of water!). **Never run it empty.**
3. Session: 30 s background (oven off) → 60 s oven on → 30 s off → repeat at another power level. Write down the times (or label the bursts as "microwave" on the "What is this?" card).
4. Output: `bursts_*.csv` filtered to the time window + `labels.csv` + the npz files in `snips`. Bursts in the oven window = positive samples, the windows before/after = negative.
5. Optionally Wi-Fi traffic in parallel (2437/2462) → mixed samples for interference separation.