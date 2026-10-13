// ESP32 ROM-loader flasher over Web Serial, ported from z2-web-sdr src/flasher.js
// (itself a port of esp_flasher.cpp from the SDR++ ESP-SDR module). Used by the Settings > Firmware box.
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Growable byte buffer fed by the serial reader (from z2-web-sdr index.html)
class ByteBuf {
  constructor() { this.b = new Uint8Array(1 << 18); this.n = 0; }
  push(chunk) {
    if (this.n + chunk.length > this.b.length) {
      let sz = this.b.length; while (sz < this.n + chunk.length) sz *= 2;
      const nb = new Uint8Array(sz); nb.set(this.b.subarray(0, this.n)); this.b = nb;
    }
    this.b.set(chunk, this.n); this.n += chunk.length;
  }
  drop(k) { if (k <= 0) return; if (k >= this.n) { this.n = 0; return; } this.b.copyWithin(0, k, this.n); this.n -= k; }
  clear() { this.n = 0; }
}

// ---------------------------------------------------------------- firmware flasher (ROM serial bootloader, as esptool / SDR++ ESP)
// Plain ROM commands, no stub: SYNC, SPI_ATTACH, SPI_SET_PARAMS, FLASH_BEGIN/DATA/END, SPI_FLASH_MD5,
// WRITE_REG, CHANGE_BAUDRATE. Port of esp_flasher.cpp from the SDR++ ESP-SDR module.
function md5Hex(data) {
  const K = new Uint32Array(64), S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
  const len = data.length, total = ((len + 8) >> 6) + 1 << 6, m = new Uint8Array(total);
  m.set(data); m[len] = 0x80;
  const bits = len * 8;
  for (let k = 0; k < 8; k++) m[total - 8 + k] = k < 4 ? (bits >>> (8 * k)) & 0xFF : Math.floor(bits / 4294967296) >>> (8 * (k - 4)) & 0xFF;
  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
  const M = new Uint32Array(16);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = m[off + 4 * i] | (m[off + 4 * i + 1] << 8) | (m[off + 4 * i + 2] << 16) | (m[off + 4 * i + 3] << 24);
    let A = a, B = b, C = c, D = d;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      const s = S[(i >> 4) * 4 + (i & 3)];
      B = (B + ((F << s) | (F >>> (32 - s)))) >>> 0;
    }
    a = (a + A) >>> 0; b = (b + B) >>> 0; c = (c + C) >>> 0; d = (d + D) >>> 0;
  }
  let out = "";
  for (const w of [a, b, c, d]) for (let k = 0; k < 4; k++) out += ((w >>> (8 * k)) & 0xFF).toString(16).padStart(2, "0");
  return out;
}

function slipEncode(p) {
  const o = [0xC0];
  for (const b of p) { if (b === 0xC0) o.push(0xDB, 0xDC); else if (b === 0xDB) o.push(0xDB, 0xDD); else o.push(b); }
  o.push(0xC0);
  return new Uint8Array(o);
}
const le32 = (x) => [x & 0xFF, (x >>> 8) & 0xFF, (x >>> 16) & 0xFF, (x >>> 24) & 0xFF];

class EspFlasher {
  constructor(port, log) { this.port = port; this.log = log || (() => {}); this.rx = new ByteBuf(); this.waiters = []; this.isOpen = false; }

  async openPort(baud) {
    await this.port.open({ baudRate: baud, bufferSize: 1 << 16 });
    this.isOpen = true; this.rx.clear();
    this.writer = this.port.writable.getWriter();
    this.reading = (async () => {
      this.reader = this.port.readable.getReader();
      try {
        for (;;) {
          const { value, done } = await this.reader.read();
          if (done) break;
          if (value && value.length) { this.rx.push(value); this.wake(); }
        }
      } catch (e) { /* device left the bus during a reset */ }
      finally { try { this.reader.releaseLock(); } catch (e) {} }
    })();
  }
  async closePort() {
    if (!this.isOpen) return;
    this.isOpen = false;
    try { await this.reader.cancel(); } catch (e) {}
    try { await this.reading; } catch (e) {}
    try { this.writer.releaseLock(); } catch (e) {}
    try { await this.port.close(); } catch (e) {}
  }
  // The native USB port may come back as a new device after the reset: try the same port object
  // first, then any granted ESP32-S3 port
  async reopen(baud) {
    for (let i = 0; i < 40; i++) {
      await sleep(250);
      try { await this.openPort(baud); return; } catch (e) {}
      try {
        for (const p of await navigator.serial.getPorts()) {
          if (p === this.port || p.getInfo().usbVendorId !== 0x303a) continue;
          try { this.port = p; await this.openPort(baud); this.log("flash: board came back as a new port"); return; } catch (e) {}
        }
      } catch (e) {}
    }
    throw new Error("the board did not come back after the reset");
  }
  wake() { const w = this.waiters; this.waiters = []; for (const r of w) r(); }
  waitData(ms) { return new Promise((res) => { const t = setTimeout(res, ms); this.waiters.push(() => { clearTimeout(t); res(); }); }); }
  async lines(dtr, rts) { await this.port.setSignals({ dataTerminalReady: dtr, requestToSend: rts }); }
  async drain(ms) { await sleep(ms); this.rx.clear(); }

  async readFrame(timeoutMs) {
    const end = performance.now() + timeoutMs;
    for (;;) {
      const b = this.rx.b, n = this.rx.n;
      let s = 0; while (s < n && b[s] !== 0xC0) s++;
      if (s < n) {
        let e = s + 1; while (e < n && b[e] !== 0xC0) e++;
        if (e < n) {
          if (e === s + 1) { this.rx.drop(s + 1); continue; }   // C0 C0: frame boundary
          const f = [];
          for (let i = s + 1; i < e; i++) {
            if (b[i] === 0xDB && i + 1 < e) { f.push(b[i + 1] === 0xDC ? 0xC0 : 0xDB); i++; } else f.push(b[i]);
          }
          this.rx.drop(e + 1);
          return f;
        }
      } else this.rx.clear();   // no frame start: boot log text etc.
      const left = end - performance.now();
      if (left <= 0) return null;
      await this.waitData(Math.min(left, 50));
    }
  }

  // Returns the response data (status bytes stripped); throws on error status or timeout
  async command(op, data, checksum, timeoutMs, opts) {
    const pkt = [0x00, op, data.length & 0xFF, (data.length >> 8) & 0xFF, ...le32(checksum >>> 0)];
    const enc = slipEncode(pkt.concat(Array.from(data)));
    await this.writer.write(enc);
    const end = performance.now() + timeoutMs;
    for (;;) {
      const left = end - performance.now();
      const f = left > 0 ? await this.readFrame(left) : null;
      if (!f) throw new Error("no answer to command 0x" + op.toString(16).padStart(2, "0"));
      if (f.length < 8 || f[0] !== 0x01 || f[1] !== op) continue;   // e.g. late SYNC replies
      const len = f[2] | (f[3] << 8);
      if (f.length < 8 + len) continue;
      let d = f.slice(8, 8 + len);
      if (d.length >= 2) {   // ROM loader: data ends with 4 status bytes (status, error, 0, 0)
        const st = d.length >= 4 ? d.length - 4 : d.length - 2;
        if (d[st] !== 0) throw new Error("command 0x" + op.toString(16).padStart(2, "0") + " failed (status " + d[st] + ", error 0x" + d[st + 1].toString(16) + ")");
        d = d.slice(0, st);
      }
      if (opts && opts.value) opts.value.v = (f[4] | (f[5] << 8) | (f[6] << 16) | (f[7] << 24)) >>> 0;
      return d;
    }
  }

  async sync() {
    const d = [0x07, 0x07, 0x12, 0x20]; for (let i = 0; i < 32; i++) d.push(0x55);
    for (let attempt = 0; attempt < 12; attempt++) {
      try { await this.command(0x08, d, 0, 120); await this.drain(100); return true; } catch (e) {}
    }
    return false;
  }

  async resetToBootloader(usbJtag) {
    if (usbJtag) {
      // esptool's USB-JTAG-Serial reset: IO0 low via DTR, chip reset via RTS
      await this.lines(false, false); await sleep(100);
      await this.lines(true, false); await sleep(100);
      await this.lines(true, true);   // pass through (1,1), not (0,0)
      await this.lines(false, true); await sleep(100);
      await this.lines(false, false);
    } else {
      // Classic DevKit auto-reset (DTR -> IO0, RTS -> EN through transistors)
      await this.lines(false, true); await sleep(100);
      await this.lines(true, false); await sleep(50);
      await this.lines(false, false);
    }
  }

  async hardReset(usbJtag) {
    if (usbJtag) {
      // Entering the ROM loader over USB Serial/JTAG latches "force download boot" (RTC_CNTL_OPTION1_REG
      // bit 0): clear it as esptool does for the S3, then reset with IO0 (DTR) released
      try { await this.command(0x09, [...le32(0x6000812C), ...le32(0), ...le32(1), ...le32(0)], 0, 500); } catch (e) { this.log("flash: OPTION1 clear: " + e.message); }
      try { await this.lines(false, true); } catch (e) {}
      await sleep(200);
      try { await this.lines(false, false); } catch (e) {}
      await sleep(200);
      return;
    }
    await this.lines(false, true); await sleep(100);
    await this.lines(false, false);
  }

  // images: [{offset, data: Uint8Array, name}]; progress(stage, frac)
  async flash(images, usbJtag, progress) {
    const prog = (s, f) => { this.log("flash: " + s + " (" + Math.round(f * 100) + " %)"); progress && progress(s, f); };
    const step = async (what, fn) => { try { return await fn(); } catch (e) { throw new Error(what + ": " + e.message); } };
    prog("Resetting into the bootloader", 0);
    await this.openPort(usbJtag ? 115200 : 115200);
    await this.resetToBootloader(usbJtag);
    if (usbJtag) {
      // The USB device may disappear and come back as the ROM's own USB Serial/JTAG
      await this.closePort(); await sleep(600);
      await this.reopen(115200);
    }
    this.rx.clear();
    prog("Connecting to the bootloader", 0.02);
    if (!(await this.sync())) {
      if (!usbJtag) throw new Error("bootloader: the chip did not enter its bootloader (no SYNC answer)");
      // The selected port may be a DevKit's UART port (USB-UART bridge with EN / IO0 transistors)
      prog("Connecting to the bootloader (UART port)", 0.03);
      usbJtag = false;
      await this.resetToBootloader(false);
      this.rx.clear();
      if (!(await this.sync())) throw new Error("bootloader: the chip did not enter its bootloader (no SYNC answer)");
    }
    if (!usbJtag) {
      // The ROM loader talks 115200 on a UART: switch both sides to 460800 (CHANGE_BAUDRATE new, 0 = ROM)
      try {
        await this.command(0x0F, [...le32(460800), ...le32(0)], 0, 1000);
        await this.closePort(); await this.openPort(460800); await this.drain(50);
        if (!(await this.sync())) throw new Error("no SYNC at 460800");
      } catch (e) {
        this.log("flash: staying at 115200 (" + e.message + ")");
        await this.closePort(); await this.openPort(115200); await this.drain(50);
        if (!(await this.sync())) throw new Error("bootloader: lost the chip after a baud rate change");
      }
    }
    await step("SPI attach", () => this.command(0x0D, [...le32(0), ...le32(0)], 0, 3000));
    await step("SPI flash parameters", () => this.command(0x0B, [...le32(0), ...le32(4 << 20), ...le32(64 << 10), ...le32(4 << 10), ...le32(256), ...le32(0xFFFF)], 0, 3000));
    const BLOCK = 0x400;
    const total = images.reduce((s, im) => s + im.data.length, 0);
    let done = 0;
    for (const im of images) {
      const size = im.data.length, blocks = Math.ceil(size / BLOCK);
      prog("Erasing " + im.name, 0.05 + 0.85 * done / total);
      await step("erase at 0x" + im.offset.toString(16), () => this.command(0x02, [...le32(size), ...le32(blocks), ...le32(BLOCK), ...le32(im.offset), ...le32(0)], 0, 10000 + Math.floor(size / 1024) * 60));
      for (let seq = 0; seq < blocks; seq++) {
        const blk = new Uint8Array(BLOCK).fill(0xFF);
        blk.set(im.data.subarray(seq * BLOCK, Math.min(size, (seq + 1) * BLOCK)));
        let ck = 0xEF; for (const x of blk) ck ^= x;
        const d = new Uint8Array(16 + BLOCK);
        d.set([...le32(BLOCK), ...le32(seq), ...le32(0), ...le32(0)]); d.set(blk, 16);
        let err = null;
        for (let retry = 0; retry < 3; retry++) { try { await this.command(0x03, d, ck, 3000); err = null; break; } catch (e) { err = e; } }
        if (err) throw new Error("write " + im.name + " block " + seq + ": " + err.message);
        const written = Math.min(size, (seq + 1) * BLOCK);
        if (seq % 8 === 7 || seq === blocks - 1) prog("Writing " + im.name, 0.05 + 0.85 * (done + written) / total);
      }
      done += size;
      prog("Verifying " + im.name, 0.05 + 0.85 * done / total);
      const r = await step("verify " + im.name, () => this.command(0x13, [...le32(im.offset), ...le32(size), ...le32(0), ...le32(0)], 0, 8000 + Math.floor(size / 1024) * 10));
      const got = (r.length >= 32 ? String.fromCharCode(...r.slice(0, 32)) : r.map((x) => x.toString(16).padStart(2, "0")).join("")).toLowerCase();
      if (got !== md5Hex(im.data)) throw new Error("verify " + im.name + " (MD5 mismatch)");
    }
    prog("Starting the new firmware", 0.95);
    try { await this.command(0x04, [...le32(1)], 0, 2000); } catch (e) {}   // FLASH_END, stay in the loader
    await this.hardReset(usbJtag);
    await this.closePort();
    prog("Done", 1);
    return this.port;
  }
}

// Firmware bundle: flash_args (esptool format) + images + version.json, embedded gzip+base64
async function gunzip(b64) {
  const bin = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const stream = new Blob([bin]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
function parseFlashArgs(text) {
  const tok = text.split(/\s+/).filter(Boolean), res = [];
  for (let i = 0; i + 1 < tok.length; i++) if (tok[i].startsWith("0x")) { res.push({ offset: parseInt(tok[i], 16), name: tok[i + 1] }); i++; }
  return res;
}
async function loadEmbeddedBundle() {
  const el = document.getElementById("fwBundle");
  if (!el) return null;
  const j = JSON.parse(el.textContent);
  const images = [];
  for (const it of parseFlashArgs(j.flash_args)) images.push({ offset: it.offset, name: it.name, data: await gunzip(j.files[it.name]) });
  return { images, version: j.version };
}
function embeddedVersion() {
  try { const el = document.getElementById("fwBundle"); return el ? JSON.parse(el.textContent).version : null; } catch (e) { return null; }
}
// A build picked from disk (the build folder or the files flash_args + images + version.json)
async function loadBundleFromFiles(fileList) {
  const files = Array.from(fileList), byName = (n) => files.find((f) => (f.webkitRelativePath || f.name).endsWith(n));
  const fa = byName("flash_args");
  if (!fa) throw new Error("flash_args not found in the selected files");
  const images = [];
  for (const it of parseFlashArgs(await fa.text())) {
    const f = byName(it.name) || byName(it.name.split("/").pop());
    if (!f) throw new Error("missing " + it.name);
    images.push({ offset: it.offset, name: it.name, data: new Uint8Array(await f.arrayBuffer()) });
  }
  let version = { build_date: "custom", build_timestamp: "", revision: "" };
  const vj = byName("version.json");
  if (vj) try { version = JSON.parse(await vj.text()); } catch (e) {}
  return { images, version };
}
