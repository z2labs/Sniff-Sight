/* Sniff-Sight demo player: replays a canned capture (sample.json) in the real dashboard UI.
   It replaces window.WebSocket and window.fetch for the dashboard's /ws and /api/* calls, so no
   backend and no hardware are needed (works from `python -m sniff_sight --demo` and from a
   static page such as GitHub Pages). Full-span spectra are re-synthesised from the recorded
   burst log (noise floor + burst shapes, max-hold between pushes); packets, packet/RF pairing
   results and the per-packet spectrum snippets are the recorded ones (addresses scrubbed). */
(function () {
  'use strict';
  const SAMPLE_URL = window.SS_DEMO_SAMPLE || 'sample.json';
  const realFetch = window.fetch.bind(window);
  const sampleP = realFetch(SAMPLE_URL).then(r => { if (!r.ok) throw new Error('demo sample: HTTP ' + r.status); return r.json(); });
  const PUSH_HZ = 30;
  const json = (o, st) => new Response(JSON.stringify(o), { status: st || 200, headers: { 'Content-Type': 'application/json' } });

  // ---- replay engine (one per page)
  let eng = null;
  function engine(S) {
    if (eng) return eng;
    const st = { settings: { freq_mhz: S.center_hz / 1e6, span: S.span_hz, bins: S.bins, gain: 60, max_hold: false, dc_fix: true } };
    const wall0 = Date.now() / 1000, D = S.duration_s;
    const bursts = S.bursts, pkts = S.packets;
    let ripple = null, noise = [];
    function prep(n) {
      if (ripple && ripple.length === n) return;
      let seed = 12345; const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
      const g = () => { let u = 0; for (let i = 0; i < 6; i++) u += rnd(); return (u - 3) * 1.4; };
      ripple = new Float32Array(n); for (let i = 0; i < n; i++) ripple[i] = 1.5 * Math.sin(i / n * 9.3) + 0.6 * Math.sin(i / n * 41);
      noise = []; for (let k = 0; k < 8; k++) { const a = new Float32Array(n); for (let i = 0; i < n; i++) a[i] = g(); noise.push(a); }
    }
    const e = {
      st, S, wall0, listeners: new Set(), loop: 0, bi: 0, pi: 0, pend: [], active: [], stats: { total: {}, last60: [] , frames: 0},
      pairCounts: {}, total: 0, offsets: [], tPrev: 0, seq: 0, recentB: [], recentP: [],
      emit(m) { for (const l of this.listeners) l(m); },
      now() { return Date.now() / 1000; },
      status() {
        const s = st.settings;
        return { type: 'status', port: 'DEMO', state: 'streaming', error: null, info: 'Demo replay (canned data, no hardware)', version: 'demo',
          spec: `SPEC ${s.bins} ${s.span} demo`, settings: s, center_hz: s.freq_mhz * 1e6, span_hz: s.span };
      },
      thread() {
        const o = this.offsets.slice().sort((a, b) => a - b);
        return { type: 'thread', enabled: true, channel: 15, channel_mhz: 2425, hop: null, dwell: 2, per_channel: { '15': this.total },
          total: this.total, per_source: {}, records: this.total, file: 'demo.pcap', wireshark_connected: false, wireshark_packets: 0, running: true,
          pairing: this.pairCounts, offset_median_ms: o.length ? o[o.length >> 1] : null, timing: null };
      },
      burstStats() {
        const t = this.now(); this.stats.last60 = this.stats.last60.filter(x => t - x[0] <= 60);
        const l = {}; for (const [, c] of this.stats.last60) l[c] = (l[c] || 0) + 1;
        return { type: 'burst_stats', total: this.stats.total, last60: l, ground_truth: {}, frames: this.stats.frames, dropped: 0, queue: 0, user_labels: {} };
      },
      // play position: recording time (s) for wall time w
      pos(w) { const x = w - wall0; return [x % D, Math.floor(x / D)]; },
      base(loop) { return wall0 + loop * D; },
      tick() {
        const w = this.now(), [p, loop] = this.pos(w);
        if (loop !== this.loop) { this.loop = loop; this.bi = 0; this.pi = 0; this.active = []; }
        const B = this.base(loop), sfx = loop ? '_L' + loop : '';
        // bursts that started up to now
        while (this.bi < bursts.length && bursts[this.bi].t0 <= p) { this.active.push([bursts[this.bi], B]); this.bi++; }
        // packets
        while (this.pi < pkts.length && pkts[this.pi].t <= p) {
          const src = pkts[this.pi++], pk = Object.assign({}, src, { id: src.id + sfx, t: src.t + B, pair: null });
          this.total++; this.recentP.push(pk); if (this.recentP.length > 300) this.recentP.shift();
          this.emit(pk);
          const pr = Object.assign({}, src.pair, { snippet: src.id + sfx });
          this.pend.push([w + 0.25, () => {
            pk.pair = pr; this.pairCounts[pr.quality] = (this.pairCounts[pr.quality] || 0) + 1;
            if (pr.quality === 'matched' && pr.offset_ms != null) { this.offsets.push(pr.offset_ms); if (this.offsets.length > 200) this.offsets.shift(); }
            this.emit({ type: 'pair', id: pk.id, t: pk.t, pair: pr });
          }]);
        }
        // finished bursts -> burst messages (0.6 s after the end, like the server)
        const keep = [];
        for (const a of this.active) {
          const [b, bb] = a;
          if (b.t1 + bb + 0.6 <= w) {
            const m = Object.assign({ type: 'burst' }, b, { id: b.id + (bb > wall0 ? '_' + Math.round((bb - wall0) / D) : ''), t0: b.t0 + bb, t1: b.t1 + bb });
            this.stats.total[b.cls] = (this.stats.total[b.cls] || 0) + 1; this.stats.last60.push([w, b.cls]);
            this.recentB.push(m); if (this.recentB.length > 300) this.recentB.shift();
            this.emit(m);
          } else keep.push(a);
        }
        this.active = keep;
        for (let i = this.pend.length - 1; i >= 0; i--) if (this.pend[i][0] <= w) { const f = this.pend[i][1]; this.pend.splice(i, 1); f(); }
        this.emit(this.spectrum(w));
        this.tPrev = w;
      },
      spectrum(w) {
        const s = st.settings, n = s.bins, c = s.freq_mhz, sp = s.span / 1e6; prep(n);
        const nz = noise[(this.seq++) & 7], db = new Float32Array(n), fl = S.floor_dbfs + (60 - s.gain) * 0.3;
        for (let i = 0; i < n; i++) db[i] = fl + ripple[i] + nz[(i * 7 + this.seq * 13) % n];
        const df = sp / n, f0 = c - sp / 2, ta = this.tPrev || w - 1 / PUSH_HZ;
        for (const [b, bb] of this.active) {
          if (b.t1 + bb < ta || b.t0 + bb > w) continue;
          const lo = b.f_lo_mhz, hi = b.f_hi_mhz, fc = b.f_center_mhz || (lo + hi) / 2, hw = Math.max(0.3, (hi - lo) / 2);
          const pk = (b.floor_dbfs ?? S.floor_dbfs) + (b.peak_excess_db || 10) - (60 - s.gain) * 0.1, flat = b.cls === 'wifi';
          const i0 = Math.max(0, Math.floor((lo - 1.5 - f0) / df)), i1 = Math.min(n - 1, Math.ceil((hi + 1.5 - f0) / df));
          for (let i = i0; i <= i1; i++) {
            const f = f0 + (i + 0.5) * df, d = Math.abs(f - fc) / hw;
            const v = d <= 1 ? pk - (flat ? 1 : 4) * d * d : pk - (flat ? 1 : 4) - 14 * (d - 1) * (d - 1) * hw;
            const x = v + nz[(i * 3) % n] * 0.4; if (x > db[i]) db[i] = x;
          }
        }
        this.stats.frames++;
        const meta = { type: 'spec', seq: this.seq, gain: s.gain, drops: 0, ffts: 1, frame_ms: S.frame_ms, fps: PUSH_HZ, gaps: 0, crc_errors: 0,
          center_hz: c * 1e6, span_hz: s.span, clock: { frames: this.seq, resets: 0, fallback: false, frame_ms: S.frame_ms, latency_jitter_ms: 0 }, t: w, enc: 'u16', n };
        let mb = new TextEncoder().encode(JSON.stringify(meta)); const pad = (4 + mb.length) % 2;
        const buf = new ArrayBuffer(4 + mb.length + pad + 2 * n), dv = new DataView(buf);
        dv.setUint32(0, mb.length + pad, true); new Uint8Array(buf, 4, mb.length).set(mb); if (pad) new Uint8Array(buf)[4 + mb.length] = 32;
        const q = new Uint16Array(buf, 4 + mb.length + pad, n);
        for (let i = 0; i < n; i++) q[i] = Math.max(0, Math.min(65535, Math.round((db[i] + 140) * 100)));
        return buf;
      },
    };
    setInterval(() => e.tick(), 1000 / PUSH_HZ);
    setInterval(() => { e.emit(e.thread()); e.emit(e.burstStats()); }, 2000);
    eng = e; return e;
  }

  // ---- WebSocket stand-in
  class DemoSocket {
    constructor(url) {
      this.url = url; this.readyState = 0; this.binaryType = 'blob';
      this.onopen = this.onmessage = this.onclose = this.onerror = null;
      sampleP.then(S => {
        const e = engine(S); this.e = e; this.readyState = 1;
        this._l = (m) => { if (this.readyState !== 1 || !this.onmessage) return; this.onmessage({ data: m instanceof ArrayBuffer ? m : JSON.stringify(m) }); };
        this.onopen && this.onopen({});
        this._l({ type: 'hello', msg: 'Sniff-Sight demo replay ready' }); this._l(e.status()); this._l(e.thread());
        for (const p of e.recentP.slice(-100)) this._l(p);
        e.listeners.add(this._l);
      }).catch(err => { const s = document.getElementById('status'); if (s) s.textContent = String(err); });
    }
    send(raw) {
      let m; try { m = JSON.parse(raw); } catch (x) { return; }
      const e = this.e; if (!e || !m) return;
      if (m.type === 'stream') { this._l({ type: 'stream', light: false, lite_hz: 25, lite_pts: m.pts || 512, full_hz: PUSH_HZ, binary: true }); return; }
      if (m.type === 'ping') return;
      const s = Object.assign({}, e.st.settings);
      if ('gain' in m) s.gain = Math.max(0, Math.min(82, +m.gain));
      if ('freq_mhz' in m) s.freq_mhz = Math.max(2300, Math.min(2600, +m.freq_mhz));
      if ('span' in m && [16e6, 40e6, 80e6].includes(+m.span)) s.span = +m.span;
      if ('bins' in m && [256, 512, 1024, 2048, 4096].includes(+m.bins)) s.bins = +m.bins;
      if ('max_hold' in m) s.max_hold = !!m.max_hold;
      e.st.settings = s; e.emit(e.status());
    }
    close() { this.readyState = 3; if (this.e) this.e.listeners.delete(this._l); }
  }
  DemoSocket.CONNECTING = 0; DemoSocket.OPEN = 1; DemoSocket.CLOSING = 2; DemoSocket.CLOSED = 3;
  window.WebSocket = DemoSocket;

  // ---- fetch stand-in for the dashboard API
  window.fetch = async function (input, init) {
    const url = typeof input === 'string' ? input : input.url, u = new URL(url, location.href), p = u.pathname;
    const i = p.indexOf('/api/');
    if (i < 0) return realFetch(input, init);
    const S = await sampleP, e = engine(S), r = p.slice(i + 4);
    if (r === '/snippets') return json({ dir: 'demo', recent: e.recentP.slice().reverse().map(x => Object.assign({}, x)), files: [] });
    if (r.startsWith('/snippets/')) {
      const id = decodeURIComponent(r.slice(10)).replace(/\.npz$/, '').replace(/_L\d+$/, ''), sn = S.snippets[id];
      return sn ? json(sn) : json({ error: 'not found' }, 404);
    }
    if (r === '/bursts') return json({ stats: e.burstStats(), recent: e.recentB.slice(-200) });
    if (r === '/bursts/label') return json({ ok: true, row: { demo: true } });
    if (r === '/per') return json({ runs: [], archived: [], fc: [], fc_events: [] });
    if (r.startsWith('/per/')) return json({ error: 'not found' }, 404);
    if (r === '/info') return json({ status: e.status(), thread: e.thread(), settings: e.st.settings, demo: true });
    if (r.startsWith('/fw/')) return json({ error: 'firmware tools are not available in the demo' }, 503);
    return json({ error: 'not available in the demo' }, 404);
  };

  // ---- banner
  function banner() {
    const d = document.createElement('div');
    d.textContent = 'DEMO: replay of a recorded lab capture (no hardware). Spectrum is re-synthesised from the burst log; packets, pairing and snippets are recorded.';
    d.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:9999;background:#5a3d00;color:#ffe9b0;font:12px system-ui,sans-serif;padding:4px 10px;text-align:center;opacity:.92';
    document.body.appendChild(d);
  }
  if (document.body) banner(); else document.addEventListener('DOMContentLoaded', banner);
})();