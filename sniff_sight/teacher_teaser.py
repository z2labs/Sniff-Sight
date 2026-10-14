"""Free edition: greyed-out Pro teasers for the Settings tab (static HTML only)."""

HTML = r"""
    <div class="box pro-teaser" style="margin-top:10px;opacity:.45;filter:grayscale(1);pointer-events:none;user-select:none" aria-disabled="true">
      <h3>Teacher network <small class="sub">Pro</small></h3>
      <div class="sub">Two or more ESP32-C6 "Teacher" nodes play scheduled RF lessons (BLE, Thread, Wi-Fi, collisions, silence)
        and auto-label the captured bursts for the classifier. Master/slave roles, schedule presets, JSON schedules and live node status.</div>
      <div class="ctl" style="margin-top:6px"><button disabled>Connect nodes</button> <select disabled><option>basic</option></select>
        <button disabled>Start</button> <button disabled>Stop</button></div>
      <h3 style="margin-top:10px">Model evaluation &amp; retraining <small class="sub">Pro</small></h3>
      <div class="sub">Per-protocol accuracy, precision/recall, confusion matrix and confidence calibration against Teacher labels;
        retrain on Teacher-labelled data, compare and activate versioned models.</div>
      <div class="ctl" style="margin-top:6px"><button disabled>Evaluate</button> <button disabled>Retrain</button> <button disabled>Activate model</button></div>
      <h3 style="margin-top:10px">Timing calibration &mdash; Pro feature &mdash; contact hello [at] z2labs [dot] io</h3>
      <div class="sub">Measures serial-marker, sniffer and SDR timing offsets and jitter with a known on/off RF pattern from the Teacher nodes
        and corrects packet &harr; burst pairing.</div>
      <div class="ctl" style="margin-top:6px"><button disabled>Run calibration</button> <label><input type="checkbox" disabled> Apply timing correction</label></div>
      <div class="sub" style="margin-top:6px"><b>Pro feature &mdash; contact hello [at] z2labs [dot] io</b></div>
    </div>
"""
