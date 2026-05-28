/* Dashboard renderer. Fetches one encrypted bundle, decrypts locally with a
   passphrase, and draws the result with lightweight-charts. Supports
   adjustable parameters, threshold-coloured signal bars, arrow markers on
   the main pane, and basic drawing tools (horizontal & trend lines).
   Persists settings + drawings in localStorage. */

const STORAGE_KEY  = "btc-liq-viz/v2";
const DRAW_KEY     = "btc-liq-viz/drawings/v1";
const DEFAULTS = Object.freeze({
  thrPos: 3,
  thrNeg: -3,
  maFast: 720,
  maSlow: 8400,
  markers: true,
});

const els = {
  status:   document.getElementById("status"),
  gate:     document.getElementById("gate"),
  form:     document.getElementById("gate-form"),
  input:    document.getElementById("gate-input"),
  error:    document.getElementById("gate-error"),
  card:     null,
  readout:  document.getElementById("hover-info"),
  chart:    document.getElementById("chart"),
  drawHint: document.getElementById("draw-hint"),
  panel:    document.getElementById("settings-panel"),
  lblFast:  document.getElementById("lbl-ma-fast"),
  lblSlow:  document.getElementById("lbl-ma-slow"),
  thrPos:   document.getElementById("sp-thr-pos"),
  thrNeg:   document.getElementById("sp-thr-neg"),
  maFast:   document.getElementById("sp-ma-fast"),
  maSlow:   document.getElementById("sp-ma-slow"),
  markers:  document.getElementById("sp-markers"),
  btnHLine: document.getElementById("tool-hline"),
  btnTrend: document.getElementById("tool-trend"),
  btnClear: document.getElementById("tool-clear"),
  btnFit:   document.getElementById("tool-fit"),
  btnGear:  document.getElementById("tool-settings"),
  btnClose: document.getElementById("sp-close"),
  btnApply: document.getElementById("sp-apply"),
  btnReset: document.getElementById("sp-reset"),
};
els.card = els.form.querySelector(".gate-card");

const fmtUsd  = n => n == null ? "—" : "$" + n.toLocaleString("en-US", {maximumFractionDigits: 2});
const fmtBtc  = n => n == null ? "—" : n.toLocaleString("en-US", {maximumFractionDigits: 2}) + " BTC";
const fmtSign = n => n == null ? "—" : (n >= 0 ? "+" : "") + n.toFixed(3);

function setStatus(text, cls = "") {
  els.status.textContent = text;
  els.status.className = "status " + cls;
}

// --------------------------------------------------------------------------
// Settings (localStorage-backed)
// --------------------------------------------------------------------------
let settings = loadSettings();

function loadSettings() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return { ...DEFAULTS, ...JSON.parse(raw) };
  } catch (e) { /* ignore */ }
  return { ...DEFAULTS };
}

function saveSettings() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(settings)); } catch (e) {}
}

function applySettingsToForm() {
  els.thrPos.value  = settings.thrPos;
  els.thrNeg.value  = settings.thrNeg;
  els.maFast.value  = settings.maFast;
  els.maSlow.value  = settings.maSlow;
  els.markers.checked = settings.markers;
}

function readFormIntoSettings() {
  settings.thrPos  = parseFloat(els.thrPos.value);
  settings.thrNeg  = parseFloat(els.thrNeg.value);
  settings.maFast  = parseInt(els.maFast.value, 10);
  settings.maSlow  = parseInt(els.maSlow.value, 10);
  settings.markers = els.markers.checked;
  saveSettings();
}

// --------------------------------------------------------------------------
// AES-GCM decrypt
// --------------------------------------------------------------------------
function b64decode(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function decryptPayload(envelope, password) {
  const salt = b64decode(envelope.salt);
  const iv   = b64decode(envelope.iv);
  const ct   = b64decode(envelope.ct);
  const enc  = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: envelope.iters, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

// --------------------------------------------------------------------------
// Moving average
// --------------------------------------------------------------------------
function sma(series, window) {
  const out = [];
  if (window < 2 || series.length < window) return out;
  let sum = 0;
  for (let i = 0; i < series.length; i++) {
    sum += series[i].close;
    if (i >= window) sum -= series[i - window].close;
    if (i >= window - 1) out.push({ time: series[i].time, value: sum / window });
  }
  return out;
}

// --------------------------------------------------------------------------
// Chart state
// --------------------------------------------------------------------------
let chart;
let candleSeries, volSeries, liqSeries, maFastSeries, maSlowSeries;
let candleByTime = new Map();
let recByTime = new Map();
let allRecords = [];     // raw decrypted records, used on re-render
let allCandles = [];
let markerHandle = null;

// Drawings: persisted to localStorage
let drawings = loadDrawings();
let drawSeriesList = [];   // active LineSeries handles for current drawings
let drawMode = null;       // null | 'hline' | 'trend'
let trendPending = null;   // first click of a trend line

function loadDrawings() {
  try {
    const raw = localStorage.getItem(DRAW_KEY);
    if (raw) return JSON.parse(raw);
  } catch (e) {}
  return [];
}
function saveDrawings() {
  try { localStorage.setItem(DRAW_KEY, JSON.stringify(drawings)); } catch (e) {}
}

// --------------------------------------------------------------------------
// Build chart
// --------------------------------------------------------------------------
function buildChart() {
  chart = LightweightCharts.createChart(els.chart, {
    layout: {
      background: { type: "solid", color: "#0d1117" },
      textColor:  "#d9d9d9",
      panes:      { separatorColor: "#1f2937", separatorHoverColor: "#374151", enableResize: true },
    },
    grid: {
      vertLines: { color: "#1f2937" },
      horzLines: { color: "#1f2937" },
    },
    crosshair: { mode: 1 },
    rightPriceScale: { borderColor: "#1f2937" },
    timeScale: {
      borderColor: "#1f2937",
      timeVisible: true,
      secondsVisible: false,
    },
    autoSize: true,
  });

  candleSeries = chart.addSeries(LightweightCharts.CandlestickSeries, {
    upColor: "#26a69a", downColor: "#ef5350",
    borderUpColor: "#26a69a", borderDownColor: "#ef5350",
    wickUpColor: "#26a69a", wickDownColor: "#ef5350",
  }, 0);

  maFastSeries = chart.addSeries(LightweightCharts.LineSeries, {
    color: "#2962ff", lineWidth: 1, priceLineVisible: false, lastValueVisible: false,
  }, 0);
  maSlowSeries = chart.addSeries(LightweightCharts.LineSeries, {
    color: "#ff9800", lineWidth: 1, priceLineVisible: false, lastValueVisible: false,
  }, 0);

  volSeries = chart.addSeries(LightweightCharts.HistogramSeries, {
    priceFormat: { type: "volume" },
    priceLineVisible: false, lastValueVisible: false,
  }, 1);

  liqSeries = chart.addSeries(LightweightCharts.HistogramSeries, {
    priceFormat: { type: "price", precision: 2, minMove: 0.01 },
    priceLineVisible: false,
    base: 0,
  }, 2);

  // Pane heights
  const panes = chart.panes();
  if (panes.length >= 3) {
    const total = window.innerHeight - 66;
    panes[0].setHeight(Math.round(total * 0.60));
    panes[1].setHeight(Math.round(total * 0.15));
    panes[2].setHeight(Math.round(total * 0.25));
  }

  chart.subscribeCrosshairMove(onCrosshair);
  chart.subscribeClick(onClick);
}

// --------------------------------------------------------------------------
// Render data + re-render hooks
// --------------------------------------------------------------------------
function colorForLiq(v) {
  if (v == null) return "rgba(120,120,120,0.45)";
  if (v >=  settings.thrPos) return "rgba(38,166,154,0.95)";    // bright green
  if (v <=  settings.thrNeg) return "rgba(239,83,80,0.95)";     // bright red
  if (v >= 0) return "rgba(38,166,154,0.30)";                   // muted green
  return "rgba(239,83,80,0.30)";                                // muted red
}

function renderAll(records) {
  allRecords = records;
  allCandles = [];
  const volumes = [];
  for (const r of records) {
    if (!r.k) continue;
    const [o, h, l, c, v] = r.k;
    allCandles.push({ time: r.t, open: o, high: h, low: l, close: c });
    volumes.push({
      time: r.t,
      value: v,
      color: c >= o ? "rgba(38,166,154,0.55)" : "rgba(239,83,80,0.55)",
    });
  }
  candleByTime = new Map(allCandles.map(c => [c.time, c]));
  recByTime   = new Map(records.map(r => [r.t, r]));

  candleSeries.setData(allCandles);
  volSeries.setData(volumes);
  refreshMAs();
  refreshLiqBars();
  refreshLiqRefLines();
  refreshMarkers();
  refreshLegend();
  applyDrawingsToChart();

  chart.timeScale().fitContent();
  setStatus(`ok · ${allCandles.length.toLocaleString()} bars`, "ok");
}

function refreshMAs() {
  maFastSeries.setData(sma(allCandles, settings.maFast));
  maSlowSeries.setData(sma(allCandles, settings.maSlow));
}

function refreshLiqBars() {
  const bars = allRecords.map(r => ({
    time: r.t,
    value: r.l == null ? 0 : r.l,
    color: colorForLiq(r.l),
  }));
  liqSeries.setData(bars);
}

// Re-create reference lines whenever thresholds change
let refLineHandles = [];
function refreshLiqRefLines() {
  for (const h of refLineHandles) {
    try { liqSeries.removePriceLine(h); } catch (e) {}
  }
  refLineHandles = [];
  refLineHandles.push(liqSeries.createPriceLine({
    price: settings.thrPos, color: "rgba(38,166,154,0.55)",
    lineWidth: 1, lineStyle: 2, axisLabelVisible: true, title: `+${settings.thrPos}`
  }));
  refLineHandles.push(liqSeries.createPriceLine({
    price: settings.thrNeg, color: "rgba(239,83,80,0.55)",
    lineWidth: 1, lineStyle: 2, axisLabelVisible: true, title: `${settings.thrNeg}`
  }));
  refLineHandles.push(liqSeries.createPriceLine({
    price: 0, color: "rgba(217,217,217,0.25)",
    lineWidth: 1, lineStyle: 0, axisLabelVisible: false
  }));
}

function refreshMarkers() {
  if (markerHandle) {
    try { markerHandle.detach(); } catch (e) {}
    markerHandle = null;
  }
  if (!settings.markers) return;
  const markers = [];
  for (const r of allRecords) {
    if (r.l == null || !candleByTime.has(r.t)) continue;
    if (r.l >= settings.thrPos) {
      markers.push({
        time: r.t, position: "belowBar", color: "#26a69a",
        shape: "arrowUp", size: 1,
      });
    } else if (r.l <= settings.thrNeg) {
      markers.push({
        time: r.t, position: "aboveBar", color: "#ef5350",
        shape: "arrowDown", size: 1,
      });
    }
  }
  if (markers.length) {
    markerHandle = LightweightCharts.createSeriesMarkers(candleSeries, markers);
  }
}

function refreshLegend() {
  els.lblFast.textContent = `MA${settings.maFast}`;
  els.lblSlow.textContent = `MA${settings.maSlow}`;
}

// --------------------------------------------------------------------------
// Crosshair readout
// --------------------------------------------------------------------------
function onCrosshair(param) {
  if (!param || !param.time) {
    els.readout.textContent = "hover the chart";
    return;
  }
  const t = param.time;
  const c = candleByTime.get(t);
  const r = recByTime.get(t);
  const dt = new Date(t * 1000).toISOString().replace("T", " ").slice(0, 16) + "Z";
  let html = `<span class="k">time</span><span class="v">${dt}</span>`;
  if (c) {
    html += `<span class="k">O</span><span class="v">${fmtUsd(c.open)}</span>`;
    html += `<span class="k">H</span><span class="v">${fmtUsd(c.high)}</span>`;
    html += `<span class="k">L</span><span class="v">${fmtUsd(c.low)}</span>`;
    html += `<span class="k">C</span><span class="v">${fmtUsd(c.close)}</span>`;
  }
  if (r) {
    const cls = (r.l ?? 0) >= 0 ? "pos" : "neg";
    html += `<span class="k">LIQ</span><span class="v ${cls}">${fmtSign(r.l)}</span>`;
    html += `<span class="k">DIF</span><span class="v ${cls}">${fmtBtc(r.d)}</span>`;
  }
  els.readout.innerHTML = html;
}

// --------------------------------------------------------------------------
// Drawing tools
// --------------------------------------------------------------------------
function setDrawMode(mode) {
  drawMode = mode;
  trendPending = null;
  els.btnHLine.classList.toggle("active", mode === "hline");
  els.btnTrend.classList.toggle("active", mode === "trend");
  els.chart.classList.toggle("crosshair", !!mode);
  if (mode === "hline") {
    els.drawHint.textContent = "click chart to place a horizontal line";
    els.drawHint.classList.remove("hidden");
  } else if (mode === "trend") {
    els.drawHint.textContent = "click first point of trend line";
    els.drawHint.classList.remove("hidden");
  } else {
    els.drawHint.classList.add("hidden");
  }
}

function onClick(param) {
  if (!drawMode) return;
  if (!param.point || param.time == null) return;
  // price from candle series
  const price = candleSeries.coordinateToPrice(param.point.y);
  if (price == null) return;
  const t = param.time;

  if (drawMode === "hline") {
    drawings.push({ kind: "hline", price });
    saveDrawings();
    applyDrawingsToChart();
    setDrawMode(null);
    return;
  }

  if (drawMode === "trend") {
    if (!trendPending) {
      trendPending = { time: t, price };
      els.drawHint.textContent = "click second point";
      return;
    }
    drawings.push({
      kind: "trend",
      a: trendPending,
      b: { time: t, price },
    });
    trendPending = null;
    saveDrawings();
    applyDrawingsToChart();
    setDrawMode(null);
  }
}

function applyDrawingsToChart() {
  // Remove all existing drawing series
  for (const s of drawSeriesList) {
    try { chart.removeSeries(s); } catch (e) {}
  }
  drawSeriesList = [];
  if (!allCandles.length) return;
  const firstT = allCandles[0].time;
  const lastT  = allCandles[allCandles.length - 1].time;

  for (const d of drawings) {
    const s = chart.addSeries(LightweightCharts.LineSeries, {
      color: d.kind === "hline" ? "#aab8ff" : "#ffd778",
      lineWidth: 1,
      lineStyle: d.kind === "hline" ? 2 : 0,
      priceLineVisible: false,
      lastValueVisible: false,
      crosshairMarkerVisible: false,
    }, 0);
    if (d.kind === "hline") {
      s.setData([
        { time: firstT, value: d.price },
        { time: lastT,  value: d.price },
      ]);
    } else {
      const pts = [{ time: d.a.time, value: d.a.price },
                   { time: d.b.time, value: d.b.price }];
      pts.sort((p, q) => p.time - q.time);
      s.setData(pts);
    }
    drawSeriesList.push(s);
  }
}

function clearAllDrawings() {
  drawings = [];
  saveDrawings();
  applyDrawingsToChart();
}

// --------------------------------------------------------------------------
// Toolbar wiring
// --------------------------------------------------------------------------
function wireToolbar() {
  els.btnHLine.addEventListener("click", () =>
    setDrawMode(drawMode === "hline" ? null : "hline"));
  els.btnTrend.addEventListener("click", () =>
    setDrawMode(drawMode === "trend" ? null : "trend"));
  els.btnClear.addEventListener("click", () => {
    if (drawings.length && confirm(`Clear ${drawings.length} drawing(s)?`)) {
      clearAllDrawings();
    }
  });
  els.btnFit.addEventListener("click", () => chart.timeScale().fitContent());
  els.btnGear.addEventListener("click", () => togglePanel(true));
  els.btnClose.addEventListener("click", () => togglePanel(false));
  els.btnApply.addEventListener("click", () => {
    readFormIntoSettings();
    refreshMAs();
    refreshLiqBars();
    refreshLiqRefLines();
    refreshMarkers();
    refreshLegend();
  });
  els.btnReset.addEventListener("click", () => {
    settings = { ...DEFAULTS };
    saveSettings();
    applySettingsToForm();
    refreshMAs();
    refreshLiqBars();
    refreshLiqRefLines();
    refreshMarkers();
    refreshLegend();
  });
}

function togglePanel(open) {
  els.panel.classList.toggle("hidden", !open);
}

// --------------------------------------------------------------------------
// Entry: gate -> decrypt -> render
// --------------------------------------------------------------------------
let envelopePromise = null;
async function getEnvelope() {
  if (!envelopePromise) {
    envelopePromise = fetch("data/historical.enc.json").then(r => {
      if (!r.ok) throw new Error("envelope http " + r.status);
      return r.json();
    });
  }
  return envelopePromise;
}

async function handleSubmit(e) {
  e.preventDefault();
  const password = els.input.value;
  if (!password) return;
  els.error.textContent = "";
  const btn = els.form.querySelector("button");
  btn.disabled = true;
  btn.textContent = "decrypting…";
  try {
    const env = await getEnvelope();
    const data = await decryptPayload(env, password);
    btn.textContent = "rendering…";
    els.gate.classList.add("hidden");
    setTimeout(() => els.gate.remove(), 400);
    buildChart();
    applySettingsToForm();
    refreshLegend();
    wireToolbar();
    renderAll(data.records);
  } catch (err) {
    btn.disabled = false;
    btn.textContent = "unlock";
    els.error.textContent = "wrong passphrase";
    els.card.classList.remove("shake");
    void els.card.offsetWidth;
    els.card.classList.add("shake");
    els.input.select();
    setStatus("locked");
  }
}

els.form.addEventListener("submit", handleSubmit);
getEnvelope().catch(() => {});
