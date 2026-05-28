/* Dashboard renderer. Fetches one encrypted bundle, decrypts it locally with
   a passphrase, and draws the result with lightweight-charts. */

const els = {
  status:  document.getElementById("status"),
  gate:    document.getElementById("gate"),
  form:    document.getElementById("gate-form"),
  input:   document.getElementById("gate-input"),
  error:   document.getElementById("gate-error"),
  card:    null,
  readout: document.getElementById("hover-info"),
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
  let sum = 0;
  for (let i = 0; i < series.length; i++) {
    sum += series[i].close;
    if (i >= window) sum -= series[i - window].close;
    if (i >= window - 1) out.push({ time: series[i].time, value: sum / window });
  }
  return out;
}

// --------------------------------------------------------------------------
// Chart
// --------------------------------------------------------------------------
let chart, candleSeries, volSeries, liqSeries, ma720Series, ma8400Series;
let candleByTime = new Map();
let recByTime = new Map();

function buildChart() {
  chart = LightweightCharts.createChart(document.getElementById("chart"), {
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

  // Pane 0: candles + MAs
  candleSeries = chart.addSeries(LightweightCharts.CandlestickSeries, {
    upColor: "#26a69a", downColor: "#ef5350",
    borderUpColor: "#26a69a", borderDownColor: "#ef5350",
    wickUpColor: "#26a69a", wickDownColor: "#ef5350",
  }, 0);

  ma720Series = chart.addSeries(LightweightCharts.LineSeries, {
    color: "#2962ff", lineWidth: 1, priceLineVisible: false, lastValueVisible: false,
  }, 0);
  ma8400Series = chart.addSeries(LightweightCharts.LineSeries, {
    color: "#ff9800", lineWidth: 1, priceLineVisible: false, lastValueVisible: false,
  }, 0);

  // Pane 1: volume
  volSeries = chart.addSeries(LightweightCharts.HistogramSeries, {
    priceFormat: { type: "volume" },
    priceLineVisible: false, lastValueVisible: false,
  }, 1);

  // Pane 2: signal histogram with reference lines
  liqSeries = chart.addSeries(LightweightCharts.HistogramSeries, {
    priceFormat: { type: "price", precision: 2, minMove: 0.01 },
    priceLineVisible: false,
    base: 0,
  }, 2);
  liqSeries.createPriceLine({ price: 3,  color: "rgba(38,166,154,0.45)", lineWidth: 1, lineStyle: 2, axisLabelVisible: false });
  liqSeries.createPriceLine({ price: -3, color: "rgba(239,83,80,0.45)",  lineWidth: 1, lineStyle: 2, axisLabelVisible: false });
  liqSeries.createPriceLine({ price: 0,  color: "rgba(217,217,217,0.25)", lineWidth: 1, lineStyle: 0, axisLabelVisible: false });

  // Pane heights: candles 60% / volume 15% / signal 25%
  const panes = chart.panes();
  if (panes.length >= 3) {
    const total = window.innerHeight - 64;
    panes[0].setHeight(Math.round(total * 0.60));
    panes[1].setHeight(Math.round(total * 0.15));
    panes[2].setHeight(Math.round(total * 0.25));
  }

  chart.subscribeCrosshairMove(onCrosshair);
}

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

function renderFromRecords(records) {
  // Build candles + volumes from inline OHLCV
  const candles = [];
  const volumes = [];
  for (const r of records) {
    if (!r.k) continue;
    const [o, h, l, c, v] = r.k;
    const candle = { time: r.t, open: o, high: h, low: l, close: c };
    candles.push(candle);
    volumes.push({
      time: r.t,
      value: v,
      color: c >= o ? "rgba(38,166,154,0.55)" : "rgba(239,83,80,0.55)",
    });
  }

  candleByTime = new Map(candles.map(c => [c.time, c]));
  recByTime   = new Map(records.map(r => [r.t, r]));

  candleSeries.setData(candles);
  volSeries.setData(volumes);
  ma720Series.setData(sma(candles, 720));
  ma8400Series.setData(sma(candles, 8400));

  const liqBars = records.map(r => ({
    time: r.t,
    value: r.l == null ? 0 : r.l,
    color: (r.l ?? 0) >= 0 ? "rgba(38,166,154,0.85)" : "rgba(239,83,80,0.85)",
  }));
  liqSeries.setData(liqBars);

  chart.timeScale().fitContent();
  setStatus(`ok · ${candles.length.toLocaleString()} bars`, "ok");
}

// --------------------------------------------------------------------------
// Entry
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
    renderFromRecords(data.records);
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
// Warm-fetch while the user types
getEnvelope().catch(() => {});
