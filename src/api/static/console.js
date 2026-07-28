"use strict";

const API = "/api/v1";
const state = {
  token: sessionStorage.getItem("bitclone-api-token") || "",
  view: "dashboard",
  events: [],
  eventController: null,
  lastData: {},
};

const titles = {
  dashboard: "Node overview",
  chain: "Chain state",
  peers: "Peer network",
  mempool: "Mempool",
  explorer: "Block & transaction explorer",
  rpc: "RPC console",
};

const allowedRpc = [
  "getblockchaininfo", "getnetworkinfo", "getpeerinfo", "getrawmempool",
  "getrawtransaction", "decoderawtransaction", "gettxout", "sendrawtransaction",
];
const mutatingRpc = new Set(["sendrawtransaction"]);

const $ = (selector) => document.querySelector(selector);
const content = $("#view-content");
const tokenDialog = $("#token-dialog");
const tokenInput = $("#api-token");

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}

function formatNumber(value) {
  return Number.isFinite(Number(value)) ? new Intl.NumberFormat().format(Number(value)) : "—";
}

function shortHash(value, width = 12) {
  if (!value) return "—";
  const text = String(value);
  return text.length > width * 2 + 1 ? `${text.slice(0, width)}…${text.slice(-width)}` : text;
}

function authHeaders(extra = {}) {
  return { Authorization: `Bearer ${state.token}`, ...extra };
}

async function request(path) {
  const response = await fetch(`${API}${path}`, {
    headers: authHeaders({ Accept: "application/json" }),
    cache: "no-store",
  });
  if (response.status === 401) {
    disconnect("The API token was rejected.");
    throw new Error("Authentication required");
  }
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error?.message || `Request failed (${response.status})`);
  return payload;
}

async function rpc(method, params = []) {
  if (!allowedRpc.includes(method)) throw new Error("This RPC method is not allowlisted.");
  const response = await fetch("/rpc", {
    method: "POST",
    headers: authHeaders({
      "Content-Type": "application/json",
      "X-BitClone-CSRF": "1",
    }),
    body: JSON.stringify({ jsonrpc: "2.0", id: `console-${Date.now()}`, method, params }),
  });
  if (response.status === 401) {
    disconnect("The API token was rejected.");
    throw new Error("Authentication required");
  }
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error?.message || `RPC failed (${response.status})`);
  if (payload.error) throw new Error(`${payload.error.code}: ${payload.error.message}`);
  return payload.result;
}

function setConnection(kind, label) {
  $("#connection-dot").className = `status-dot ${kind}`;
  $("#connection-label").textContent = label;
}

function setTrust(trust) {
  const badge = $("#trust-badge");
  const local = trust?.block_data?.independently_validated;
  badge.className = `trust-badge ${local ? "local" : trust ? "remote" : "neutral"}`;
  badge.textContent = local ? "Independently validated" :
    trust ? "Trusted remote source" : "Trust source unknown";
}

function showNotice(message = "") {
  $("#notice-region").innerHTML = message
    ? `<div class="notice"><span>${escapeHtml(message)}</span><button class="text-button" data-retry>Retry</button></div>`
    : "";
}

function showLoading() {
  content.replaceChildren($("#loading-template").content.cloneNode(true));
}

function showError(error) {
  content.innerHTML = `<div class="error-state">
    <span class="empty-icon" aria-hidden="true">!</span>
    <h2>Could not load this view</h2>
    <p>${escapeHtml(error.message || error)}</p>
    <button class="secondary-button" data-retry>Try again</button>
  </div>`;
}

function showEmpty(title, body) {
  content.innerHTML = `<div class="empty-state">
    <span class="empty-icon" aria-hidden="true">◇</span>
    <h2>${escapeHtml(title)}</h2><p>${escapeHtml(body)}</p>
  </div>`;
}

function metric(label, value, meta) {
  return `<article class="metric-card"><span class="metric-label">${escapeHtml(label)}</span>
    <strong class="metric-value">${escapeHtml(value)}</strong><span class="metric-meta">${escapeHtml(meta)}</span></article>`;
}

function rows(values) {
  return `<dl class="data-list">${values.map(([key, value, cls = ""]) =>
    `<div class="data-row"><dt>${escapeHtml(key)}</dt><dd class="${cls}">${escapeHtml(value)}</dd></div>`
  ).join("")}</dl>`;
}

async function loadDashboard() {
  const [status, sync, trust, chain] = await Promise.all([
    request("/node/status"), request("/node/sync"), request("/node/trust"), request("/chain"),
  ]);
  state.lastData = { status, sync, trust, chain };
  setTrust(trust);
  const remote = trust.remote_source;
  const displayedHeight = remote?.tip_height ?? status.height;
  const displayedHeaderHeight = remote?.tip_height ?? status.best_header_height;
  const displayedTip = remote?.tip_hash ?? status.tip;
  const displayedHeader = remote?.tip_hash ?? status.best_header;
  const progress = Math.max(0, Math.min(100, Number(sync.remote_verification_progress ?? sync.progress ?? 0) * 100));
  const trustText = trust.block_data.independently_validated
    ? "This node validates its local chain data."
    : "Block data is supplied by a trusted Bitcoin Core instance.";
  if (remote && !remote.reachable) {
    showNotice(remote.error || "The trusted Bitcoin Core source is currently unreachable.");
  }
  content.innerHTML = `
    <div class="metric-grid">
      ${metric("Chain height", formatNumber(displayedHeight), status.network)}
      ${metric("Known header", formatNumber(displayedHeaderHeight), sync.state)}
      ${metric("Ready peers", formatNumber(status.ready_peers), `Target ${formatNumber(status.target_outbound_peers)}`)}
      ${metric("Mempool", formatNumber(status.mempool_size), "transactions")}
    </div>
    <div class="panel-grid">
      <article class="panel">
        <div class="panel-header"><div><h2>Synchronization</h2><p>${escapeHtml(trustText)}</p></div>
          <span class="pill ${status.started ? "success" : "warn"}">${status.started ? "Running" : "API only"}</span></div>
        <div class="progress-track" aria-label="Synchronization progress"><div class="progress-bar" style="width:${progress.toFixed(3)}%"></div></div>
        <p class="metric-meta">${progress.toFixed(4)}% reported verification progress</p>
        ${rows([
          ["Best block", shortHash(displayedTip), "hash"],
          ["Best header", shortHash(displayedHeader), "hash"],
          ["Storage", status.block_storage],
          ["Trust", trust.block_data.trust],
        ])}
      </article>
      <article class="panel">
        <div class="panel-header"><div><h2>Live node activity</h2><p>Streamed from BitClone</p></div></div>
        <div id="event-list" class="event-list">${renderEvents()}</div>
      </article>
    </div>`;
}

async function loadChain() {
  const [chain, rpcInfo] = await Promise.all([request("/chain"), rpc("getblockchaininfo")]);
  content.innerHTML = `<article class="panel">
    <div class="panel-header"><div><h2>Active chain</h2><p>Consensus and storage state</p></div>
      <span class="pill">${escapeHtml(chain.network)}</span></div>
    ${rows([
      ["Height", formatNumber(rpcInfo.blocks)],
      ["Headers", formatNumber(rpcInfo.headers)],
      ["Best block", rpcInfo.bestblockhash, "hash"],
      ["Chainwork", rpcInfo.chainwork, "hash"],
      ["Difficulty", rpcInfo.difficulty ?? "—"],
      ["Storage on disk", rpcInfo.size_on_disk ? `${formatNumber(rpcInfo.size_on_disk)} bytes` : "Not reported"],
      ["Pruned", rpcInfo.pruned ? "Yes" : "No"],
      ["Validation source", rpcInfo.bitclone?.trust || chain.block_storage],
    ])}
  </article>`;
}

async function loadPeers() {
  const [ready, book] = await Promise.all([request("/peers?limit=200&offset=0"), request("/peers/address-book")]);
  if (!book.peers.length) return showEmpty("No peer addresses yet", "BitClone will populate this view after DNS discovery or a manual connection.");
  const readyKeys = new Set(ready.items.map((peer) => `${peer.host}:${peer.port}`));
  content.innerHTML = `<article class="panel">
    <div class="panel-header"><div><h2>Peer address book</h2><p>${book.count} known endpoints, ${ready.page.total} ready</p></div></div>
    <div class="table-wrap"><table><thead><tr><th>Endpoint</th><th>Status</th><th>Source</th><th>Services</th><th>Last message</th><th>Failures</th></tr></thead>
    <tbody>${book.peers.map((peer) => {
      const isReady = readyKeys.has(`${peer.host}:${peer.port}`);
      return `<tr><td class="hash">${escapeHtml(peer.host)}:${escapeHtml(peer.port)}</td>
        <td><span class="pill ${isReady ? "success" : ""}">${isReady ? "Ready" : "Known"}</span></td>
        <td>${escapeHtml(peer.sources.join(", ") || "manual")}</td><td>${escapeHtml(peer.service_names || "—")}</td>
        <td>${escapeHtml(peer.last_known_message || "No connection attempt")}</td><td>${formatNumber(peer.fail_count)}</td></tr>`;
    }).join("")}</tbody></table></div></article>`;
}

async function loadMempool() {
  const data = await request("/mempool?limit=200&offset=0");
  if (!data.items.length) return showEmpty("The mempool is empty", "Transactions accepted by BitClone will appear here.");
  content.innerHTML = `<article class="panel"><div class="panel-header"><div><h2>Mempool transactions</h2>
    <p>${data.page.total} transaction${data.page.total === 1 ? "" : "s"}</p></div></div>
    <div class="table-wrap"><table><thead><tr><th>Transaction ID</th><th>Fee</th><th>Virtual size</th><th>Fee rate</th><th>Ancestors</th></tr></thead>
    <tbody>${data.items.map((tx) => `<tr><td class="hash" title="${escapeHtml(tx.txid)}">${escapeHtml(shortHash(tx.txid, 10))}</td>
      <td>${formatNumber(tx.fee_sats)} sats</td><td>${formatNumber(tx.virtual_size_vbytes)} vB</td>
      <td>${Number(tx.feerate_sats_per_vbyte).toFixed(2)} sat/vB</td><td>${formatNumber(tx.ancestor_count)}</td></tr>`).join("")}
    </tbody></table></div></article>`;
}

async function loadExplorer() {
  content.innerHTML = `<div class="panel-grid">
    <article class="panel"><div class="panel-header"><div><h2>Block lookup</h2><p>Use a 64-character display hash</p></div></div>
      <form id="block-form" class="search-form"><input name="hash" required pattern="[0-9a-fA-F]{64}" placeholder="Block hash">
      <button class="primary-button">Load block</button></form><pre id="block-result" class="result-box">No block selected.</pre></article>
    <article class="panel"><div class="panel-header"><div><h2>Transaction lookup</h2><p>Mempool or confirmed with a block hash</p></div></div>
      <form id="tx-form" class="form-stack"><input name="txid" required pattern="[0-9a-fA-F]{64}" placeholder="Transaction ID">
      <input name="blockhash" pattern="[0-9a-fA-F]{64}" placeholder="Block hash (required for confirmed transactions)">
      <button class="primary-button">Load transaction</button></form><pre id="tx-result" class="result-box">No transaction selected.</pre></article>
  </div>`;
  $("#block-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const output = $("#block-result"); output.textContent = "Loading…";
    try { output.textContent = JSON.stringify(await request(`/chain/blocks/${new FormData(event.target).get("hash")}`), null, 2); }
    catch (error) { output.textContent = error.message; }
  });
  $("#tx-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.target); const output = $("#tx-result"); output.textContent = "Loading…";
    const params = [form.get("txid"), true]; if (form.get("blockhash")) params.push(form.get("blockhash"));
    try { output.textContent = JSON.stringify(await rpc("getrawtransaction", params), null, 2); }
    catch (error) { output.textContent = error.message; }
  });
}

async function loadRpc() {
  content.innerHTML = `<div class="rpc-grid">
    <article class="panel"><div class="panel-header"><div><h2>Allowlisted RPC</h2><p>Calls stay on this node</p></div></div>
      <form id="rpc-form" class="form-stack"><label for="rpc-method">Method</label>
      <select id="rpc-method" name="method">${allowedRpc.map((method) => `<option>${method}</option>`).join("")}</select>
      <label for="rpc-params">Parameters (JSON array or object)</label>
      <textarea id="rpc-params" name="params" rows="7">[]</textarea>
      <div id="rpc-warning" class="warning-box" hidden>
        This method can change node state or broadcast data.
        <label class="checkbox-line"><input id="rpc-confirm" type="checkbox"> I understand and want to run it.</label>
      </div><button class="primary-button">Run RPC</button></form></article>
    <article class="panel"><div class="panel-header"><div><h2>Result</h2><p>Bitcoin-compatible JSON</p></div></div>
      <pre id="rpc-result" class="result-box">Choose a method and run it.</pre></article></div>`;
  const method = $("#rpc-method"); const warning = $("#rpc-warning");
  const syncWarning = () => { warning.hidden = !mutatingRpc.has(method.value); $("#rpc-confirm").checked = false; };
  method.addEventListener("change", syncWarning); syncWarning();
  $("#rpc-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const output = $("#rpc-result");
    if (mutatingRpc.has(method.value) && !$("#rpc-confirm").checked) {
      output.textContent = "Confirmation is required for this mutating method."; return;
    }
    let params;
    try { params = JSON.parse($("#rpc-params").value); }
    catch { output.textContent = "Parameters must be valid JSON."; return; }
    output.textContent = "Running…";
    try { output.textContent = JSON.stringify(await rpc(method.value, params), null, 2); }
    catch (error) { output.textContent = error.message; }
  });
}

const loaders = { dashboard: loadDashboard, chain: loadChain, peers: loadPeers, mempool: loadMempool, explorer: loadExplorer, rpc: loadRpc };

async function loadView(view = state.view) {
  if (!state.token) return openTokenDialog();
  state.view = view;
  $("#view-title").textContent = titles[view];
  document.querySelectorAll(".nav-item").forEach((button) => {
    const active = button.dataset.view === view;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
  });
  showNotice(); showLoading();
  try {
    await loaders[view]();
    setConnection("online", "Node connected");
  } catch (error) {
    setConnection(navigator.onLine ? "offline" : "offline", navigator.onLine ? "Node unavailable" : "Browser offline");
    showError(error);
  }
}

function renderEvents() {
  if (!state.events.length) return `<p class="metric-meta">Waiting for node events…</p>`;
  return state.events.slice(0, 12).map((event) => `<div class="event-item"><i></i>
    <span><strong>${escapeHtml(event.type)}</strong> · ${escapeHtml(event.summary)}</span>
    <time>${escapeHtml(event.time)}</time></div>`).join("");
}

function recordEvent(type, data) {
  const summary = data.state || data.code || data.tip || data.size ||
    JSON.stringify(data).slice(0, 90);
  state.events.unshift({ type, summary, time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) });
  state.events = state.events.slice(0, 30);
  const list = $("#event-list"); if (list) list.innerHTML = renderEvents();
}

async function connectEvents() {
  state.eventController?.abort();
  if (!state.token) return;
  const controller = new AbortController(); state.eventController = controller;
  try {
    const response = await fetch(`${API}/events`, { headers: authHeaders(), signal: controller.signal, cache: "no-store" });
    if (!response.ok || !response.body) throw new Error("Event stream unavailable");
    const reader = response.body.getReader(); const decoder = new TextDecoder(); let buffer = "";
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const frames = buffer.split("\n\n"); buffer = frames.pop() || "";
      for (const frame of frames) {
        let type = "message"; let data = null;
        for (const line of frame.split("\n")) {
          if (line.startsWith("event:")) type = line.slice(6).trim();
          if (line.startsWith("data:")) {
            try { data = JSON.parse(line.slice(5)); } catch { data = { state: line.slice(5).trim() }; }
          }
        }
        if (data) recordEvent(type, data);
      }
    }
  } catch (error) {
    if (error.name !== "AbortError" && state.token) setTimeout(connectEvents, 3000);
  }
}

function openTokenDialog(message = "") {
  $("#token-error").textContent = message;
  tokenInput.value = "";
  if (!tokenDialog.open) tokenDialog.showModal();
  setTimeout(() => tokenInput.focus(), 0);
}

function disconnect(message = "") {
  sessionStorage.removeItem("bitclone-api-token"); state.token = ""; state.eventController?.abort();
  setConnection("idle", "Token required"); openTokenDialog(message);
}

$("#token-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const candidate = tokenInput.value.trim();
  if (!candidate) return;
  state.token = candidate;
  try {
    await request("/node/status");
    sessionStorage.setItem("bitclone-api-token", candidate);
    tokenDialog.close(); connectEvents(); loadView("dashboard");
  } catch (error) {
    state.token = ""; $("#token-error").textContent = error.message;
  }
});

$("#primary-nav").addEventListener("click", (event) => {
  const button = event.target.closest("[data-view]"); if (button) loadView(button.dataset.view);
});
$("#refresh-view").addEventListener("click", () => loadView());
$("#change-token").addEventListener("click", () => disconnect());
document.addEventListener("click", (event) => { if (event.target.closest("[data-retry]")) loadView(); });
window.addEventListener("offline", () => { setConnection("offline", "Browser offline"); showNotice("Network access is offline. BitClone will retry when connectivity returns."); });
window.addEventListener("online", () => { showNotice(); loadView(); connectEvents(); });

if (state.token) { connectEvents(); loadView(); } else { openTokenDialog(); }
