/* FreeAI Gateway admin console — vanilla JS, no build step. */
"use strict";

/* ---------- tiny helpers ---------- */
const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtTime(ts) {
  const d = new Date(Number(ts));
  return Number.isFinite(d.getTime())
    ? d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : String(ts);
}

function statusClass(status) {
  if (status >= 200 && status < 400) return "ok";
  if (status >= 400 && status < 500) return "warn";
  return "bad"; // 5xx and 0 (never reached)
}

let noticeTimer = null;
function notify(message, isError = false) {
  const el = $("notice");
  el.textContent = message;
  el.classList.toggle("hidden", false);
  el.style.borderColor = isError ? "var(--color-destructive)" : "var(--color-accent)";
  el.style.color = isError ? "var(--color-destructive)" : "var(--color-accent)";
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => el.classList.add("hidden"), isError ? 6000 : 3000);
}

/** API wrapper: JSON in/out, propagates {status, message}. */
async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || "GET",
    headers: opts.body !== undefined ? { "content-type": "application/json" } : undefined,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    credentials: "same-origin",
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* non-JSON response */
  }
  if (!res.ok) {
    const message = data && data.error ? data.error.message : `${res.status} ${res.statusText || "error"}`;
    throw { status: res.status, message };
  }
  return data;
}

/* ---------- state ---------- */
const state = {
  providers: [],
  chains: [],
  logsFilter: "all",
  logsTimer: null,
  oauth: [],
  oauthFlows: {}, // prefix → in-flight login UI state (authUrl / user_code)
  oauthTimers: {}, // prefix → device-poll setTimeout id
};

/* ---------- auth / boot ---------- */
async function boot() {
  try {
    await api("/admin/api/me");
    showApp();
    await loadAll();
  } catch {
    showLogin();
  }
}

function showLogin() {
  stopLogsTimer(); // a pending auto-refresh poll would just hammer 401s
  stopOauthTimers(); // same for device-flow polls
  $("login-overlay").classList.remove("hidden");
  ["app-header", "app-nav", "app-main"].forEach((id) => $(id).classList.add("hidden"));
  const pw = $("login-password");
  pw.value = "";
  setTimeout(() => pw.focus(), 50);
}

function showApp() {
  $("login-overlay").classList.add("hidden");
  ["app-header", "app-nav", "app-main"].forEach((id) => $(id).classList.remove("hidden"));
}

async function loadAll() {
  await Promise.all([loadProviders(), loadLogs(), loadStats(), loadFallbacks(), loadOauth()]);
}

$("login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const errEl = $("login-error");
  errEl.classList.add("hidden");
  const password = $("login-password").value;
  try {
    await api("/admin/api/login", { method: "POST", body: { password } });
    showApp();
    await loadAll();
  } catch (err) {
    errEl.textContent =
      err.status === 503
        ? "Console disabled — set the ADMIN_PASSWORD secret on the worker first."
        : err.status === 401
          ? "Wrong password."
          : err.message;
    errEl.classList.remove("hidden");
  }
});

$("logout-btn").addEventListener("click", async () => {
  stopLogsTimer();
  try {
    await api("/admin/api/logout", { method: "POST" });
  } catch {
    /* cookie clear failure is not fatal */
  }
  showLogin();
});

/* ---------- tabs ---------- */
const TABS = ["overview", "logs", "stats", "fallbacks", "playground"];

function selectTab(name) {
  TABS.forEach((t) => {
    $("tab-" + t).setAttribute("aria-selected", String(t === name));
    $("tab-" + t).tabIndex = t === name ? 0 : -1;
    $("panel-" + t).classList.toggle("hidden", t !== name);
  });
  if (name !== "logs") stopLogsTimer(); // auto-refresh is a Logs-tab-only behavior
  if (name !== "overview") stopOauthTimers(); // device polls belong to the Overview tab
  if (name === "overview") {
    loadProviders();
    loadOauth();
  }
  if (name === "logs") loadLogs();
  if (name === "stats") loadStats();
  if (name === "fallbacks") loadFallbacks();
}

TABS.forEach((t) => $("tab-" + t).addEventListener("click", () => selectTab(t)));

document.addEventListener("keydown", (ev) => {
  if (ev.key !== "ArrowRight" && ev.key !== "ArrowLeft") return;
  // Never steal arrows from text entry (textarea, inputs, selects, editors).
  const target = ev.target;
  if (
    target &&
    typeof target.closest === "function" &&
    target.closest("input, textarea, select, [contenteditable]")
  ) {
    return;
  }
  const current = TABS.find((t) => $("tab-" + t).getAttribute("aria-selected") === "true");
  if (!current) return;
  const idx = (TABS.indexOf(current) + (ev.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length;
  selectTab(TABS[idx]);
  $("tab-" + TABS[idx]).focus();
});

function stopLogsTimer() {
  clearInterval(state.logsTimer);
  state.logsTimer = null;
}

/* ---------- Overview: providers ---------- */
async function loadProviders() {
  try {
    const data = await api("/admin/api/providers");
    state.providers = data.providers || [];
    renderProviders();
  } catch (err) {
    if (err.status === 401) return showLogin();
    notify(`Providers load failed: ${err.message}`, true);
  }
}

function renderProviders() {
  const grid = $("provider-grid");
  grid.innerHTML = state.providers
    .map((p) => {
      const dot = p.keyConfigured
        ? '<span class="key-dot configured" title="Key configured"></span>'
        : '<span class="key-dot missing" title="Key missing — set the secret"></span>';
      const models = (p.freeModels || []).slice(0, 2).join(", ");
      return `
      <div class="provider-card" data-prefix="${escapeHtml(p.prefix)}">
        <div class="card-top">
          <span class="provider-name">${escapeHtml(p.prefix)}</span>
          ${dot}
        </div>
        <div class="card-meta">
          ${p.keyConfigured ? "key configured" : "key missing (secret)"} ·
          ${escapeHtml(models || "no curated models")}
        </div>
        <div class="card-actions">
          <label class="switch" title="Enable/disable provider">
            <input type="checkbox" class="provider-toggle" aria-label="Enable ${escapeHtml(p.prefix)}" ${p.enabled ? "checked" : ""} />
            <span class="track"><span class="thumb"></span></span>
          </label>
          <button class="btn ghost provider-test" type="button">Test</button>
          <span class="test-result" aria-live="polite"></span>
        </div>
      </div>`;
    })
    .join("");
  // The Logs provider filter mirrors the registry — keep it in sync here so
  // it is populated once providers load and after every reload.
  renderProviderFilterOptions();
}

$("provider-grid").addEventListener("change", async (ev) => {
  const input = ev.target.closest(".provider-toggle");
  if (!input) return;
  const card = input.closest(".provider-card");
  const prefix = card.dataset.prefix;
  const enabled = input.checked;
  try {
    await api(`/admin/api/providers/${encodeURIComponent(prefix)}/toggle`, {
      method: "POST",
      body: { enabled },
    });
    notify(`${prefix} ${enabled ? "enabled" : "disabled"}`);
  } catch (err) {
    input.checked = !enabled; // revert on failure
    notify(`Toggle failed: ${err.message}`, true);
  }
});

$("provider-grid").addEventListener("click", async (ev) => {
  const btn = ev.target.closest(".provider-test");
  if (!btn) return;
  const card = btn.closest(".provider-card");
  const prefix = card.dataset.prefix;
  const out = card.querySelector(".test-result");
  out.textContent = "testing…";
  out.className = "test-result";
  btn.disabled = true;
  try {
    const r = await api(`/admin/api/providers/${encodeURIComponent(prefix)}/test`, { method: "POST" });
    out.textContent = r.ok ? `ok · ${r.status} · ${r.latencyMs}ms` : `fail · ${r.status}${r.error ? " · " + r.error : ""}`;
    out.className = `test-result ${r.ok ? "ok" : "fail"}`;
  } catch (err) {
    out.textContent = `error · ${err.message}`;
    out.className = "test-result fail";
  } finally {
    btn.disabled = false;
  }
});

$("providers-reload").addEventListener("click", loadProviders);

/* ---------- Overview: OAuth providers (Wave B) ---------- */
/**
 * Device-flow poll chain: fires immediately, then re-arms itself every
 * `intervalSec` seconds. Stops on connected/error/401/network failure —
 * the only state that keeps polling is "pending".
 *
 * Liveness: each start increments a module-level generation; stale chains
 * (superseded by a new start, or stopped) abort silently instead of
 * re-arming. slow_down bumps the poll interval in a module-level map —
 * state.oauthFlows is re-rendered on every poll and must not hold timers.
 */
let oauthPollSeq = 0;
const oauthPollGeneration = {}; // prefix → live chain seq
const oauthSlowDown = {}; // prefix → current interval after slow_down

async function pollDevice(prefix, intervalSec) {
  const gen = oauthPollGeneration[prefix];
  try {
    const data = await api(`/admin/api/oauth/${encodeURIComponent(prefix)}/poll`);
    if (gen !== oauthPollGeneration[prefix]) return; // superseded/stopped chain
    if (data.status === "connected") {
      stopOauthPoll(prefix);
      delete state.oauthFlows[prefix];
      notify(`${prefix} connected`);
      await loadOauth();
      return;
    }
    if (data.status === "error") {
      stopOauthPoll(prefix);
      delete state.oauthFlows[prefix];
      notify(`${prefix} login failed: ${data.error || "flow error"}`, true);
      await loadOauth();
      return;
    }
    if (data.error === "slow_down") {
      oauthSlowDown[prefix] = (oauthSlowDown[prefix] || intervalSec) + 5;
    }
    const delaySec = oauthSlowDown[prefix] || intervalSec;
    state.oauthTimers[prefix] = setTimeout(() => pollDevice(prefix, delaySec), delaySec * 1000);
  } catch (err) {
    if (err.status === 401) return showLogin();
    notify(`OAuth poll failed: ${err.message}`, true);
    // network failure — stop hammering
  }
}

function startDevicePoll(prefix, intervalSec) {
  stopOauthPoll(prefix); // one live chain per prefix
  oauthPollGeneration[prefix] = ++oauthPollSeq;
  oauthSlowDown[prefix] = Math.max(1, Number(intervalSec) || 5);
  void pollDevice(prefix, oauthSlowDown[prefix]);
}

function stopOauthPoll(prefix) {
  if (state.oauthTimers[prefix]) {
    clearTimeout(state.oauthTimers[prefix]);
    delete state.oauthTimers[prefix];
  }
  delete oauthPollGeneration[prefix];
  delete oauthSlowDown[prefix];
}

function stopOauthTimers() {
  for (const prefix of Object.keys(state.oauthTimers)) stopOauthPoll(prefix);
}

async function loadOauth() {
  try {
    const data = await api("/admin/api/oauth");
    state.oauth = data.providers || [];
    renderOauth();
  } catch (err) {
    if (err.status === 401) return showLogin();
    notify(`OAuth load failed: ${err.message}`, true);
  }
}

/** Status line: connected (+expiry) wins; else last error; else not connected.
 * A connected row that also carries lastError is the corrupt-token state
 * (e.g. key rotation) — surface both so the operator sees reconnect is needed. */
function oauthStatusText(p) {
  if (p.connected) {
    const base = p.expiresAt ? `connected · expires ${fmtTime(p.expiresAt)}` : "connected";
    return p.lastError ? `${base} · reconnect required: ${p.lastError}` : base;
  }
  if (p.lastError) return `last error: ${p.lastError}`;
  return "not connected";
}

function renderOauth() {
  const grid = $("oauth-grid");
  grid.innerHTML = state.oauth
    .map((p) => {
      const flow = state.oauthFlows[p.prefix];
      let actions = "";
      if (p.flowMode === "paste") {
        actions = `
          <textarea class="oauth-paste-input" rows="2" placeholder="Paste the token" aria-label="Token for ${escapeHtml(p.prefix)}"></textarea>
          <button class="btn oauth-connect" type="button">Connect</button>`;
      } else if (p.flowMode === "paste-code") {
        actions = `
          <button class="btn oauth-start" type="button">Start login</button>
          ${
            flow && flow.authUrl
              ? `<a class="oauth-auth-link" href="${escapeHtml(flow.authUrl)}" target="_blank" rel="noopener">Open login page</a>
                 <input class="oauth-code-input" type="text" placeholder="Paste the code" aria-label="Authorization code for ${escapeHtml(p.prefix)}" />
                 <button class="btn oauth-complete" type="button">Complete</button>`
              : ""
          }`;
        if (p.importToken) {
          actions += `
          <textarea class="oauth-token-input" rows="2" placeholder="Or paste a token (setup token / auth.json)" aria-label="Token for ${escapeHtml(p.prefix)}"></textarea>
          <button class="btn oauth-token-connect" type="button">Connect with token</button>`;
        }
      } else if (p.flowMode === "device") {
        actions = `
          <button class="btn oauth-start" type="button">Start login</button>
          ${
            flow
              ? `<span class="oauth-user-code">code <strong>${escapeHtml(flow.userCode ?? "")}</strong></span>
                 <a class="oauth-auth-link" href="${escapeHtml(flow.verifyUrl ?? "")}" target="_blank" rel="noopener">${escapeHtml(flow.verifyUrl ?? "")}</a>
                 <span class="card-meta">waiting for approval…</span>`
              : ""
          }`;
        if (p.importToken) {
          actions += `
          <textarea class="oauth-token-input" rows="2" placeholder="Or paste a token (setup token / auth.json)" aria-label="Token for ${escapeHtml(p.prefix)}"></textarea>
          <button class="btn oauth-token-connect" type="button">Connect with token</button>`;
        }
      }
      const disconnect = p.connected
        ? `<button class="btn ghost oauth-disconnect" type="button">Disconnect</button>`
        : "";
      return `
      <div class="oauth-card" data-prefix="${escapeHtml(p.prefix)}">
        <div class="card-top">
          <span class="provider-name">${escapeHtml(p.prefix)}</span>
          <span class="flow-badge">${escapeHtml(p.flowMode)}</span>
        </div>
        ${p.instructions ? `<div class="card-meta oauth-instructions">${escapeHtml(p.instructions)}</div>` : ""}
        <div class="card-meta oauth-status">${escapeHtml(oauthStatusText(p))}</div>
        <div class="card-actions oauth-actions">${actions}${disconnect}</div>
      </div>`;
    })
    .join("");
}

$("oauth-grid").addEventListener("click", async (ev) => {
  const btn = ev.target.closest("button");
  if (!btn) return;
  const cardEl = btn.closest(".oauth-card");
  if (!cardEl) return;
  const prefix = cardEl.dataset.prefix;
  if (btn.classList.contains("oauth-connect")) {
    const input = cardEl.querySelector(".oauth-paste-input");
    try {
      const data = await api(`/admin/api/oauth/${encodeURIComponent(prefix)}/complete`, {
        method: "POST",
        body: { token: input.value },
      });
      notify(`${prefix} connected${data.accountLabel ? ` — ${data.accountLabel}` : ""}`);
      await loadOauth();
    } catch (err) {
      if (err.status === 401) return showLogin();
      notify(`Connect failed: ${err.message}`, true);
    }
    return;
  }
  if (btn.classList.contains("oauth-start")) {
    try {
      const data = await api(`/admin/api/oauth/${encodeURIComponent(prefix)}/start`, {
        method: "POST",
      });
      if (data.mode === "paste-code") {
        state.oauthFlows[prefix] = { authUrl: data.authUrl };
        renderOauth();
      } else if (data.mode === "device") {
        state.oauthFlows[prefix] = {
          userCode: data.user_code,
          verifyUrl: data.verification_uri_complete || data.verification_uri,
        };
        renderOauth();
        startDevicePoll(prefix, data.interval);
      }
    } catch (err) {
      if (err.status === 401) return showLogin();
      notify(`Login start failed: ${err.message}`, true);
    }
    return;
  }
  if (btn.classList.contains("oauth-complete")) {
    const input = cardEl.querySelector(".oauth-code-input");
    try {
      const data = await api(`/admin/api/oauth/${encodeURIComponent(prefix)}/complete`, {
        method: "POST",
        body: { code: input.value },
      });
      delete state.oauthFlows[prefix];
      stopOauthPoll(prefix);
      notify(`${prefix} connected${data.accountLabel ? ` — ${data.accountLabel}` : ""}`);
      await loadOauth();
    } catch (err) {
      if (err.status === 401) return showLogin();
      notify(`Connect failed: ${err.message}`, true);
    }
    return;
  }
  if (btn.classList.contains("oauth-token-connect")) {
    const input = cardEl.querySelector(".oauth-token-input");
    try {
      const data = await api(`/admin/api/oauth/${encodeURIComponent(prefix)}/complete`, {
        method: "POST",
        body: { token: input.value },
      });
      delete state.oauthFlows[prefix];
      stopOauthPoll(prefix);
      notify(`${prefix} connected${data.accountLabel ? ` — ${data.accountLabel}` : ""}`);
      await loadOauth();
    } catch (err) {
      if (err.status === 401) return showLogin();
      notify(`Connect failed: ${err.message}`, true);
    }
    return;
  }
  if (btn.classList.contains("oauth-disconnect")) {
    try {
      await api(`/admin/api/oauth/${encodeURIComponent(prefix)}`, { method: "DELETE" });
      delete state.oauthFlows[prefix];
      stopOauthPoll(prefix);
      notify(`${prefix} disconnected`);
      await loadOauth();
    } catch (err) {
      if (err.status === 401) return showLogin();
      notify(`Disconnect failed: ${err.message}`, true);
    }
  }
});

$("oauth-reload").addEventListener("click", loadOauth);

/* ---------- Logs ---------- */
function renderProviderFilterOptions() {  const sel = $("logs-provider");
  const current = sel.value || "all";
  const options = ['<option value="all">all</option>']
    .concat(state.providers.map((p) => `<option value="${escapeHtml(p.prefix)}">${escapeHtml(p.prefix)}</option>`));
  sel.innerHTML = options.join("");
  sel.value = [...sel.options].some((o) => o.value === current) ? current : "all";
}

async function loadLogs() {
  try {
    const limit = $("logs-limit").value || "50";
    const data = await api(`/admin/api/logs?limit=${encodeURIComponent(limit)}`);
    const rows = (data.logs || []).filter(
      (r) => state.logsFilter === "all" || r.provider === state.logsFilter,
    );
    renderLogs(rows);
  } catch (err) {
    if (err.status === 401) return showLogin();
    if (err.status === 503) {
      $("logs-body").innerHTML = "";
      $("logs-empty").textContent = "D1 not configured — request logs unavailable (run wrangler d1 migrations).";
      $("logs-empty").classList.remove("hidden");
      return;
    }
    notify(`Logs load failed: ${err.message}`, true);
  }
}

function renderLogs(rows) {
  const body = $("logs-body");
  $("logs-empty").classList.toggle("hidden", rows.length > 0);
  body.innerHTML = rows
    .map((r) => {
      const status = r.status === 0 || r.status === "0" ? "—" : String(r.status);
      const errText = r.error || "";
      return `<tr>
        <td class="mono">${escapeHtml(fmtTime(r.ts))}</td>
        <td class="mono">${escapeHtml(r.provider)}</td>
        <td class="mono">${escapeHtml(r.model)}</td>
        <td><span class="status ${statusClass(Number(r.status))}">${escapeHtml(status)}</span></td>
        <td class="mono">${r.latency_ms == null ? "—" : escapeHtml(r.latency_ms + "ms")}</td>
        <td>${Number(r.stream) ? "yes" : "no"}</td>
        <td class="mono">${r.chain == null ? "—" : escapeHtml(r.chain)}</td>
        <td class="mono">${r.attempt == null ? "—" : escapeHtml(String(r.attempt))}</td>
        <td class="mono muted">${errText ? escapeHtml(errText) : ""}</td>
      </tr>`;
    })
    .join("");
}

$("logs-provider").addEventListener("change", (ev) => {
  state.logsFilter = ev.target.value;
  loadLogs();
});
$("logs-limit").addEventListener("change", loadLogs);
$("logs-reload").addEventListener("click", loadLogs);
$("logs-auto").addEventListener("change", (ev) => {
  clearInterval(state.logsTimer);
  if (ev.target.checked) state.logsTimer = setInterval(loadLogs, 5000);
});
$("logs-prune").addEventListener("click", async () => {
  const btn = $("logs-prune");
  btn.disabled = true;
  try {
    await api("/admin/api/logs/prune", { method: "POST", body: { olderThanDays: 30 } });
    notify("Logs older than 30 days pruned");
    await loadLogs();
  } catch (err) {
    if (err.status === 401) return showLogin();
    notify(`Prune failed: ${err.message}`, true);
  } finally {
    btn.disabled = false;
  }
});

/* ---------- Stats ---------- */
async function loadStats() {
  try {
    const data = await api("/admin/api/stats");
    renderStats(data.stats || []);
  } catch (err) {
    if (err.status === 401) return showLogin();
    if (err.status === 503) {
      $("stats-body").innerHTML = "";
      $("stats-empty").textContent = "D1 not configured — stats unavailable (run wrangler d1 migrations).";
      $("stats-empty").classList.remove("hidden");
      return;
    }
    notify(`Stats load failed: ${err.message}`, true);
  }
}

function renderStats(stats) {
  const body = $("stats-body");
  $("stats-empty").classList.toggle("hidden", stats.length > 0);
  body.innerHTML = stats
    .map((s) => {
      const rate = s.requests > 0 ? ((Number(s.errors) / Number(s.requests)) * 100).toFixed(1) + "%" : "—";
      const avg = s.avgLatencyMs == null ? "—" : Math.round(Number(s.avgLatencyMs)) + "ms";
      return `<tr>
        <td class="mono">${escapeHtml(s.provider)}</td>
        <td class="mono">${escapeHtml(String(s.requests))}</td>
        <td class="mono">${escapeHtml(String(s.errors))}</td>
        <td class="mono">${escapeHtml(rate)}</td>
        <td class="mono">${escapeHtml(avg)}</td>
      </tr>`;
    })
    .join("");
}

$("stats-reload").addEventListener("click", loadStats);

/* ---------- Fallbacks editor ---------- */
function allPrefixes() {
  return state.providers.map((p) => p.prefix);
}

async function loadFallbacks() {
  try {
    const data = await api("/admin/api/fallbacks");
    state.chains = (data.chains || []).map((c) => ({ name: c.name, providers: [...c.providers] }));
    if (state.providers.length === 0) await loadProviders();
    renderChains();
  } catch (err) {
    if (err.status === 401) return showLogin();
    notify(`Fallbacks load failed: ${err.message}`, true);
  }
}

function renderChains() {
  const editor = $("chains-editor");
  const prefixes = allPrefixes();
  editor.innerHTML = state.chains
    .map(
      (chain, ci) => `
    <div class="chain-row" data-ci="${ci}">
      <div class="chain-top">
        <label class="inline-label" for="chain-name-${ci}">Name (model prefix)</label>
        <input id="chain-name-${ci}" class="chain-name-input" type="text" value="${escapeHtml(chain.name)}" />
        <button class="btn danger chain-remove" type="button">Remove chain</button>
      </div>
      <div class="chain-providers">
        ${chain.providers
          .map(
            (p, pi) => `
          <span class="chip">${escapeHtml(p)}
            <span class="chip-arrow">
              <button type="button" class="chip-up" title="Move up" ${pi === 0 ? "disabled" : ""}>▲</button>
              <button type="button" class="chip-down" title="Move down" ${pi === chain.providers.length - 1 ? "disabled" : ""}>▼</button>
            </span>
            <button type="button" class="remove chip-remove" title="Remove provider">✕</button>
          </span>`,
          )
          .join("")}
        <span class="add-provider">
          <select class="chain-add-select" aria-label="Add provider to chain">
            ${prefixes.map((p) => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join("")}
          </select>
          <button class="btn ghost chain-add-btn" type="button">Add</button>
        </span>
      </div>
    </div>`,
    )
    .join("");
}

$("chain-add").addEventListener("click", () => {
  const base = "chain";
  let name = base;
  let n = 2;
  while (state.chains.some((c) => c.name === name)) name = `${base}-${n++}`;
  state.chains.push({ name, providers: [] });
  renderChains();
});

$("chains-editor").addEventListener("input", (ev) => {
  // Sync chain-name edits into state immediately — chip operations re-render
  // the editor from state, and without this an uncommitted name reverts.
  const input = ev.target.closest(".chain-name-input");
  if (!input) return;
  const row = input.closest(".chain-row");
  const ci = Number(row && row.dataset.ci);
  if (state.chains[ci]) state.chains[ci].name = input.value;
});

$("chains-editor").addEventListener("click", (ev) => {
  const row = ev.target.closest(".chain-row");
  if (!row) return;
  const ci = Number(row.dataset.ci);
  const chain = state.chains[ci];
  if (ev.target.closest(".chain-remove")) {
    state.chains.splice(ci, 1);
    renderChains();
  } else if (ev.target.closest(".chip-up") || ev.target.closest(".chip-down")) {
    const pi = [...row.querySelectorAll(".chip")].findIndex((c) => c.contains(ev.target.closest(".chip-arrow")));
    if (pi < 0) return;
    const delta = ev.target.closest(".chip-up") ? -1 : 1;
    const next = pi + delta;
    if (next < 0 || next >= chain.providers.length) return;
    [chain.providers[pi], chain.providers[next]] = [chain.providers[next], chain.providers[pi]];
    renderChains();
  } else if (ev.target.closest(".chip-remove")) {
    const pi = [...row.querySelectorAll(".chip")].findIndex((c) => c.contains(ev.target.closest(".chip-remove")));
    if (pi < 0) return;
    chain.providers.splice(pi, 1);
    renderChains();
  } else if (ev.target.closest(".chain-add-btn")) {
    const sel = row.querySelector(".chain-add-select");
    if (sel.value) chain.providers.push(sel.value);
    renderChains();
  }
});

$("fallbacks-save").addEventListener("click", async () => {
  const errEl = $("fallbacks-error");
  errEl.classList.add("hidden");
  // read names from inputs (may have been edited)
  document.querySelectorAll(".chain-row").forEach((row) => {
    const ci = Number(row.dataset.ci);
    const nameInput = row.querySelector(".chain-name-input");
    if (nameInput && state.chains[ci]) state.chains[ci].name = nameInput.value.trim();
  });
  try {
    const data = await api("/admin/api/fallbacks", {
      method: "PUT",
      body: { chains: state.chains },
    });
    state.chains = data.chains.map((c) => ({ name: c.name, providers: [...c.providers] }));
    renderChains();
    notify("Fallback chains saved");
  } catch (err) {
    errEl.textContent = err.status === 503 ? "D1 not configured — cannot save chains." : err.message;
    errEl.classList.remove("hidden");
  }
});

/* ---------- Playground ---------- */
$("playground-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const model = $("pg-model").value.trim();
  const prompt = $("pg-prompt").value;
  const stream = $("pg-stream").checked;
  const pane = $("pg-response");
  const runBtn = $("pg-run");
  if (!model) return;
  runBtn.disabled = true;
  pane.textContent = "…";
  try {
    const res = await fetch("/admin/api/playground", {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
        stream,
      }),
    });
    if (res.status === 401) {
      showLogin();
      return;
    }
    if (!res.ok) {
      let message = `${res.status} ${res.statusText || "error"}`;
      try {
        const data = await res.json();
        if (data.error) message = data.error.message;
      } catch {
        /* non-JSON */
      }
      pane.textContent = `Error: ${message}`;
      return;
    }
    if (!stream || !res.body) {
      const text = await res.text();
      pane.textContent = prettyModelOutput(text);
      return;
    }
    // SSE streaming: read chunks, parse data: lines, show deltas live.
    pane.textContent = "";
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const events = buffer.split("\n\n");
      buffer = events.pop() || "";
      for (const event of events) {
        const line = event.split("\n").find((l) => l.startsWith("data: "));
        if (!line) continue;
        const payload = line.slice(6).trim();
        if (payload === "[DONE]") continue;
        try {
          const chunk = JSON.parse(payload);
          const delta =
            chunk.choices && chunk.choices[0] && chunk.choices[0].delta
              ? chunk.choices[0].delta.content || ""
              : "";
          pane.textContent += delta;
          pane.scrollTop = pane.scrollHeight;
        } catch {
          /* keep partials out */
        }
      }
    }
  } catch (err) {
    pane.textContent = `Error: ${err.message || err}`;
  } finally {
    runBtn.disabled = false;
  }
});

function prettyModelOutput(text) {
  try {
    const data = JSON.parse(text);
    const content =
      data.choices && data.choices[0] && data.choices[0].message
        ? data.choices[0].message.content
        : null;
    return content != null ? content : JSON.stringify(data, null, 2);
  } catch {
    return text;
  }
}

/* ---------- boot ---------- */
boot();
