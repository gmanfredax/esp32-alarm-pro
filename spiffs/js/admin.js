// /spiffs/js/admin.js — Admin UI (Utenti, Rete, MQTT)
(() => {
  const $  = (s, r=document) => r.querySelector(s);
  const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));

  // ========== FETCH shim: Authorization Bearer + cookie same-origin + redirect 401/403
  (function installAuthFetchShim(){
    const _fetch = window.fetch;
    window.fetch = (input, init = {}) => {
      const { __skipAuthRedirect, ...rest } = init || {};
      const headers = new Headers(rest.headers || {});
      const t = (()=>{
        try {
          return (
            localStorage.getItem("alarmpro.token") ||
            sessionStorage.getItem("alarmpro.token") ||
            localStorage.getItem("token") ||
            sessionStorage.getItem("token") ||
            ""
          );
        } catch {
          return "";
        }
      })();
      if (t && !headers.has("Authorization")) headers.set("Authorization", "Bearer " + t);
      const creds = rest.credentials ? rest.credentials : "same-origin";
      return _fetch(input, { ...rest, headers, credentials: creds }).then(resp => {
        if (!__skipAuthRedirect){
          if (resp.status === 401) { location.replace("/login.html"); }
          else if (resp.status === 403) { location.replace("/403.html"); }
        }
        return resp;
      });
    };
  })();

  // ========== Helpers UI / auth ==========
  function toast(msg, ok=true){
    let el = $("#toast");
    if (!el){
      el = document.createElement("div");
      el.id = "toast";
      el.className = "toast";
      Object.assign(el.style, {position:"fixed",bottom:"18px",left:"18px",padding:".6rem .8rem",borderRadius:"10px",background:"rgba(20,28,44,.95)",border:"1px solid var(--border)",color:"var(--text)",zIndex:2000,boxShadow:"0 6px 24px rgba(0,0,0,.35)",maxWidth:"80%"});
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.style.borderColor = ok ? "rgba(16,185,129,.45)" : "rgba(239,68,68,.55)";
    el.style.background = ok ? "rgba(10,20,24,.95)" : "rgba(32,12,12,.95)";
    clearTimeout(el._t); el._t = setTimeout(()=>{ el.remove(); }, 2400);
  }
  const needLogin = () => location.replace("/login.html");

  let currentUser = "";
  let isAdmin = false;

  async function apiGet(url){
    const r = await fetch(url, { headers: { "Accept":"application/json" } });
    if (r.status === 401) { needLogin(); throw new Error("401"); }
    if (!r.ok) throw new Error(await r.text());
    try {
      return await r.json();
    } catch (err) {
      throw new Error("Risposta JSON non valida");
    }
  }
  async function apiPost(url, body, opts = {}){
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body!=null ? JSON.stringify(body) : undefined,
      __skipAuthRedirect: opts.skipAuthRedirect === true
    });
    if (r.status === 401) { needLogin(); throw new Error("401"); }
    if (!r.ok) {
      let detail = "";
      try {
        const ct = r.headers.get("content-type") || "";
        if (ct.includes("application/json")){
          const data = await r.json();
          detail = data?.message || data?.error || JSON.stringify(data);
        } else {
          detail = await r.text();
        }
      } catch (err) {
        detail = err?.message || `${r.status} ${r.statusText}`;
      }
      throw new Error(detail || `${r.status} ${r.statusText}`);
    }
    try { return await r.json(); } catch { return {}; }
  }

  async function apiDelete(url){
    const r = await fetch(url, { method:"DELETE", headers:{ "Accept":"application/json" } });
    if (r.status === 401) { needLogin(); throw new Error("401"); }
    if (!r.ok){
      let detail = "";
      try {
        const ct = r.headers.get("content-type") || "";
        if (ct.includes("application/json")){
          const data = await r.json();
          detail = data?.error || data?.message || JSON.stringify(data);
        } else {
          detail = await r.text();
        }
      } catch(err){
        detail = err?.message || await r.text();
      }
      throw new Error(detail || `${r.status} ${r.statusText}`);
    }
    try { return await r.json(); } catch { return {}; }
  }

  const escapeHtml = (value = "") => (value ?? "").toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

  const fileToBase64 = (file) => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("lettura"));
    reader.onload = () => {
      try {
        const bytes = new Uint8Array(reader.result);
        let binary = "";
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        resolve(btoa(binary));
      } catch (e) {
        reject(e);
      }
    };
    reader.readAsArrayBuffer(file);
  });

  const WEB_TLS_MAX_PEM_LEN = 4096;
  const ROLE_ADMIN = 2;

  const expansionsState = {
    items: [],
    loading: false,
    error: "",
    lastScan: null,
  };
  const CAN_MAX_NODE_ID = 127;
  const CAN_NODE_LABEL_MAX = 31;

  const canTestBroadcastState = {
    sending: false,
    pendingState: null,
    lastState: null,
    lastError: "",
    lastRequestAt: 0,
  };

  const ADS_DIAG_REFRESH_THRESHOLD_MS = 15000;
  const adsDiagState = {
    enabled: true,
    loading: false,
    error: "",
    expected: 0,
    detected: 0,
    devices: [],
    timestampMs: null,
  };
  let adsDiagFetchedOnce = false;

  const analogEolState = {
    payload: null,
    loading: false,
    saving: false,
    error: "",
    lastFetched: 0,
  };

  const TELEMETRY_REFRESH_MS = 1500;
  let telemetryTimer = null;
  let telemetryNodeId = null;
  let telemetryFetchPending = false;
  const modalCleanupHandlers = new Set();

  function formatDateTime(ts){
    if (ts == null) return "";
    let date;
    if (ts instanceof Date) date = ts;
    else if (typeof ts === "number") date = new Date(ts);
    else if (typeof ts === "string" && ts) date = new Date(ts);
    else return "";
    if (Number.isNaN(date.getTime())) return "";
    try { return date.toLocaleString("it-IT"); }
    catch { return date.toISOString(); }
  }

  function formatInteger(value){
    const num = Number(value);
    if (!Number.isFinite(num)) return "—";
    try {
      return num.toLocaleString("it-IT");
    } catch {
      return String(num);
    }
  }

  const formatAnalogValue = (value) => {
    const num = Number(value);
    if (!Number.isFinite(num)) return '';
    return num.toFixed(2);
  };

  const normalizeRole = (roleValue) => {
    if (typeof roleValue === 'number') return Number.isNaN(roleValue) ? null : roleValue;
    if (typeof roleValue === 'string' && roleValue.trim() !== '') {
      const parsed = Number.parseInt(roleValue, 10);
      return Number.isNaN(parsed) ? null : parsed;
    }
    return null;
  };

    // -------------- Header / menu utente --------------
  function syncHeader(){
    const label = $("#userLabel");
    if (!label) return;
    if (!currentUser) {
      label.textContent = "";
      return;
    }
    const nameHtml = `<span class="user-name">${escapeHtml(currentUser)}</span>`;
    const roleHtml = isAdmin ? ' <span class="user-role tag warn">ADMIN</span>' : '';
    label.innerHTML = `${nameHtml}${roleHtml}`;
  }
  
  function updateAdminVisibility(){
    document.body.classList.toggle('is-admin', isAdmin);
    $$('.admin-only').forEach(el => {
      el.classList.toggle('hidden', !isAdmin);
      el.style.removeProperty('display');
    });
    const zBtn = $('#btnZonesCfg');
    if (zBtn) {
      zBtn.classList.toggle('hidden', !isAdmin);
      zBtn.style.removeProperty('display');
    }
  }

  function mountUserMenu(){
    const btn = $("#userBtn"), dd = $("#userDropdown");
    if (!btn || !dd) return;
    btn.onclick = (e)=>{ e.stopPropagation(); dd.classList.toggle("hidden"); };
    document.addEventListener("click", ()=>dd.classList.add("hidden"));
    dd.querySelector("[data-act=logout]")?.addEventListener("click", async ()=>{
      dd.classList.add("hidden");
      try{ await apiPost("/api/logout",{});}catch{}
      try {
        localStorage.removeItem("alarmpro.token");
        localStorage.removeItem("token");
      } catch(_){}
      try {
        sessionStorage.removeItem("alarmpro.token");
        sessionStorage.removeItem("token");
      } catch(_){}
      needLogin();
    });
  }

  // ========== Gate client-side (semplificato)
  // Il server decide già se servire admin.html o 403.html.
  // Qui sblocchiamo solo la UI e lasciamo al fetch-shim il redirect quando il token scade.
  async function ensureAdminOr403(){
    document.getElementById("appRoot")?.classList.remove("hidden");
    return true;
  }
  async function ensureAdmin(){ return ensureAdminOr403(); }

  // ========== Sidebar / Views
  function setupSidebar(){
    $$(".side button").forEach(btn => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-view");
        const targetView = id ? document.getElementById(id) : null;
        const views = $$(".view");
        $$(".side button").forEach(b => b.classList.toggle("active", b===btn));
        if (targetView){
          views.forEach(view => view.classList.toggle("active", view === targetView));
        }
        if (!targetView){
          const current = views.find(view => view.classList.contains("active"));
          if (current) current.classList.add("active");
        }
        if (id !== "view-mqtt") maskMqttPassword();
        if (id === "view-diagnostics") maybeAutoRefreshAdsDiag();
        if (id === "view-general") { loadAnalogEolConfig(); loadDigitalFilters().catch(()=>{}); }
      });
    });
  }

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) maskMqttPassword();
  });

  function getExpansionItems(){
    const items = Array.isArray(expansionsState.items) ? expansionsState.items : [];
    return items.slice().sort((a, b) => {
      const aId = Number(a?.node_id ?? 0);
      const bId = Number(b?.node_id ?? 0);
      return aId - bId;
    });
  }

    function upsertExpansionNode(updated){
    if (!updated || typeof updated !== "object") return;
    const nodeId = Number(updated?.node_id ?? updated?.nodeId);
    if (!Number.isFinite(nodeId) || nodeId <= 0) return;
    const current = Array.isArray(expansionsState.items) ? expansionsState.items.slice() : [];
    let replaced = false;
    for (let idx = 0; idx < current.length; ++idx){
      const itemId = Number(current[idx]?.node_id);
      if (itemId === nodeId){
        current[idx] = { ...current[idx], ...updated };
        replaced = true;
        break;
      }
    }
    if (!replaced){
      current.push(updated);
    }
    expansionsState.items = current;
    expansionsState.lastScan = Date.now();
    expansionsState.error = "";
    renderExpansionsSection();
  }

  function nodeTitle(node){
    if (!node) return "Nodo CAN";
    const label = (node.label && String(node.label).trim()) || "";
    if (label) return label;
    const kind = (node.kind && String(node.kind).trim()) || "";
    if (kind) return `${kind}${node.node_id != null ? ` #${node.node_id}` : ""}`;
    if (node.node_id != null) return `Nodo ${node.node_id}`;
    return "Nodo CAN";
  }

  function formatNodeStateLabel(node){
    const raw = (node?.state || "").toString().toUpperCase();
    switch (raw) {
      case "ONLINE": return "Online";
      case "OFFLINE": return "Offline";
      case "PREOP":
      case "PRE-OP": return "Pre-operativa";
      case "UNKNOWN":
      case "": return "Sconosciuto";
      default: return raw;
    }
  }

  function formatUid(value){
    if (value == null) return "—";
    const cleaned = String(value).replace(/[^0-9a-fA-F]/g, "").toUpperCase();
    if (!cleaned) return "—";
    return cleaned.replace(/(.{2})/g, "$1 ").trim();
  }

  const WALL_TIME_MIN_MS = Date.UTC(2000, 0, 1);

  function coerceTimestampMs(value){
    if (value == null) return null;
    let raw = null;
    if (typeof value === "number") {
      raw = value;
    } else if (typeof value === "string") {
      const trimmed = value.trim();
      if (!trimmed) return null;
      const parsed = Number(trimmed);
      raw = Number.isFinite(parsed) ? parsed : null;
    } else {
      raw = Number(value);
    }
    if (!Number.isFinite(raw) || raw <= 0) return null;
    if (raw < WALL_TIME_MIN_MS) return null;
    return raw;
  }

  function formatNodeAssociation(node){
    if (!node) return "—";
    const nodeId = Number(node?.node_id ?? -1);
    const raw = coerceTimestampMs(nodeId === 0
      ? (node?.registered_at_ms ?? node?.registered_at)
      : (node?.associated_at_ms ?? node?.associated_at)
    );
    if (!Number.isFinite(raw)) return "—";
    return formatDateTime(raw);
  }

  function formatNodeLastSeen(node){
    const raw = Number(node?.last_seen_ms ?? node?.last_seen);
    if (!Number.isFinite(raw) || raw <= 0) return "—";
    return formatDateTime(raw);
  }

  function renderExpansionsSection(){
    const nodes = getExpansionItems();
    const list = $("#adminExpansionList");
    if (list){
      list.innerHTML = nodes.map((node) => {
        if (!node) return "";
        const nodeId = Number(node.node_id ?? -1);
        const title = escapeHtml(nodeTitle(node));
        const stateLabel = formatNodeStateLabel(node);
        const uidDisplay = formatUid(node?.uid);
        const association = formatNodeAssociation(node);
        const metaParts = [];
        if (nodeId >= 0) metaParts.push(`ID ${nodeId}`);
        if (stateLabel) metaParts.push(`Stato: ${stateLabel}`);
        if (node.kind) metaParts.push(String(node.kind));
        const ioParts = [];
        if (node.inputs_count != null) ioParts.push(`${node.inputs_count} ingressi`);
        if (node.outputs_count != null) ioParts.push(`${node.outputs_count} uscite`);
        if (ioParts.length) metaParts.push(ioParts.join(' · '));
        const assocLabel = nodeId === 0 ? "Registrata il" : "Associata il";
        if (association !== "—") metaParts.push(`${assocLabel}: ${association}`);
        const meta = metaParts.filter(Boolean).map((part)=>escapeHtml(String(part))).join(' · ');
        const telemetryBtn = nodeId === 0
          ? ''
          : `<button class="btn btn-sm" type="button" data-node-telemetry="${nodeId}">Telemetria</button>`;
        const actions = nodeId === 0
          ? '<span class="muted">Master</span>'
          : `${telemetryBtn}<button class="btn btn-sm outline" type="button" data-node-actions="${nodeId}">Azioni</button>`;
        return `<li class="expansion-item" data-node-id="${nodeId}">
            <div class="expansion-info">
              <div class="expansion-title">${title}</div>
              ${meta ? `<div class="expansion-meta">${meta}</div>` : ''}
              ${uidDisplay ? `<div class="expansion-meta">UID ${uidDisplay}</div>` : ''}
            </div>
            <div class="expansion-actions">${actions}</div>
          </li>`;
      }).join("");
    }
    const empty = $("#adminExpansionEmpty");
    if (empty){
      const showEmpty = !expansionsState.loading && !expansionsState.error && nodes.length === 0;
      empty.classList.toggle("hidden", !showEmpty);
    }
    const status = $("#adminExpansionStatus");
    if (status){
      status.classList.remove("error", "success", "muted", "hidden");
      let text = "";
      if (expansionsState.loading){
        text = "Caricamento nodi CAN…";
        status.classList.add("muted");
      } else if (expansionsState.error){
        text = expansionsState.error;
        status.classList.add("error");
      } else if (nodes.length){
        const when = formatDateTime(expansionsState.lastScan);
        text = when ? `Ultimo aggiornamento: ${when}` : "Elenco aggiornato.";
        status.classList.add("success");
      } else {
        text = "Nessuna scheda registrata.";
        status.classList.add("muted");
      }
      status.textContent = text;
      status.classList.toggle("hidden", !text);
    }
    const disableActions = !!expansionsState.loading;
    const scanBtn = $("#adminExpansionScanBtn");
    if (scanBtn) scanBtn.disabled = disableActions;
    const refreshBtn = $("#adminExpansionRefreshBtn");
    if (refreshBtn) refreshBtn.disabled = disableActions;
  }

  function setTelemetryValue(key, value, { warn = false } = {}){
    const el = document.querySelector(`[data-telemetry="${key}"]`);
    if (!el) return;
    const display = (value == null || value === '') ? '—' : value;
    el.textContent = display;
    el.classList.toggle('warn', !!warn);
  }

  function formatTelemetryTimestamp(ts){
    if (ts == null) return '—';
    const num = Number(ts);
    if (!Number.isFinite(num) || num <= 0) return '—';
    return formatDateTime(num);
  }

  function updateTelemetryUI(payload){
    if (!payload || typeof payload !== 'object') {
      return;
    }
    const node = payload.node || {};
    const bus = payload.bus || {};
    const exists = node.exists !== false;
    const online = !!node.online;
    setTelemetryValue('node_state', exists ? (online ? 'Online' : 'Offline') : 'Non registrato', { warn: exists && !online });
    setTelemetryValue('node_last_seen', formatTelemetryTimestamp(node.last_seen_ms));
    setTelemetryValue('node_last_online', formatTelemetryTimestamp(node.last_online_ms));
    setTelemetryValue('node_heartbeat', formatInteger(node.heartbeat_count));
    setTelemetryValue('node_info', formatInteger(node.info_count));
    setTelemetryValue('node_commands', formatInteger(node.command_count));
    setTelemetryValue('node_command_errors', formatInteger(node.command_errors), { warn: Number(node.command_errors) > 0 });
    setTelemetryValue('node_offline_events', formatInteger(node.offline_events), { warn: Number(node.offline_events) > 0 });

    const supported = !!bus.supported;
    setTelemetryValue('bus_supported', supported ? 'Disponibile' : 'Non disponibile', { warn: !supported });
    if (supported) {
      setTelemetryValue('bus_driver', bus.driver_started ? 'Attivo' : 'Spento', { warn: !bus.driver_started });
      setTelemetryValue('bus_last_activity', formatTelemetryTimestamp(bus.last_activity_ms));
      setTelemetryValue('bus_packets_sent', formatInteger(bus.packets_sent));
      setTelemetryValue('bus_packets_received', formatInteger(bus.packets_received));
      setTelemetryValue('bus_packets_lost', formatInteger(bus.packets_lost), { warn: Number(bus.packets_lost) > 0 });
      setTelemetryValue('bus_tx_errors', formatInteger(bus.tx_errors), { warn: Number(bus.tx_errors) > 0 });
      setTelemetryValue('bus_rx_errors', formatInteger(bus.rx_errors), { warn: Number(bus.rx_errors) > 0 });
      setTelemetryValue('bus_offline_events', formatInteger(bus.offline_events), { warn: Number(bus.offline_events) > 0 });
      setTelemetryValue('bus_nodes_online', formatInteger(bus.nodes_online));
      setTelemetryValue('bus_nodes_known', formatInteger(bus.nodes_known));
    } else {
      [
        'bus_driver',
        'bus_last_activity',
        'bus_packets_sent',
        'bus_packets_received',
        'bus_packets_lost',
        'bus_tx_errors',
        'bus_rx_errors',
        'bus_offline_events',
        'bus_nodes_online',
        'bus_nodes_known',
      ].forEach((key) => setTelemetryValue(key, '—', { warn: false }));
    }
  }

  async function fetchNodeTelemetry(nodeId){
    if (!telemetryNodeId || telemetryNodeId !== nodeId) {
      telemetryFetchPending = false;
      return;
    }
    if (telemetryFetchPending) return;
    telemetryFetchPending = true;
    const statusEl = $("#telemetryStatus");
    try {
      const payload = await apiGet(`/api/can/node/${nodeId}/telemetry`);
      if (!telemetryNodeId || telemetryNodeId !== nodeId) {
        return;
      }
      updateTelemetryUI(payload);
      if (statusEl && document.body.contains(statusEl)) {
        statusEl.textContent = `Aggiornato alle ${formatDateTime(Date.now())}`;
        statusEl.classList.remove("error");
      }
    } catch (err){
      const message = err?.message || "telemetria non disponibile";
      if (statusEl && document.body.contains(statusEl)) {
        statusEl.textContent = `Errore: ${message}`;
        statusEl.classList.add("error");
      }
      if (err?.status === 404 && telemetryNodeId === nodeId) {
        stopTelemetryWatcher();
      }
    } finally {
      if (telemetryNodeId === nodeId) {
        telemetryFetchPending = false;
      }
    }
  }

  function stopTelemetryWatcher(){
    if (telemetryTimer) {
      clearInterval(telemetryTimer);
      telemetryTimer = null;
    }
    telemetryNodeId = null;
    telemetryFetchPending = false;
  }

  function startTelemetryWatcher(nodeId){
    stopTelemetryWatcher();
    const normalized = Number(nodeId);
    if (!Number.isFinite(normalized) || normalized <= 0) {
      telemetryNodeId = null;
      return;
    }
    telemetryNodeId = normalized;
    const statusEl = $("#telemetryStatus");
    if (statusEl) {
      statusEl.textContent = "Caricamento telemetria…";
      statusEl.classList.remove("error");
    }
    fetchNodeTelemetry(telemetryNodeId);
    telemetryTimer = window.setInterval(() => {
      if (telemetryNodeId) {
        fetchNodeTelemetry(telemetryNodeId);
      }
    }, TELEMETRY_REFRESH_MS);
  }

  function openNodeTelemetry(nodeId){
    const nodes = getExpansionItems();
    const node = nodes.find((item) => Number(item?.node_id) === nodeId) || null;
    const title = escapeHtml(nodeTitle(node) || `Nodo ${nodeId}`);
    const metaParts = [];
    if (node?.kind) metaParts.push(escapeHtml(String(node.kind)));
    const inputsCount = Number(node?.inputs_count);
    const outputsCount = Number(node?.outputs_count);
    const ioParts = [];
    if (Number.isFinite(inputsCount)) ioParts.push(`${inputsCount} ingressi`);
    if (Number.isFinite(outputsCount)) ioParts.push(`${outputsCount} uscite`);
    if (ioParts.length) metaParts.push(ioParts.join(' · '));
    const metaLine = metaParts.length ? `<p class="muted small">${metaParts.join(' · ')}</p>` : '';
    modal(`
      <div class="card-head row" style="justify-content:space-between;align-items:center">
        <h3>Telemetria nodo CAN</h3>
        <button class="btn" id="telemetryCloseBtn" type="button">Chiudi</button>
      </div>
      <p class="muted">Monitoraggio in tempo reale per <strong>${title}</strong> (ID ${escapeHtml(String(nodeId))}).</p>
      ${metaLine}
      <div id="telemetryStatus" class="telemetry-status">Caricamento telemetria…</div>
      <div class="telemetry-grid">
        <section class="telemetry-card">
          <h4>Stato nodo</h4>
          <div class="telemetry-metric">
            <span>Stato</span>
            <strong data-telemetry="node_state">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Ultimo pacchetto</span>
            <strong data-telemetry="node_last_seen">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Ultimo online</span>
            <strong data-telemetry="node_last_online">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Heartbeat ricevuti</span>
            <strong data-telemetry="node_heartbeat">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Info ricevute</span>
            <strong data-telemetry="node_info">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Comandi inviati</span>
            <strong data-telemetry="node_commands">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Errori comando</span>
            <strong data-telemetry="node_command_errors">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Offline rilevati</span>
            <strong data-telemetry="node_offline_events">—</strong>
          </div>
        </section>
        <section class="telemetry-card">
          <h4>Bus CAN</h4>
          <div class="telemetry-metric">
            <span>Supporto</span>
            <strong data-telemetry="bus_supported">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Driver</span>
            <strong data-telemetry="bus_driver">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Ultima attività</span>
            <strong data-telemetry="bus_last_activity">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Pacchetti inviati</span>
            <strong data-telemetry="bus_packets_sent">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Pacchetti ricevuti</span>
            <strong data-telemetry="bus_packets_received">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Pacchetti perduti</span>
            <strong data-telemetry="bus_packets_lost">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Errori TX</span>
            <strong data-telemetry="bus_tx_errors">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Errori RX</span>
            <strong data-telemetry="bus_rx_errors">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Offline bus</span>
            <strong data-telemetry="bus_offline_events">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Nodi online</span>
            <strong data-telemetry="bus_nodes_online">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Nodi totali</span>
            <strong data-telemetry="bus_nodes_known">—</strong>
          </div>
        </section>
      </div>
    `);
    $("#telemetryCloseBtn")?.addEventListener("click", () => closeModal());
    registerModalCleanup(() => stopTelemetryWatcher());
    startTelemetryWatcher(nodeId);
  }

  function updateCanTestBroadcastUI(){
    const onBtn = $("#canTestBroadcastOnBtn");
    const offBtn = $("#canTestBroadcastOffBtn");
    const { sending, pendingState, lastState } = canTestBroadcastState;
    if (onBtn){
      const busy = sending && pendingState === true;
      onBtn.disabled = sending;
      onBtn.textContent = busy ? "Invio…" : "BUS ON";
      onBtn.classList.toggle("outline", lastState !== true);
      onBtn.setAttribute("aria-pressed", lastState === true ? "true" : "false");
    }
    if (offBtn){
      const busy = sending && pendingState === false;
      offBtn.disabled = sending;
      offBtn.textContent = busy ? "Invio…" : "BUS OFF";
      offBtn.classList.toggle("outline", lastState !== false);
      offBtn.setAttribute("aria-pressed", lastState === false ? "true" : "false");
    }
    const status = $("#canTestBroadcastStatus");
    if (status){
      status.classList.remove("error", "success");
      if (sending){
        status.textContent = `Invio comando CAN ${pendingState ? "ON" : "OFF"}…`;
        status.classList.remove("muted");
      } else if (canTestBroadcastState.lastError){
        status.textContent = canTestBroadcastState.lastError;
        status.classList.remove("muted");
        status.classList.add("error");
      } else if (lastState === true || lastState === false){
        status.textContent = `Ultimo broadcast: ${lastState ? "ON" : "OFF"}.`;
        status.classList.remove("muted");
        status.classList.add("success");
      } else {
        status.textContent = "Premi per inviare \"ON\" o \"OFF\" sul bus CAN.";
        status.classList.add("muted");
      }
    }
  }

  function formatVoltage(value){
    const num = Number(value);
    if (!Number.isFinite(num)) return "—";
    return `${num.toFixed(3)} V`;
  }

  function formatAddressHex(hexValue, addressValue){
    if (typeof hexValue === "string" && hexValue.trim()) {
      return hexValue.trim();
    }
    const addrNum = Number(addressValue);
    if (!Number.isFinite(addrNum)) {
      return "0x??";
    }
    return `0x${addrNum.toString(16).padStart(2, "0").toUpperCase()}`;
  }

  function buildAdsDiagCard(device, fallbackIndex){
    const card = document.createElement("div");
    card.className = "diag-card";

    const online = device?.online === true;
    const addressHex = formatAddressHex(device?.address_hex, device?.address);
    const slot = Number(device?.slot);
    const displayIndex = Number.isFinite(slot) ? slot + 1 : fallbackIndex + 1;

    const header = document.createElement("div");
    header.className = "diag-card-head";

    const title = document.createElement("h4");
    title.textContent = `Modulo ${displayIndex} — ${addressHex}`;
    header.appendChild(title);

    const badge = document.createElement("span");
    const hasError = !!device?.error_code;
    badge.className = `tag ${online ? (hasError ? "warn" : "ok") : "err"}`;
    badge.textContent = online ? (hasError ? "Online (attenzione)" : "Online") : "Offline";
    header.appendChild(badge);

    card.appendChild(header);

    const meta = document.createElement("div");
    meta.className = "diag-meta";
    const addressDec = Number(device?.address);
    const labelAddress = Number.isFinite(addressDec) ? ` (${addressDec})` : "";
    meta.innerHTML = `Indirizzo I²C: <code>${escapeHtml(addressHex)}</code>${labelAddress}`;
    card.appendChild(meta);

    const config = device?.config || {};
    const modeLabel = config.mode_label || "—";
    const gainLabel = config.gain_label || "—";
    const rateLabel = config.data_rate_label || (Number.isFinite(Number(config.data_rate_sps)) ? `${config.data_rate_sps} SPS` : "—");
    const compLabel = config.comp_queue_label || (config.comparator_enabled ? "Comparator attivo" : "Comparator disabilitato");

    const metaList = document.createElement("ul");
    metaList.className = "diag-meta-list";
    metaList.innerHTML = `
      <li><span>Modo:</span> <strong>${escapeHtml(modeLabel)}</strong></li>
      <li><span>Gain:</span> <strong>${escapeHtml(gainLabel)}</strong></li>
      <li><span>Frequenza:</span> <strong>${escapeHtml(rateLabel)}</strong></li>
      <li><span>Comparator:</span> <strong>${escapeHtml(compLabel)}</strong></li>
    `;
    card.appendChild(metaList);

    const statusMsg = document.createElement("p");
    statusMsg.className = "diag-message";
    const statusText = device?.status ? String(device.status) : (online ? "Dispositivo online." : "Modulo non rilevato sul bus I²C.");
    statusMsg.textContent = statusText;
    if (!online) {
      statusMsg.classList.add("warn");
    } else if (device?.error_code) {
      statusMsg.classList.add("error");
    } else {
      statusMsg.classList.add("ok");
    }
    card.appendChild(statusMsg);

    const channels = Array.isArray(device?.channels) ? device.channels : [];
    if (channels.length) {
      const table = document.createElement("table");
      table.className = "diag-channels";
      table.innerHTML = "<thead><tr><th>Canale</th><th>Raw</th><th>Tensione</th></tr></thead>";
      const tbody = document.createElement("tbody");
      channels.forEach((ch) => {
        const tr = document.createElement("tr");
        const indexCell = document.createElement("td");
        const idxValue = Number(ch?.index);
        indexCell.textContent = Number.isFinite(idxValue) ? `AIN${idxValue}` : "—";
        const rawCell = document.createElement("td");
        const rawValue = Number(ch?.raw);
        rawCell.textContent = Number.isFinite(rawValue) ? String(rawValue) : "—";
        const voltCell = document.createElement("td");
        const voltValue = Number(ch?.voltage);
        voltCell.textContent = Number.isFinite(voltValue) ? formatVoltage(voltValue) : "—";
        tr.append(indexCell, rawCell, voltCell);
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      card.appendChild(table);
    }

    return card;
  }

  function adsBadge(value, okText = 'Sì', noText = 'No'){
    return `<span class="ads-chip ${value ? 'ok' : 'err'}">${value ? okText : noText}</span>`;
  }

  async function adsAction(path, payload){
    await apiPost(path, payload || {});
    await loadAdsDiagnostics();
  }

  function renderAdsDiagnostics(){
    const summary = $("#adsDiagSummary");
    const refreshBtn = $("#adsDiagRefreshBtn");
    const scanBtn = $("#adsDiagScanBtn");
    const addBtn = $("#adsDiagAddBtn");
    const tbody = $("#adsDiagDevices");
    const emptyMsg = $("#adsDiagEmpty");
    const timestampEl = $("#adsDiagTimestamp");
    const unconfiguredEl = $("#adsDiagUnconfigured");

    [refreshBtn, scanBtn, addBtn].forEach(btn => { if (btn) btn.disabled = !!adsDiagState.loading; });

    const configured = Number(adsDiagState.expected || 0);
    const detected = Number(adsDiagState.detected || 0);
    const offline = Number(adsDiagState.offline || 0);
    if (summary) {
      summary.classList.remove("error", "success", "muted", "warn");
      if (adsDiagState.loading) {
        summary.textContent = "Caricamento ADS1115…"; summary.classList.add("muted");
      } else if (adsDiagState.error) {
        summary.textContent = `Errore: ${adsDiagState.error}`; summary.classList.add("error");
      } else if (!configured) {
        summary.textContent = "Nessun modulo ADS1115 configurato. Lo scan può mostrare moduli rilevati ma non configurati."; summary.classList.add("muted");
      } else if (offline > 0) {
        summary.textContent = `Configurati ${configured}, rilevati ${detected}, offline ${offline}.`; summary.classList.add("warn");
      } else {
        summary.textContent = `Configurati ${configured}, rilevati ${detected}. Tutti i moduli abilitati sono online.`; summary.classList.add("success");
      }
    }

    if (tbody && !adsDiagState.loading) {
      tbody.innerHTML = "";
      const modules = Array.isArray(adsDiagState.devices) ? adsDiagState.devices : [];
      modules.forEach((mod) => {
        const zones = Array.isArray(mod.zones) ? mod.zones.map(z => `Z${z}`).join(', ') : '—';
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><code>${escapeHtml(mod.id || '')}</code></td>
          <td>${escapeHtml(mod.label || '')}<br><small class="muted">${escapeHtml(mod.role || '')}</small></td>
          <td><code>${escapeHtml(mod.address_hex || '')}</code></td>
          <td>${adsBadge(!!mod.enabled)}</td>
          <td>${adsBadge(!!mod.detected)}</td>
          <td>${adsBadge(!!mod.online, 'Online', 'Offline')}</td>
          <td>${escapeHtml(mod.last_error || '—')}<br><small class="muted">fail: ${Number(mod.consecutive_failures || 0)}</small></td>
          <td>${mod.last_seen ? formatDateTime(Number(mod.last_seen)) : '—'}</td>
          <td>${escapeHtml(zones)}</td>
          <td><div class="ads-actions">
            <button class="btn outline" data-ads-act="edit" data-id="${escapeHtml(mod.id)}">Modifica</button>
            <button class="btn outline" data-ads-act="replace" data-id="${escapeHtml(mod.id)}">Sostituisci</button>
            <button class="btn outline" data-ads-act="test" data-id="${escapeHtml(mod.id)}">Test lettura</button>
            <button class="btn outline" data-ads-act="reset" data-id="${escapeHtml(mod.id)}">Reset errori</button>
            <button class="btn ${mod.enabled ? 'danger' : ''}" data-ads-act="${mod.enabled ? 'disable' : 'enable'}" data-id="${escapeHtml(mod.id)}">${mod.enabled ? 'Disabilita' : 'Riabilita'}</button>
            <button class="btn danger" data-ads-act="delete" data-id="${escapeHtml(mod.id)}">Elimina</button>
          </div></td>`;
        tbody.appendChild(tr);
      });
    }

    if (emptyMsg) emptyMsg.classList.toggle('hidden', adsDiagState.loading || (adsDiagState.devices || []).length > 0);
    if (timestampEl) {
      if (!adsDiagState.loading && adsDiagState.timestampMs) { timestampEl.textContent = `Ultimo scan/aggiornamento: ${formatDateTime(adsDiagState.timestampMs)}.`; timestampEl.classList.remove('hidden'); }
      else { timestampEl.classList.add('hidden'); }
    }
    if (unconfiguredEl) {
      const list = Array.isArray(adsDiagState.unconfigured) ? adsDiagState.unconfigured : [];
      unconfiguredEl.textContent = list.length ? `Rilevati ma non configurati: ${list.join(', ')}.` : '';
      unconfiguredEl.classList.toggle('hidden', !list.length);
    }
  }

  async function loadAdsDiagnostics(){
    if (adsDiagState.loading) return;
    adsDiagState.loading = true;
    adsDiagState.error = "";
    renderAdsDiagnostics();
    try {
      const data = await apiGet("/api/admin/ads1115");
      adsDiagState.enabled = true;
      adsDiagState.expected = Number.isFinite(Number(data?.configured)) ? Number(data.configured) : 0;
      adsDiagState.detected = Number.isFinite(Number(data?.detected)) ? Number(data.detected) : 0;
      adsDiagState.offline = Number.isFinite(Number(data?.offline)) ? Number(data.offline) : 0;
      adsDiagState.timestampMs = Number.isFinite(Number(data?.last_scan)) && Number(data.last_scan) > 0 ? Number(data.last_scan) : Date.now();
      adsDiagState.devices = Array.isArray(data?.modules) ? data.modules : [];
      adsDiagState.unconfigured = Array.isArray(data?.detected_unconfigured) ? data.detected_unconfigured : [];
      adsDiagFetchedOnce = true;
    } catch (err){
      adsDiagState.error = err?.message || "Impossibile caricare ADS1115.";
      if (!adsDiagFetchedOnce) adsDiagState.devices = [];
    } finally {
      adsDiagState.loading = false;
      renderAdsDiagnostics();
    }
  }

  function setupAdsDiagnostics(){
    const refreshBtn = $("#adsDiagRefreshBtn");
    const scanBtn = $("#adsDiagScanBtn");
    const addBtn = $("#adsDiagAddBtn");
    if (refreshBtn && !refreshBtn._adsBound){ refreshBtn.addEventListener("click", (ev)=>{ ev.preventDefault(); loadAdsDiagnostics(); }); refreshBtn._adsBound = true; }
    if (scanBtn && !scanBtn._adsBound){ scanBtn.addEventListener("click", async (ev)=>{ ev.preventDefault(); try { await apiPost('/api/admin/ads1115/scan', {}); await loadAdsDiagnostics(); } catch(err){ adsDiagState.error = err?.message || 'Scan fallito'; renderAdsDiagnostics(); } }); scanBtn._adsBound = true; }
    if (addBtn && !addBtn._adsBound){ addBtn.addEventListener("click", async (ev)=>{ ev.preventDefault(); const address = prompt('Indirizzo I²C (0x48, 0x49, 0x4A, 0x4B)', '0x48'); if (!address) return; const label = prompt('Label modulo', 'ADS1115 Zone 1-4') || ''; try { await apiPost('/api/admin/ads1115', { address, label, enabled: true }); await loadAdsDiagnostics(); } catch(err){ alert(err?.message || 'Aggiunta fallita'); } }); addBtn._adsBound = true; }
    if (!setupAdsDiagnostics._delegated){
      document.addEventListener('click', async (ev) => {
        const btn = ev.target?.closest?.('[data-ads-act]');
        if (!btn) return;
        ev.preventDefault();
        const id = btn.dataset.id;
        const act = btn.dataset.adsAct;
        try {
          if (act === 'disable' || act === 'enable') await adsAction(`/api/admin/ads1115/${encodeURIComponent(id)}/${act}`);
          else if (act === 'reset') await adsAction(`/api/admin/ads1115/${encodeURIComponent(id)}/reset-errors`);
          else if (act === 'test') { const r = await apiPost(`/api/admin/ads1115/${encodeURIComponent(id)}/test-read`, {}); alert(`Raw: ${(r.raw || []).join(', ')}`); }
          else if (act === 'replace' || act === 'edit') { const address = prompt('Nuovo indirizzo I²C', '0x48'); if (!address) return; const label = prompt('Nuova label (opzionale)', '') || ''; await adsAction(`/api/admin/ads1115/${encodeURIComponent(id)}/replace`, { new_address: address, label }); }
          else if (act === 'delete') { const force = confirm('Forzare eliminazione se ci sono zone associate? OK=force, Annulla=senza force'); await apiDelete(`/api/admin/ads1115/${encodeURIComponent(id)}${force ? '?force=true' : ''}`); await loadAdsDiagnostics(); }
        } catch(err){ alert(err?.message || 'Operazione ADS1115 fallita'); }
      });
      setupAdsDiagnostics._delegated = true;
    }
    return loadAdsDiagnostics();
  }

  function maybeAutoRefreshAdsDiag(){
    if (adsDiagState.loading) return;
    const last = Number(adsDiagState.timestampMs) || 0;
    const stale = !adsDiagFetchedOnce || (Date.now() - last) > ADS_DIAG_REFRESH_THRESHOLD_MS;
    if (adsDiagState.error || stale) loadAdsDiagnostics();
  }

  function setAnalogStatus(text, variant){
    const statusEl = $("#analogEolStatus");
    if (!statusEl) return;
    statusEl.textContent = text || '';
    statusEl.classList.remove('hidden', 'error', 'success', 'warn');
    if (!text) {
      statusEl.classList.add('hidden');
      return;
    }
    if (variant === 'error') {
      statusEl.classList.add('error');
      statusEl.classList.remove('muted');
    } else if (variant === 'success') {
      statusEl.classList.add('success');
      statusEl.classList.remove('muted');
    } else if (variant === 'warn') {
      statusEl.classList.add('warn');
      statusEl.classList.remove('muted');
    } else {
      statusEl.classList.remove('error', 'success', 'warn');
      statusEl.classList.add('muted');
    }
  }

  function updateAnalogConfigMode(){
    const modeSelect = $("#analogConfigMode");
    const mode = Number.parseInt(modeSelect?.value ?? '', 10);
    const disableTamper = mode === 1;
    const tamperInputs = [
      $("#analogConfigTamperLow"),
      $("#analogConfigTamperHigh"),
    ];
    tamperInputs.forEach((input) => {
      if (!(input instanceof HTMLInputElement)) return;
      input.disabled = disableTamper;
      if (disableTamper) {
        input.classList.remove('input-error');
      }
    });
  }

  function renderAnalogEolSection(){
    const tableWrap = document.querySelector('.analog-table-wrap');
    const tbody = $("#analogEolTableBody");
    const emptyEl = $("#analogEolEmpty");
    const saveBtn = $("#analogEolSaveBtn");
    const reloadBtn = $("#analogEolReloadBtn");
    const configWrap = $("#analogEolConfigContainer");
    const supplyInfo = $("#analogSupplyInfo");
    const modeSelect = $("#analogConfigMode");
    const normalMinInput = $("#analogConfigNormalMin");
    const normalMaxInput = $("#analogConfigNormalMax");
    const alarmMinInput = $("#analogConfigAlarmMin");
    const alarmMaxInput = $("#analogConfigAlarmMax");
    const tamperLowInput = $("#analogConfigTamperLow");
    const tamperHighInput = $("#analogConfigTamperHigh");

    if (reloadBtn) reloadBtn.disabled = analogEolState.loading;
    if (saveBtn) saveBtn.disabled = analogEolState.loading || analogEolState.saving;

    if (analogEolState.loading) {
      setAnalogStatus('Caricamento…');
    } else if (analogEolState.error) {
      setAnalogStatus(`Errore: ${analogEolState.error}`, 'error');
    } else if (analogEolState.payload && analogEolState.payload.enabled) {
      const expected = Number.isFinite(Number(analogEolState.payload.expected_devices))
        ? Number(analogEolState.payload.expected_devices) : 0;
      const detected = Number.isFinite(Number(analogEolState.payload.detected_devices))
        ? Number(analogEolState.payload.detected_devices) : 0;
      const analogCount = Number.isFinite(Number(analogEolState.payload.analog_count))
        ? Number(analogEolState.payload.analog_count) : 0;
      const variant = expected > 0 && detected < expected
        ? 'warn'
        : (analogCount > 0 ? 'success' : null);
      const message = `Zone analogiche: ${analogCount}. ADS1115 rilevati ${detected}/${expected}.`;
      setAnalogStatus(message, variant);
    } else if (analogEolState.payload && analogEolState.payload.enabled === false) {
      const msg = analogEolState.payload.message || 'Nessun modulo ADS1115 configurato';
      const analogMsg = analogEolState.payload.analog_message || 'Nessuna zona analogica attiva';
      setAnalogStatus(`${msg}. ${analogMsg}. ADS1115 rilevati 0/0.`, null);
    } else {
      setAnalogStatus('', null);
    }

    const config = analogEolState.payload?.config;
    const zones = Array.isArray(analogEolState.payload?.zones) ? analogEolState.payload.zones : [];
    const enabled = !analogEolState.error && !analogEolState.loading && analogEolState.payload?.enabled;

    if (configWrap) {
      configWrap.classList.toggle('hidden', !(enabled && config));
    }

    if (enabled && config) {
      const modeValue = Number.isFinite(Number(config.mode)) ? Number(config.mode) : 2;
      if (modeSelect) modeSelect.value = String(modeValue);
      const assignValue = (input, value) => {
        if (!(input instanceof HTMLInputElement)) return;
        input.value = Number.isFinite(Number(value)) ? formatAnalogValue(value) : '';
        input.classList.remove('input-error');
      };
      assignValue(normalMinInput, config.normal_min);
      assignValue(normalMaxInput, config.normal_max);
      assignValue(alarmMinInput, config.alarm_min);
      assignValue(alarmMaxInput, config.alarm_max);
      assignValue(tamperLowInput, config.tamper_low);
      assignValue(tamperHighInput, config.tamper_high);
      updateAnalogConfigMode();
    }

    if (supplyInfo) {
      const supply = analogEolState.payload?.supply;
      if (enabled && supply?.available) {
        supplyInfo.classList.remove('hidden');
        if (supply.device_present === false) {
          supplyInfo.textContent = 'Monitor alimentazione: modulo non rilevato.';
        } else if (supply.sample_valid === false) {
          const errText = typeof supply.last_error === 'string' ? ` (${supply.last_error})` : '';
          supplyInfo.textContent = `Monitor alimentazione: lettura non disponibile${errText}.`;
        } else if (supply.sample_valid) {
          const supplyVolt = formatAnalogValue(supply.supply_voltage);
          const adcVolt = formatAnalogValue(supply.adc_voltage);
          supplyInfo.textContent = `Alimentazione 12V: ${supplyVolt} V (ADC ${adcVolt} V).`;
        } else {
          supplyInfo.textContent = '';
        }
      } else {
        supplyInfo.classList.add('hidden');
        supplyInfo.textContent = '';
      }
    }

    const showTable = enabled && zones.length > 0;
    if (tableWrap) tableWrap.classList.toggle('hidden', !showTable);
    if (emptyEl) {
      emptyEl.textContent = analogEolState.payload?.analog_message || analogEolState.payload?.message || 'Nessuna zona analogica attiva.';
      emptyEl.classList.toggle('hidden', showTable || analogEolState.error || analogEolState.loading);
    }

    if (!showTable) {
      if (tbody) tbody.innerHTML = '';
      return;
    }

    const rowsHtml = zones.map((zone) => {
      const index = Number(zone?.index ?? -1);
      if (!Number.isFinite(index) || index < 0) {
        return '';
      }
      const zoneId = Number(zone?.zone_id ?? index + 1);
      const userName = typeof zone?.name === 'string' && zone.name.trim() ? zone.name.trim() : '';
      const title = userName ? `Z${zoneId} • ${userName}` : `Z${zoneId}`;
      const deviceSlot = Number(zone?.device_slot ?? 0) + 1;
      const channel = Number(zone?.channel ?? 0);

      const infoEntries = [];
      infoEntries.push({ text: `Dispositivo ${deviceSlot} • Canale ${channel}`, cls: '' });
      if (zone?.address_hex) infoEntries.push({ text: `Indirizzo ${zone.address_hex}`, cls: '' });

      const statusEntries = [];
      if (zone?.device_present === false) {
        statusEntries.push({ text: 'Modulo non rilevato', cls: 'warn' });
      } else if (zone?.sample_valid === false) {
        statusEntries.push({ text: 'Campione non disponibile', cls: 'warn' });
      } else if (zone?.sample_valid && zone?.voltage != null) {
        statusEntries.push({ text: `Ultima lettura ${formatAnalogValue(zone.voltage)} V`, cls: '' });
      }
      if (zone?.alarm_active) statusEntries.push({ text: 'Allarme attivo', cls: 'warn' });
      if (zone?.tamper_active) statusEntries.push({ text: 'Tamper attivo', cls: 'error' });
      if (zone?.last_error) statusEntries.push({ text: `Errore: ${zone.last_error}`, cls: 'warn' });

      const infoHtml = infoEntries.map((entry) => `<div class="analog-zone-meta${entry.cls ? ` ${entry.cls}` : ''}">${escapeHtml(entry.text)}</div>`).join('');
      const statusHtml = statusEntries.length
        ? statusEntries.map((entry) => `<div class="analog-zone-meta${entry.cls ? ` ${entry.cls}` : ''}">${escapeHtml(entry.text)}</div>`).join('')
        : '<div class="analog-zone-meta muted">In attesa di dati…</div>';

      return `
        <tr>
          <td>
            <div class="analog-zone-title">${escapeHtml(title)}</div>
            ${infoHtml}
          </td>
          <td>
            ${statusHtml}
          </td>
        </tr>`;
    }).join('');

    if (tbody) {
      tbody.innerHTML = rowsHtml;
    }
  }

  async function loadAnalogEolConfig(force = false){
    if (analogEolState.loading) return analogEolState.payload;
    const now = Date.now();
    if (!force && analogEolState.payload && (now - analogEolState.lastFetched) < 5000) {
      renderAnalogEolSection();
      return analogEolState.payload;
    }
    analogEolState.loading = true;
    analogEolState.error = "";
    renderAnalogEolSection();
    try {
      const data = await apiGet('/api/admin/inputs/analog-eol');
      analogEolState.payload = data;
      analogEolState.lastFetched = Date.now();
      analogEolState.error = "";
    } catch (err) {
      analogEolState.payload = null;
      analogEolState.error = err?.message || 'Impossibile caricare la configurazione analogica.';
    }
    analogEolState.loading = false;
    renderAnalogEolSection();
    return analogEolState.payload;
  }

  async function saveAnalogEolConfig(){
    if (analogEolState.loading || analogEolState.saving) return;

    const modeSelect = $("#analogConfigMode");
    const normalMinInput = $("#analogConfigNormalMin");
    const normalMaxInput = $("#analogConfigNormalMax");
    const alarmMinInput = $("#analogConfigAlarmMin");
    const alarmMaxInput = $("#analogConfigAlarmMax");
    const tamperLowInput = $("#analogConfigTamperLow");
    const tamperHighInput = $("#analogConfigTamperHigh");

    let hasError = false;

    const mode = Number.parseInt(modeSelect?.value ?? '', 10);
    if (!Number.isInteger(mode) || mode < 1 || mode > 3) {
      modeSelect?.classList.add('input-error');
      hasError = true;
    } else {
      modeSelect?.classList.remove('input-error');
    }

    const readNumber = (input) => {
      if (!(input instanceof HTMLInputElement)) return null;
      input.classList.remove('input-error');
      if (input.disabled) {
        const disabledValue = Number.parseFloat(input.value);
        return Number.isFinite(disabledValue) ? disabledValue : 0;
      }
      const value = Number.parseFloat(input.value);
      if (!Number.isFinite(value)) {
        input.classList.add('input-error');
        hasError = true;
        return null;
      }
      return value;
    };

    const normalMin = readNumber(normalMinInput);
    const normalMax = readNumber(normalMaxInput);
    const alarmMin = readNumber(alarmMinInput);
    const alarmMax = readNumber(alarmMaxInput);
    const tamperLow = readNumber(tamperLowInput);
    const tamperHigh = readNumber(tamperHighInput);

    if (hasError) {
      toast('Correggi i valori evidenziati.', false);
      return;
    }

    analogEolState.saving = true;
    renderAnalogEolSection();
    try {
      await apiPost('/api/admin/inputs/analog-eol', {
        config: {
          mode,
          normal_min: normalMin,
          normal_max: normalMax,
          alarm_min: alarmMin,
          alarm_max: alarmMax,
          tamper_low: tamperLow,
          tamper_high: tamperHigh,
        },
      });
      analogEolState.saving = false;
      analogEolState.error = "";
      toast('Configurazione analogica salvata');
      await loadAnalogEolConfig(true);
    } catch (err) {
      analogEolState.saving = false;
      analogEolState.error = err?.message || 'Salvataggio configurazione fallito.';
      renderAnalogEolSection();
      toast(`Analogico: ${analogEolState.error}`, false);
    }
  }

  async function setupAnalogGeneralSection(){
    const reloadBtn = $("#analogEolReloadBtn");
    if (reloadBtn && !reloadBtn._analogBound){
      reloadBtn.addEventListener('click', () => loadAnalogEolConfig(true));
      reloadBtn._analogBound = true;
    }
    const saveBtn = $("#analogEolSaveBtn");
    if (saveBtn && !saveBtn._analogBound){
      saveBtn.addEventListener('click', () => saveAnalogEolConfig());
      saveBtn._analogBound = true;
    }
    const modeSelect = $("#analogConfigMode");
    if (modeSelect && !modeSelect._analogBound){
      modeSelect.addEventListener('change', () => updateAnalogConfigMode());
      modeSelect._analogBound = true;
    }
    await loadAnalogEolConfig(true);
  }

  async function sendCanBroadcast(nextState){
    const now = Date.now();
    if (now - canTestBroadcastState.lastRequestAt < 200){
      return;
    }
    canTestBroadcastState.lastRequestAt = now;
    if (canTestBroadcastState.sending){
      return;
    }
    canTestBroadcastState.sending = true;
    canTestBroadcastState.pendingState = nextState;
    canTestBroadcastState.lastError = "";
    updateCanTestBroadcastUI();
    try {
      const endpoint = nextState ? "/api/can/test/broadcast/on" : "/api/can/test/broadcast/off";
      const resp = await apiPost(endpoint, null);
      const isOn = typeof resp?.on === "boolean" ? resp.on : nextState;
      canTestBroadcastState.lastState = isOn;
      toast(`CAN: broadcast ${isOn ? "ON" : "OFF"} inviato`);
    } catch (err){
      const message = err?.message || "Invio comando CAN fallito";
      canTestBroadcastState.lastError = `Errore: ${message}`;
      toast(`CAN: ${message}`, false);
    } finally {
      canTestBroadcastState.sending = false;
      canTestBroadcastState.pendingState = null;
      updateCanTestBroadcastUI();
    }
  }

  async function loadExpansionNodes(){
    expansionsState.loading = true;
    expansionsState.error = "";
    renderExpansionsSection();
    try {
      const nodes = await apiGet("/api/can/nodes");
      expansionsState.items = Array.isArray(nodes) ? nodes : [];
      expansionsState.lastScan = Date.now();
    } catch(err){
      expansionsState.items = [];
      expansionsState.error = err?.message || "Impossibile recuperare le schede CAN.";
    }
    expansionsState.loading = false;
    renderExpansionsSection();
    if (expansionsState.error){
      toast(`Nodo CAN: ${expansionsState.error}`, false);
    }
  }

  async function scanExpansionBus(){
    if (expansionsState.loading) return;
    expansionsState.loading = true;
    expansionsState.error = "";
    renderExpansionsSection();
    try {
      await apiPost("/api/can/scan", {});
      toast("Scansione CAN avviata");
    } catch(err){
      expansionsState.loading = false;
      expansionsState.error = err?.message || "Impossibile avviare la scansione del bus CAN.";
      renderExpansionsSection();
      toast(`Nodo CAN: ${expansionsState.error}`, false);
      return;
    }
    await loadExpansionNodes();
  }

    async function updateExpansionLabel(nodeId, nextLabel, options = {}){
    if (!Number.isFinite(nodeId) || nodeId <= 0){
      toast("Operazione non valida", false);
      throw new Error("invalid_node");
    }
    const { reset = false } = options;
    let labelPayload = "";
    if (typeof nextLabel === "string") {
      labelPayload = nextLabel.trim();
    }
    if (labelPayload.length > CAN_NODE_LABEL_MAX) {
      labelPayload = labelPayload.slice(0, CAN_NODE_LABEL_MAX);
    }

    try {
      const resp = await apiPost(`/api/can/node/${nodeId}/label`, { label: labelPayload });
      const updatedLabel = (resp && typeof resp.label === "string") ? resp.label : labelPayload;
      if (resp && typeof resp === "object") {
        upsertExpansionNode(resp);
      } else {
        await loadExpansionNodes();
      }
      toast(reset ? "Nome scheda ripristinato" : "Nome scheda aggiornato");
      return { label: updatedLabel, node: resp };
    } catch (err){
      const message = err?.message || "Impossibile aggiornare il nome della scheda.";
      toast(`Nodo CAN: ${message}`, false);
      throw err;
    }
  }

  function openExpansionActions(nodeId){
    const node = getExpansionItems().find((item) => Number(item?.node_id) === nodeId);
    if (!node){
      toast("Nodo non trovato", false);
      return;
    }
    const title = escapeHtml(nodeTitle(node));
    const labelValue = typeof node?.label === "string" ? node.label : "";
    const stateLabel = escapeHtml(formatNodeStateLabel(node));
    const uidDisplay = escapeHtml(formatUid(node?.uid));
    const associationLabel = nodeId === 0 ? "Registrata il" : "Associata il";
    const association = escapeHtml(formatNodeAssociation(node));
    const lastSeen = escapeHtml(formatNodeLastSeen(node));
    const inputsCount = Number.isFinite(Number(node?.inputs_count)) ? Number(node.inputs_count) : "—";
    const outputsCount = Number.isFinite(Number(node?.outputs_count)) ? Number(node.outputs_count) : "—";
    const assignDefault = nodeId > 0 ? nodeId : "";
    modal(`
      <div class="card-head row" style="justify-content:space-between;align-items:center">
        <h3>Gestisci nodo CAN</h3>
        <button class="btn" id="mClose">Chiudi</button>
      </div>
      <div class="form" style="padding-bottom:.5rem">
        <p class="muted">Dettagli per <strong id="expModalName">${title}</strong>.</p>
        <form id="expLabelForm" class="form" style="margin:1rem 0;">
          <label class="field" style="width:100%;max-width:360px;">
            <span>Nome scheda</span>
            <input id="expLabelInput" type="text" maxlength="${CAN_NODE_LABEL_MAX}" value="${escapeHtml(labelValue)}" placeholder="Nome descrittivo" />
          </label>
          <div class="row" style="gap:.5rem;flex-wrap:wrap;margin-top:.5rem;">
            <button class="btn primary" type="submit">Salva nome</button>
            <button class="btn outline" type="button" id="expLabelResetBtn">Ripristina predefinito</button>
          </div>
          <p class="muted small" style="margin-top:.4rem;">Personalizza il nome visualizzato nelle dashboard.</p>
        </form>
        <div class="meta-grid" style="display:grid;grid-template-columns:160px 1fr;gap:.35rem .75rem;margin-bottom:1rem;">
          <span class="muted">ID nodo</span><span>${escapeHtml(String(nodeId))}</span>
          <span class="muted">UID</span><span>${uidDisplay}</span>
          <span class="muted">Stato</span><span>${stateLabel}</span>
          <span class="muted">Ingressi</span><span>${escapeHtml(String(inputsCount))}</span>
          <span class="muted">Uscite</span><span>${escapeHtml(String(outputsCount))}</span>
          <span class="muted">${associationLabel}</span><span>${association}</span>
          <span class="muted">Ultimo contatto</span><span>${lastSeen}</span>
        </div>
        <div class="row" style="gap:.5rem;flex-wrap:wrap;margin-bottom:1rem;">
          <button class="btn outline" type="button" data-exp-action="offline" data-node-id="${nodeId}">Segna offline</button>
          <button class="btn btn-danger" type="button" data-exp-action="forget" data-node-id="${nodeId}">Dimentica nodo</button>
        </div>
        <form id="expAssignForm" class="form" style="border-top:1px solid var(--border);padding-top:1rem;margin-top:1rem;">
          <div class="row" style="gap:1rem;flex-wrap:wrap;align-items:flex-end;">
            <label class="field" style="min-width:160px;max-width:220px;">
              <span>Nuovo ID nodo</span>
              <input id="expAssignInput" type="number" min="1" max="${CAN_MAX_NODE_ID}" value="${assignDefault}" required />
            </label>
            <button class="btn primary" type="submit">Riassegna ID</button>
          </div>
          <p class="muted small" style="margin-top:.4rem;">Assegna questo nodo a un ID specifico, utile quando sostituisci una scheda mantenendo la configurazione.</p>
        </form>
      </div>
    `);
    $("#mClose")?.addEventListener("click", () => closeModal());
    $$("[data-exp-action]").forEach((btn) => {
      btn.addEventListener("click", async (ev) => {
        ev.preventDefault();
        const mode = btn.getAttribute("data-exp-action");
        const id = Number(btn.getAttribute("data-node-id"));
        await handleExpansionAction(id, mode);
      });
    });
    const assignForm = $("#expAssignForm");
    if (assignForm){
      const input = assignForm.querySelector("#expAssignInput");
      const submitBtn = assignForm.querySelector('button[type="submit"]');
      assignForm.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const newId = Number(input?.value);
        if (!Number.isFinite(newId) || newId <= 0 || newId > CAN_MAX_NODE_ID){
          toast(`Inserisci un ID tra 1 e ${CAN_MAX_NODE_ID}`, false);
          return;
        }
        if (submitBtn) submitBtn.disabled = true;
        await assignExpansionNode(nodeId, newId);
        if (submitBtn && document.body.contains(submitBtn)) {
          submitBtn.disabled = false;
        }
      });
    }

    const labelForm = $("#expLabelForm");
    if (labelForm){
      const labelInput = labelForm.querySelector("#expLabelInput");
      const saveBtn = labelForm.querySelector('button[type="submit"]');
      const resetBtn = labelForm.querySelector("#expLabelResetBtn");
      labelForm.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        if (!labelInput) return;
        const raw = String(labelInput.value ?? "");
        const trimmed = raw.trim();
        if (!trimmed){
          toast("Inserisci un nome valido", false);
          return;
        }
        if (saveBtn) saveBtn.disabled = true;
        if (resetBtn) resetBtn.disabled = true;
        try {
          const { label } = await updateExpansionLabel(nodeId, trimmed);
          const finalLabel = (typeof label === "string" && label) ? label : trimmed.slice(0, CAN_NODE_LABEL_MAX);
          if (labelInput) labelInput.value = finalLabel;
          const nameEl = $("#expModalName");
          if (nameEl) nameEl.textContent = finalLabel;
        } catch (_) {
          // errore già mostrato da updateExpansionLabel
        } finally {
          if (saveBtn) saveBtn.disabled = false;
          if (resetBtn) resetBtn.disabled = false;
        }
      });
      if (resetBtn){
        resetBtn.addEventListener("click", async (ev) => {
          ev.preventDefault();
          if (saveBtn) saveBtn.disabled = true;
          resetBtn.disabled = true;
          try {
            const { label } = await updateExpansionLabel(nodeId, "", { reset: true });
            const fallback = (typeof label === "string" && label) ? label : `Exp ${nodeId}`;
            if (labelInput) labelInput.value = fallback;
            const nameEl = $("#expModalName");
            if (nameEl) nameEl.textContent = fallback;
          } catch (_) {
            // errore già notificato
          } finally {
            if (saveBtn) saveBtn.disabled = false;
            resetBtn.disabled = false;
          }
        });
      }
    }
  }

  async function handleExpansionAction(nodeId, mode){
    closeModal();
    if (!Number.isFinite(nodeId) || nodeId <= 0){
      toast("Operazione non valida", false);
      return;
    }
    expansionsState.loading = true;
    expansionsState.error = "";
    renderExpansionsSection();
    try {
      const query = mode === "forget" ? "?hard=1" : "";
      await apiDelete(`/api/can/nodes/${nodeId}${query}`);
      toast(mode === "forget" ? "Nodo dimenticato" : "Nodo segnato offline");
      await loadExpansionNodes();
    } catch(err){
      expansionsState.loading = false;
      const message = err?.message || "Operazione CAN fallita";
      expansionsState.error = message;
      renderExpansionsSection();
      toast(`Nodo CAN: ${message}`, false);
    }
  }

  async function assignExpansionNode(nodeId, newId){
    if (!Number.isFinite(nodeId) || nodeId <= 0){
      toast("Operazione non valida", false);
      return;
    }
    if (!Number.isFinite(newId) || newId <= 0 || newId > CAN_MAX_NODE_ID){
      toast(`ID valido tra 1 e ${CAN_MAX_NODE_ID}`, false);
      return;
    }
    expansionsState.loading = true;
    expansionsState.error = "";
    renderExpansionsSection();
    try {
      const resp = await apiPost(`/api/can/node/${nodeId}/assign`, { new_id: newId });
      const assignedId = Number.isFinite(Number(resp?.node_id)) ? Number(resp.node_id) : newId;
      toast(`Nodo CAN assegnato all'ID ${assignedId}`);
      closeModal();
      await loadExpansionNodes();
    } catch(err){
      let message = err?.message || "Operazione CAN fallita";
      if (typeof message === "string"){
        const normalized = message.trim().toLowerCase();
        if (normalized === "uid"){
          message = "UID non disponibile. Accendi la scheda o attendi che invii le informazioni.";
        } else if (normalized === "busy"){
          message = "ID già assegnato ad un'altra scheda. Dimentica o riassegna prima quel nodo.";
        } else if (normalized === "can"){
          message = "Errore CAN durante l'invio del comando.";
        }
      }
      expansionsState.loading = false;
      expansionsState.error = message;
      renderExpansionsSection();
      toast(`Nodo CAN: ${message}`, false);
    }
  }

  async function setupExpansionsSection(){
    const scanBtn = $("#adminExpansionScanBtn");
    if (scanBtn){
      scanBtn.addEventListener("click", () => { scanExpansionBus(); });
    }
    const refreshBtn = $("#adminExpansionRefreshBtn");
    if (refreshBtn){
      refreshBtn.addEventListener("click", () => { loadExpansionNodes(); });
    }
    const list = $("#adminExpansionList");
    if (list){
      list.addEventListener("click", (event) => {
        const telemetryBtn = event.target.closest("[data-node-telemetry]");
        if (telemetryBtn){
          const telemetryId = Number(telemetryBtn.getAttribute("data-node-telemetry"));
          if (!Number.isFinite(telemetryId) || telemetryId <= 0){
            toast("Telemetria disponibile solo per le espansioni", false);
            return;
          }
          event.preventDefault();
          openNodeTelemetry(telemetryId);
          return;
        }
        const actionsBtn = event.target.closest("[data-node-actions]");
        if (!actionsBtn) return;
        const nodeId = Number(actionsBtn.getAttribute("data-node-actions"));
        if (!Number.isFinite(nodeId) || nodeId <= 0){
          toast("Nodo master non modificabile", false);
          return;
        }
        openExpansionActions(nodeId);
      });
    }
    const broadcastOnBtn = $("#canTestBroadcastOnBtn");
    if (broadcastOnBtn){
      broadcastOnBtn.addEventListener("click", () => { sendCanBroadcast(true); });
    }
    const broadcastOffBtn = $("#canTestBroadcastOffBtn");
    if (broadcastOffBtn){
      broadcastOffBtn.addEventListener("click", () => { sendCanBroadcast(false); });
    }
    updateCanTestBroadcastUI();
    renderExpansionsSection();
    await loadExpansionNodes();
  }

  // ========== USERS
  function renderUsers(list){
    const tb = $("#usersTbody");
    if (!tb){ return; }
    tb.innerHTML = "";
    if (!Array.isArray(list)){
      tb.innerHTML = `<tr><td colspan="7" class="muted">Impossibile leggere la lista utenti</td></tr>`;
      return;
    }
    if (list.length === 0){
      tb.innerHTML = `<tr><td colspan="7" class="muted">Nessun utente</td></tr>`;
      return;
    }
    const frag = document.createDocumentFragment();
    for(const u of list){
      const tr = document.createElement("tr");
      const username = (u && typeof u.username === "string") ? u.username : "";
      const firstName = (u && typeof u.first_name === "string") ? u.first_name : "";
      const lastName = (u && typeof u.last_name === "string") ? u.last_name : "";
      const hasPin = !!(u && u.has_pin);
      const hasRfid = !!(u && u.has_rfid);
      const rfidValue = hasRfid ? ((u && typeof u.rfid_uid === "string" && u.rfid_uid) ? u.rfid_uid : "✅") : "—";
      const totpValue = !!(u && u.totp_enabled) ? "✅" : "—";
      const cells = [
        username,
        firstName,
        lastName,
        hasPin ? "✅" : "—",
        rfidValue,
        totpValue
      ];
      for (const value of cells){
        const td = document.createElement("td");
        td.textContent = value;
        tr.appendChild(td);
      }
      const actionTd = document.createElement("td");
      const btn = document.createElement("button");
      btn.className = "btn btn-sm";
      btn.dataset.edit = username;
      btn.textContent = "Modifica";
      actionTd.appendChild(btn);
      tr.appendChild(actionTd);
      frag.appendChild(tr);
    }
    tb.appendChild(frag);
    tb.querySelectorAll("[data-edit]").forEach(btn => btn.addEventListener("click", () => openEditUser(btn.getAttribute("data-edit"))));
  }

  async function loadUsers(){
    try{
      const list = await apiGet("/api/admin/users");
      if (!Array.isArray(list)) throw new Error("formato inatteso");
      renderUsers(list);
    }catch(e){
      renderUsers(null);
      toast("Errore caricando utenti: " + e.message, false);
    }
  }

  // ---- Modals
  function registerModalCleanup(fn){
    if (typeof fn === "function") {
      modalCleanupHandlers.add(fn);
    }
  }

  function runModalCleanup(){
    if (!modalCleanupHandlers.size) return;
    modalCleanupHandlers.forEach((fn) => {
      try { fn(); } catch (err) { console.warn('modal cleanup', err); }
    });
    modalCleanupHandlers.clear();
  }

  function closeModal(){
    runModalCleanup();
    const root = $("#modals-root");
    if (root) {
      root.innerHTML = "";
    }
  }

  function modal(html){
    const root = $("#modals-root");
    if (!root) return;
    closeModal();
    root.innerHTML = `
      <div class="modal-overlay" style="position:fixed;inset:0;background:rgba(0,0,0,.45);backdrop-filter:blur(1px);display:grid;place-items:center;z-index:1500">
        <div class="modal card" style="width:min(720px, 96vw);max-height:88vh;overflow:auto">
          ${html}
        </div>
      </div>`;
    const overlay = root.querySelector(".modal-overlay");
    if (overlay){
      const handleClick = (e) => {
        if (e.target.classList.contains("modal-overlay")) {
          closeModal();
        }
      };
      overlay.addEventListener("click", handleClick);
      registerModalCleanup(() => overlay.removeEventListener("click", handleClick));
    }
    function onKey(e){
      if (e.key === "Escape") {
        closeModal();
      }
    }
    window.addEventListener("keydown", onKey);
    registerModalCleanup(() => window.removeEventListener("keydown", onKey));
  }

  function newUserModal(){
    modal(`
      <div class="card-head row" style="justify-content:space-between;align-items:center"><h3>Nuovo utente</h3><button class="btn" id="mClose">Chiudi</button></div>
      <form class="form" id="newUserForm">
        <div class="row" style="gap:1rem;flex-wrap:wrap">
          <div class="field"><span>Username</span><input required id="nu_user" type="text" autocomplete="off"></div>          
        </div>
        <div class="row" style="gap:1rem;flex-wrap:wrap">
          <div class="field"><span>Nome</span><input id="nu_fn" type="text"></div>
          <div class="field"><span>Cognome</span><input id="nu_ln" type="text"></div>
        </div>
        <div class="row" style="gap:1rem;flex-wrap:wrap">
          <div class="field"><span>Password</span><input id="nu_pw" type="password" autocomplete="new-password"></div>
          <div class="field"><span>PIN (Allarme)</span><input id="nu_pin" type="password" pattern="\\d{4,8}" placeholder="4–8 cifre"></div>
        </div>
        <div class="row" style="justify-content:flex-end;margin-top:.6rem">
          <button class="btn" type="submit">Crea</button>
        </div>
      </form>
    `);
    $("#mClose").addEventListener("click", closeModal);
    $("#newUserForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = {
        user: $("#nu_user").value.trim(),
        first_name: $("#nu_fn").value.trim(),
        last_name: $("#nu_ln").value.trim(),
        password: $("#nu_pw").value,
        pin: $("#nu_pin").value
      };
      if (!payload.user){ toast("Username obbligatorio", false); return; }
      try{
        await apiPost("/api/users/create", payload);
        toast("Utente creato");
        closeModal();
        await loadUsers();
      }catch(err){
        toast("Errore creazione utente: " + err.message, false);
      }
    });
  }

  // HOME tab -> torna alla dashboard
  document.addEventListener("click", (e)=>{
    const b = e.target.closest(".tab-btn");
    if (b && b.dataset.tab === 'home') {
      e.preventDefault();
      location.replace("/");
    }
  });

  // async function openEditUser(username){
  //   // Recupera record corrente
  //   let list = [];
  //   try{ list = await apiGet("/api/admin/users"); }catch{}
  //   const rec = list.find(x => x.username === username) || { username, first_name:"", last_name:"", has_rfid:false, rfid_uid:"" };

  //   modal(`
  //     <div class="card-head row" style="justify-content:space-between;align-items:center">
  //       <h3>Modifica utente — <span class="muted">${username}</span></h3>
  //       <button class="btn" id="mClose">Chiudi</button>
  //     </div>
  //     <div class="form">
  //       <div class="row" style="gap:1rem;flex-wrap:wrap">
  //         <div class="field"><span>Nome</span><input id="ed_fn" type="text" value="${(rec.first_name||"").replace(/"/g,'&quot;')}"></div>
  //         <div class="field"><span>Cognome</span><input id="ed_ln" type="text" value="${(rec.last_name||"").replace(/"/g,'&quot;')}"></div>
  //       </div>
  //       <div class="row" style="gap:1rem;flex-wrap:wrap;align-items:flex-end">
  //         <div class="field" style="min-width:260px">
  //           <span>Tag RFID</span>
  //           <div id="rfidBox">
  //             ${rec.has_rfid ? `<div class="tag">UID: <strong>${rec.rfid_uid||"—"}</strong></div>` : `<div class="muted">Nessun tag associato</div>`}
  //           </div>
  //         </div>
  //         <div class="row" style="gap:.4rem">
  //           <button class="btn" id="btnRfidLearn">Aggiungi</button>
  //           <button class="btn btn-danger" id="btnRfidClear"${rec.has_rfid?"":" disabled"}>Rimuovi</button>
  //         </div>
  //         <div class="row" style="margin-left:auto;gap:.4rem">
  //           <button class="btn" id="btnSave">Salva</button>
  //         </div>
  //       </div>
  //       <small class="muted">Nota: l'aggiornamento di Nome/Cognome richiede supporto firmware.</small>
  //       <div class="row" style="gap:1rem;flex-wrap:wrap;margin-top:.6rem">
  //         <div class="field"><span>Nuova password</span><input id="ed_pw1" type="password" autocomplete="new-password"></div>
  //         <div class="field"><span>Conferma</span><input id="ed_pw2" type="password" autocomplete="new-password"></div>
  //         <div class="row" style="align-items:flex-end">
  //           <button class="btn" id="btnSetPw">Aggiorna password</button>
  //         </div>
  //       </div>
  //       <small class="muted">Come amministratore puoi resettare la password di questo utente senza conoscere quella attuale.</small>
  //     </div>
  //   `);
  //   $("#mClose").addEventListener("click", closeModal);

  //   $("#btnSave").addEventListener("click", async (e) => {
  //     e.preventDefault();
  //     const payload = { user: username, first_name: $("#ed_fn").value.trim(), last_name: $("#ed_ln").value.trim() };
  //     try{
  //       await apiPost("/api/users/name", payload); // se non supportato -> errore gestito
  //       toast("Dati salvati");
  //       closeModal();
  //       await loadUsers();
  //     }catch(err){
  //       toast("Salvataggio Nome/Cognome non supportato dal firmware: " + err.message, false);
  //     }
  //   });

  //   $("#btnSetPw")?.addEventListener("click", async (e) => {
  //     e.preventDefault();
  //     const p1 = $("#ed_pw1")?.value || "";
  //     const p2 = $("#ed_pw2")?.value || "";
  //     if (p1.length < 6) { toast("Password troppo corta (min 6 caratteri)", false); return; }
  //     if (p1 !== p2) { toast("Le password non coincidono", false); return; }
  //     try{
  //       await apiPost("/api/users/password", { user: username, newpass: p1 });
  //       toast("Password aggiornata");
  //       if ($("#ed_pw1")) $("#ed_pw1").value = "";
  //       if ($("#ed_pw2")) $("#ed_pw2").value = "";
  //     }catch(err){
  //       toast("Errore aggiornando la password: " + err.message, false);
  //     }
  //   });

  //   $("#btnRfidClear").addEventListener("click", async (e) => {
  //     e.preventDefault();
  //     try{
  //       await apiPost("/api/users/rfid/clear", { user: username });
  //       toast("Tag rimosso");
  //       closeModal(); await loadUsers();
  //     }catch(err){ toast("Errore rimozione tag: "+err.message, false); }
  //   });

  //   $("#btnRfidLearn").addEventListener("click", async (e) => {
  //     e.preventDefault();
  //     const overlay = document.createElement("div");
  //     overlay.className = "modal-overlay";
  //     overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,35);display:grid;place-items:center;z-index:1600";
  //     overlay.innerHTML = `<div class="card" style="padding:1rem 1.2rem"><strong>Scansione RFID in corso…</strong><div class="muted" style="margin-top:.4rem">Avvicina il tag al lettore</div></div>`;
  //     document.body.appendChild(overlay);
  //     try{
  //       const res = await apiPost("/api/users/rfid/learn", { user: username, timeout: 10 });
  //       toast("Tag associato: " + (res?.uid_hex || "OK"));
  //       closeModal(); await loadUsers();
  //     }catch(err){
  //       toast("RFID: " + err.message, false);
  //     }finally{
  //       overlay.remove();
  //     }
  //   });
  // }

  // Sostituisci integralmente la tua funzione con questa versione
  async function openEditUser(username){
    const esc = (s) => (s ?? "").toString()
      .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
      .replace(/"/g,"&quot;").replace(/'/g,"&#39;");

    // Prova a recuperare il record dalla lista admin; fallback a valori vuoti
    let rec = { username, first_name:"", last_name:"", has_rfid:false, rfid_uid:"" };
    try {
      const list = await apiGet("/api/admin/users");
      const found = Array.isArray(list) ? list.find(u => u.username === username) : null;
      if (found) rec = { ...rec, ...found };
    } catch {}

    modal(`
      <div class="card-head row" style="justify-content:space-between;align-items:center">
        <h3>Modifica utente — <span class="muted">${esc(username)}</span></h3>
        <button class="btn" id="mClose">Chiudi</button>
      </div>

      <div class="form" style="padding-bottom:.5rem">
        <!-- ===== Dati anagrafici ===== -->
        <h4>Dati</h4>
        <div class="row" style="gap:1rem;flex-wrap:wrap">
          <label class="field"><span>Nome</span>
            <input id="ed_fn" type="text" value="${esc(rec.first_name)}">
          </label>
          <label class="field"><span>Cognome</span>
            <input id="ed_ln" type="text" value="${esc(rec.last_name)}">
          </label>
          <div class="row" style="align-items:flex-end;margin-left:auto">
            <button class="btn" id="btnSave">Salva</button>
          </div>
        </div>

        <!-- ===== RFID ===== -->
        <h4 style="margin-top:1rem">RFID</h4>
        <div class="row" style="gap:.6rem;align-items:center;flex-wrap:wrap">
          <div id="rfidBox">
            ${
              rec.has_rfid
                ? `<div class="tag">UID: <strong>${esc(rec.rfid_uid || "—")}</strong></div>`
                : `<div class="muted">Nessun tag associato</div>`
            }
          </div>
          <div class="row" style="gap:.4rem">
            <button class="btn" id="btnRfidLearn">Aggiungi</button>
            <button class="btn btn-danger" id="btnRfidClear"${rec.has_rfid ? "" : " disabled"}>Rimuovi</button>
          </div>
        </div>

        <!-- ===== PIN ===== -->
        <h4 style="margin-top:1rem">PIN (Allarme)</h4>
        <div class="row" style="gap:1rem;flex-wrap:wrap;align-items:flex-end">
          <label class="field" style="min-width:240px"><span>Nuovo PIN</span>
            <input id="ed_pin" type="password" inputmode="numeric" pattern="\\d*" maxlength="12" autocomplete="off">
          </label>
          <button class="btn" id="btnSetPin">Aggiorna PIN</button>
        </div>

        <!-- ===== Password ===== -->
        <h4 style="margin-top:1rem">Password</h4>
        <div class="row" style="gap:1rem;flex-wrap:wrap;align-items:flex-end">
          <label class="field"><span>Nuova password</span>
            <input id="ed_pw1" type="password" autocomplete="new-password">
          </label>
          <label class="field"><span>Conferma</span>
            <input id="ed_pw2" type="password" autocomplete="new-password">
          </label>
          <button class="btn" id="btnSetPw">Aggiorna password</button>
        </div>
        <small class="muted">Come amministratore puoi resettare la password di questo utente senza conoscere quella attuale.</small>
      </div>
    `);

    // --- Handlers ---
    $("#mClose")?.addEventListener("click", () => closeModal());

    // Salva Nome/Cognome
    $("#btnSave")?.addEventListener("click", async (e) => {
      e.preventDefault();
      const payload = {
        user: username,
        first_name: $("#ed_fn")?.value?.trim() || "",
        last_name:  $("#ed_ln")?.value?.trim() || ""
      };
      try {
        await apiPost("/api/users/name", payload);
        toast("Dati salvati");
        closeModal(); // se preferisci non chiudere, rimuovi questa riga
        try { await loadUsers(); } catch {}
      } catch(err) {
        toast("Salvataggio Nome/Cognome non supportato o errore: " + err.message, false);
      }
    });

    // Aggiorna PIN
    $("#btnSetPin")?.addEventListener("click", async (e) => {
      e.preventDefault();
      const pin = ($("#ed_pin")?.value || "").trim();
      if (pin.length < 4) { toast("PIN troppo corto (min 4 cifre)", false); return; }
      if (!/^[0-9]{4,12}$/.test(pin)) { toast("PIN deve contenere solo cifre (4–12)", false); return; }
      try {
        await apiPost("/api/users/pin", { user: username, pin });
        toast("PIN aggiornato");
        if ($("#ed_pin")) $("#ed_pin").value = "";
      } catch(err) {
        toast("Errore aggiornando il PIN: " + err.message, false);
      }
    });

    // Aggiorna Password
    $("#btnSetPw")?.addEventListener("click", async (e) => {
      e.preventDefault();
      const p1 = $("#ed_pw1")?.value || "";
      const p2 = $("#ed_pw2")?.value || "";
      if (p1.length < 6) { toast("Password troppo corta (min 6 caratteri)", false); return; }
      if (p1 !== p2) { toast("Le password non coincidono", false); return; }
      try {
        await apiPost("/api/users/password", { user: username, newpass: p1 });
        toast("Password aggiornata");
        if ($("#ed_pw1")) $("#ed_pw1").value = "";
        if ($("#ed_pw2")) $("#ed_pw2").value = "";
      } catch(err) {
        toast("Errore aggiornando la password: " + err.message, false);
      }
    });

    // Rimuovi RFID
    $("#btnRfidClear")?.addEventListener("click", async (e) => {
      e.preventDefault();
      try {
        await apiPost("/api/users/rfid/clear", { user: username });
        toast("Tag rimosso");
        closeModal(); await loadUsers();
      } catch(err) {
        toast("Errore rimozione tag: " + err.message, false);
      }
    });

    // Apprendimento RFID
    $("#btnRfidLearn")?.addEventListener("click", async (e) => {
      e.preventDefault();
      const overlay = document.createElement("div");
      overlay.className = "modal-overlay";
      overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.35);display:grid;place-items:center;z-index:1600";
      overlay.innerHTML = `<div class="card" style="padding:1rem 1.2rem">
          <strong>Scansione RFID in corso…</strong>
          <div class="muted" style="margin-top:.4rem">Avvicina il tag al lettore</div>
        </div>`;
      document.body.appendChild(overlay);
      try{
        const res = await apiPost("/api/users/rfid/learn", { user: username, timeout: 10 });
        toast("Tag associato: " + (res?.uid_hex || "OK"));
        closeModal(); await loadUsers();
      } catch(err) {
        toast("RFID: " + err.message, false);
      } finally {
        overlay.remove();
      }
    });
  }


  function attachNewUser(){
    $("#btnNewUser")?.addEventListener("click", newUserModal);
  }

  const MQTT_PASS_PLACEHOLDER = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
  const MQTT_REVEAL_TIMEOUT_MS = 30000;
  let mqttRevealTimer = null;

  function getMqttPassField(){ return $("#mq_pass"); }

  function clearMqttRevealTimer(){
    if (mqttRevealTimer){
      clearTimeout(mqttRevealTimer);
      mqttRevealTimer = null;
    }
  }

  function initMqttPasswordField(hasSecret){
    const field = getMqttPassField();
    if (!field) return;
    clearMqttRevealTimer();
    field.type = "password";
    field.dataset.hasSecret = hasSecret ? "1" : "0";
    field.dataset.userEdited = "0";
    field.dataset.visible = "0";
    if (hasSecret){
      field.value = MQTT_PASS_PLACEHOLDER;
      field.dataset.masked = "1";
    } else {
      field.value = "";
      field.dataset.masked = "0";
    }
    if (!field._mqttBound){
      field.addEventListener("input", () => {
        field.dataset.userEdited = "1";
        field.dataset.hasSecret = field.value ? "1" : "0";
        field.dataset.masked = "0";
        field.dataset.visible = "0";
        field.type = "password";
        clearMqttRevealTimer();
      });
      field.addEventListener("blur", () => {
        if (!field.value){ field.dataset.hasSecret = "0"; }
      });
      field._mqttBound = true;
    }
  }

  function maskMqttPassword(){
    const field = getMqttPassField();
    if (!field) return;
    clearMqttRevealTimer();
    field.type = "password";
    field.dataset.visible = "0";
    if (field.dataset.userEdited === "1") return;
    if (field.dataset.hasSecret === "1"){
      field.value = MQTT_PASS_PLACEHOLDER;
      field.dataset.masked = "1";
    } else {
      field.value = "";
      field.dataset.masked = "0";
    }
  }

  function revealMqttPassword(secret){
    const field = getMqttPassField();
    if (!field) return;
    clearMqttRevealTimer();
    field.type = "text";
    field.value = secret || "";
    field.dataset.hasSecret = secret ? "1" : "0";
    field.dataset.masked = "0";
    field.dataset.visible = "1";
    field.dataset.userEdited = "0";
    mqttRevealTimer = setTimeout(() => {
      maskMqttPassword();
    }, MQTT_REVEAL_TIMEOUT_MS);
  }

  function ensureMqttRevealButton(){
    const saveBtn = $("#btnMqttSave");
    if (!saveBtn) return;
    let revealBtn = $("#btnMqttReveal");
    if (!revealBtn){
      revealBtn = document.createElement("button");
      revealBtn.type = "button";
      revealBtn.id = "btnMqttReveal";
      revealBtn.className = "btn";
      revealBtn.textContent = "Mostra password";
      revealBtn.style.marginRight = ".5rem";
      saveBtn.parentElement?.insertBefore(revealBtn, saveBtn);
    }
    if (!revealBtn._bound){
      revealBtn.addEventListener("click", openMqttRevealModal);
      revealBtn._bound = true;
    }
  }

  function openMqttRevealModal(){
    modal(`
      <div class="card-head row" style="justify-content:space-between;align-items:center">
        <h3>Mostra password MQTT</h3>
        <button class="btn" id="mqttRevealClose" type="button">Chiudi</button>
      </div>
      <form class="form" id="mqttRevealForm">
        <div class="field"><span>Password amministratore</span><input id="mqttRevealAdminPass" type="password" autocomplete="current-password" required></div>
        <small class="muted">La password verrà mostrata per 30 secondi oppure finché non lasci questa vista.</small>
        <div id="mqttRevealError" class="muted" style="color:#ef4444;margin-top:.4rem;display:none"></div>
        <div class="row" style="justify-content:flex-end;margin-top:.8rem;gap:.5rem">
          <button class="btn" type="submit" id="mqttRevealSubmit">Mostra</button>
        </div>
      </form>
    `);
    $("#mqttRevealClose")?.addEventListener("click", closeModal);
    const form = $("#mqttRevealForm");
    const input = $("#mqttRevealAdminPass");
    const errorEl = $("#mqttRevealError");
    const submitBtn = $("#mqttRevealSubmit");
    input?.focus();
    form?.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!input) return;
      const adminPw = input.value;
      if (!adminPw){
        if (errorEl){ errorEl.textContent = "Inserisci la password amministratore."; errorEl.style.display = "block"; }
        input.focus();
        return;
      }
      if (errorEl) errorEl.style.display = "none";
      if (submitBtn){ submitBtn.disabled = true; submitBtn.textContent = "Verifica…"; }
      try {
        const resp = await apiPost("/api/sys/mqtt/reveal", { password: adminPw }, { skipAuthRedirect: true });
        const secret = resp?.pass ?? "";
        revealMqttPassword(secret);
        const field = getMqttPassField();
        if (field) field.dataset.hasSecret = secret ? "1" : "0";
        closeModal();
        toast("Password MQTT visibile per 30 secondi");
      } catch (err){
        let msg = err?.message || "Errore";
        if (msg.toLowerCase().includes("bad pass")) msg = "Password amministratore non corretta.";
        if (errorEl){ errorEl.textContent = msg; errorEl.style.display = "block"; }
        input.select();
      } finally {
        if (submitBtn){ submitBtn.disabled = false; submitBtn.textContent = "Mostra"; }
      }
    });
  }


  function formatValue(v){
    if (v === null || v === undefined || v === "") return "—";
    if (typeof v === "boolean") return v ? "sì" : "no";
    if (typeof v === "number") return Number.isInteger(v) ? String(v) : String(Math.round(v * 100) / 100);
    return String(v);
  }

  function formatInfoKey(key){
    return String(key || '').replaceAll('_', ' ');
  }

  function renderInfoRows(obj, prefix = ''){
    return Object.entries(obj || {}).map(([k, v]) => {
      const label = prefix ? `${prefix} ${formatInfoKey(k)}` : formatInfoKey(k);
      if (v && typeof v === "object" && !Array.isArray(v)) {
        return renderInfoRows(v, label);
      }
      if (Array.isArray(v)) {
        const text = v.length ? v.map(formatValue).join(', ') : '—';
        return `<div class="info-row"><span>${escapeHtml(label)}</span><strong><code>${escapeHtml(text)}</code></strong></div>`;
      }
      return `<div class="info-row"><span>${escapeHtml(label)}</span><strong><code>${escapeHtml(formatValue(v))}</code></strong></div>`;
    }).join("");
  }

  function renderInfoObject(title, obj){
    let rows = renderInfoRows(obj || {});
    if (title === 'peripherals' && obj?.ads1115?.configured === 0) {
      rows += '<p class="muted">Nessun modulo ADS1115 configurato</p>';
    }
    if (title === 'diagnostics' && (!obj || obj.active === false)) {
      rows = `<p class="muted">${escapeHtml(obj?.message || 'Nessuna diagnostica attiva')}</p>`;
    }
    return `<div class="info-card"><h4>${escapeHtml(title)}</h4>${rows || '<p class="muted">Nessuna diagnostica attiva</p>'}</div>`;
  }

  async function loadSystemInfo(){
    const grid = $("#systemInfoGrid");
    const status = $("#systemInfoStatus");
    if (!grid) return;
    try{
      if (status) status.textContent = "Caricamento…";
      const data = await apiGet("/api/admin/system");
      grid.innerHTML = ["firmware","hardware","runtime","network","storage","peripherals","mqtt","diagnostics"]
        .map(k => renderInfoObject(k, data?.[k] || {})).join("");
      if (status) status.textContent = `Aggiornato: ${new Date().toLocaleString()}`;
    }catch(e){
      if (status) status.textContent = "Errore caricando sistema: " + e.message;
    }
  }

  function setupSystemSection(){
    $("#btnSystemReload")?.addEventListener("click", loadSystemInfo);
    loadSystemInfo().catch(()=>{});
  }

  async function loadNotifications(){
    try{
      const c = await apiGet("/api/admin/notifications");
      $("#notify_mqtt") && ($("#notify_mqtt").value = c.mqtt_publish_enabled ? "1" : "0");
      $("#notify_sev") && ($("#notify_sev").value = c.min_severity || "info");
      $("#notify_repeat") && ($("#notify_repeat").value = c.repeat_critical_unacked ? "1" : "0");
      $("#notify_interval") && ($("#notify_interval").value = c.repeat_interval_s ?? 300);
    }catch(e){ toast("Errore caricando notifiche: " + e.message, false); }
  }

  function setupNotificationsSection(){
    loadNotifications().catch(()=>{});
    $("#btnNotifySave")?.addEventListener("click", async () => {
      const body = {
        mqtt_publish_enabled: ($("#notify_mqtt")?.value || "1") === "1",
        min_severity: $("#notify_sev")?.value || "info",
        repeat_critical_unacked: ($("#notify_repeat")?.value || "1") === "1",
        repeat_interval_s: parseInt($("#notify_interval")?.value || "300", 10) || 300,
      };
      try{ await apiPost("/api/admin/notifications", body); toast("Notifiche salvate"); }
      catch(e){ toast("Errore salvataggio notifiche: " + e.message, false); }
    });
    $("#btnNotifyTest")?.addEventListener("click", async () => {
      try{ await apiPost("/api/admin/notifications/test", {}); toast("Evento di test pubblicato"); }
      catch(e){ toast("Test notifica: " + e.message, false); }
    });
  }

  // ========== RETE / MQTT
  function netLabel(value){
    return ({ ethernet_only:"Solo Ethernet", wifi_only:"Solo Wi-Fi", ethernet_preferred:"Ethernet preferita", wifi_preferred:"Wi-Fi preferito", ethernet:"Ethernet", wifi:"Wi-Fi", none:"Nessuna" })[value] || value || "—";
  }

  function renderNetworkStatus(c){
    const box = $("#netStatus");
    if (!box) return;
    const wifi = c.wifi || {};
    const eth = c.ethernet || {};
    const items = [
      ["Interfaccia attiva", netLabel(c.active_interface)],
      ["Modalità", netLabel(c.network_mode)],
      ["Hostname", c.hostname || "—"],
      ["Ethernet", eth.link_up ? "link up" : "link down"],
      ["IP Ethernet", eth.ip || "0.0.0.0"],
      ["MAC Ethernet", eth.mac || "—"],
      ["Wi-Fi", wifi.connected ? "connesso" : "disconnesso"],
      ["SSID Wi-Fi", wifi.ssid || "—"],
      ["RSSI Wi-Fi", wifi.rssi ? `${wifi.rssi} dBm` : "—"],
      ["IP Wi-Fi", wifi.ip || "0.0.0.0"],
      ["MAC Wi-Fi", wifi.mac || "—"],
      ["Password Wi-Fi", wifi.password_set ? "configurata" : "non configurata"],
      ["AP fallback", c.setup_ap?.active ? `attivo (${c.setup_ap.ssid || "—"})` : (c.setup_ap?.enabled ? "abilitato" : "disabilitato")],
      ["IP AP fallback", c.setup_ap?.ip || "192.168.4.1"],
      ["Client AP fallback", Number.isFinite(c.setup_ap?.clients) ? c.setup_ap.clients : "—"],
      ["Avvii AP fallback", Number.isFinite(c.setup_ap?.start_count) ? c.setup_ap.start_count : "—"],
      ["Motivo ultimo AP", c.setup_ap?.last_reason || "—"],
      ["Ultimo evento client AP", c.setup_ap?.last_client_event || "—"],
      ["Password AP", c.setup_ap?.password_set ? "configurata" : "non configurata"],
      ["Ultimo errore", c.last_error || "—"],
    ];
    box.innerHTML = items.map(([k,v]) => `<div><span>${k}</span><strong>${v}</strong></div>`).join("");
  }

  async function loadNetwork(){
    try{
      const c = await apiGet("/api/admin/network");
      renderNetworkStatus(c);
      $("#net_mode") && ($("#net_mode").value = c.network_mode || "ethernet_only");
      $("#net_host") && ($("#net_host").value = c.hostname || "");
      $("#net_wifi_ssid") && ($("#net_wifi_ssid").value = c.wifi?.ssid || "");
      $("#net_wifi_password") && ($("#net_wifi_password").value = "");
      $("#net_setup_enabled") && ($("#net_setup_enabled").value = c.setup_ap?.enabled === false ? "0" : "1");
      $("#net_setup_password") && ($("#net_setup_password").value = "");
    }catch(e){ toast("Errore caricando rete: " + e.message, false); }

    $("#btnNetWifiScan")?.addEventListener("click", async ()=>{
      try{
        const res = await apiGet("/api/admin/network/wifi/scan");
        const box = $("#netWifiScan");
        if (box){
          const nets = res.networks || [];
          box.innerHTML = nets.length ? nets.map(n => `<button class="btn" type="button" data-ssid="${escapeHtml(n.ssid || "")}">${escapeHtml(n.ssid || "(nascosta)")} · ${n.rssi || 0} dBm · ${escapeHtml(n.security || "")}</button>`).join("") : "<div><span>Reti</span><strong>Nessuna rete trovata</strong></div>";
          box.querySelectorAll("button[data-ssid]").forEach(b => b.addEventListener("click", ()=>{ const v=b.getAttribute("data-ssid")||""; if(v) $("#net_wifi_ssid").value=v; }));
        }
      }catch(e){ toast("Scansione Wi-Fi fallita: " + e.message, false); }
    });

    $("#btnNetWifiTest")?.addEventListener("click", async ()=>{
      const ssid = ($("#net_wifi_ssid")?.value || "").trim();
      const password = $("#net_wifi_password")?.value || "";
      if (!ssid) return toast("SSID Wi-Fi obbligatorio", false);
      try{
        await apiPost("/api/admin/network/wifi/test", { ssid, password });
        toast("Test Wi-Fi riuscito");
        await loadNetwork();
      }catch(e){ toast("Test Wi-Fi fallito: " + e.message, false); }
    });

    $("#btnNetSetupExit")?.addEventListener("click", async ()=>{
      try{ await apiPost("/api/admin/network/setup/exit", {}); toast("Uscita setup richiesta"); setTimeout(loadNetwork, 1000); }
      catch(e){ toast("Uscita setup: " + e.message, false); }
    });

    $("#btnNetRestart")?.addEventListener("click", async ()=>{
      try{ await apiPost("/api/admin/network/restart", {}); toast("Riavvio rete avviato"); setTimeout(loadNetwork, 1500); }
      catch(e){ toast("Riavvio rete: " + e.message, false); }
    });

    $("#btnNetSave")?.addEventListener("click", async ()=>{
      const mode = $("#net_mode")?.value || "ethernet_only";
      const ssid = ($("#net_wifi_ssid")?.value || "").trim();
      const password = $("#net_wifi_password")?.value || "";
      if ((mode === "wifi_only" || mode === "ethernet_preferred" || mode === "wifi_preferred") && !ssid) return toast("SSID Wi-Fi obbligatorio per la modalità scelta", false);
      const setupPass = $("#net_setup_password")?.value || "";
      const body = { network_mode: mode, hostname: ($("#net_host")?.value || "").trim(), wifi: { ssid }, setup_ap: { enabled: ($("#net_setup_enabled")?.value || "1") === "1" } };
      if (password) body.wifi.password = password;
      if (setupPass) body.setup_ap.password = setupPass;
      try{ await apiPost("/api/admin/network", body); toast("Configurazione rete salvata"); $("#net_wifi_password") && ($("#net_wifi_password").value = ""); $("#net_setup_password") && ($("#net_setup_password").value = ""); await loadNetwork(); }
      catch(e){ toast("Errore salvataggio rete: " + e.message, false); }
    });
  }

  function normalizeMqttUriForTls(uri, tlsEnabled){
    let value = (uri || "").trim();
    if (!value) return value;
    const targetScheme = tlsEnabled ? "mqtts://" : "mqtt://";
    value = value.replace(/^mqtts?:\/\//i, targetScheme);
    try {
      const parsed = new URL(value);
      const defaultPort = tlsEnabled ? "8883" : "1883";
      if (!parsed.port || parsed.port === (tlsEnabled ? "1883" : "8883")) parsed.port = defaultPort;
      return parsed.toString().replace(/\/$/, "");
    } catch {
      const withoutScheme = value.replace(/^mqtts?:\/\//i, "");
      const hasPort = /:\d+$/.test(withoutScheme);
      return targetScheme + withoutScheme + (hasPort ? "" : (tlsEnabled ? ":8883" : ":1883"));
    }
  }

  function syncMqttTlsUri(){
    const tls = (($("#mq_tls")?.value || "0") === "1");
    const uriEl = $("#mq_uri");
    if (uriEl && uriEl.value.trim()) uriEl.value = normalizeMqttUriForTls(uriEl.value, tls);
  }

  async function loadMqtt(){
    try{
      const c = await apiGet("/api/sys/mqtt");
      $("#mq_enabled") && ($("#mq_enabled").value = (c.mqtt_enabled ?? c.enabled) ? "1" : "0");
      $("#mq_uri")  && ($("#mq_uri").value  = c.broker_uri || c.uri  || "");
      $("#mq_tls") && ($("#mq_tls").value = c.tls_enabled ? "1" : "0");
      $("#mq_cid")  && ($("#mq_cid").value  = c.client_id || c.cid  || "");
      $("#mq_user") && ($("#mq_user").value = c.username || c.user || "");
      $("#mq_tenant") && ($("#mq_tenant").value = c.tenant_id || "default");
      $("#mq_site") && ($("#mq_site").value = c.site_id || "default");
      $("#mq_device") && ($("#mq_device").value = c.device_id || "");
      $("#mq_base") && ($("#mq_base").value = c.base_topic || "");
      $("#mq_discovery") && ($("#mq_discovery").value = (c.ha_discovery_enabled ?? c.discovery_enabled) ? "1" : "0");
      $("#mq_disc_prefix") && ($("#mq_disc_prefix").value = c.discovery_prefix || "homeassistant");
      $("#mq_status") && ($("#mq_status").value = c.connected ? "connesso" : "disconnesso");
      const hasSecret = (typeof c.has_pass === "boolean") ? c.has_pass : (typeof c.pass === "string" && c.pass.length > 0);
      initMqttPasswordField(!!hasSecret);
      $("#mq_keep") && ($("#mq_keep").value = (c.keepalive ?? 60));
    }catch(e){ toast("Errore caricando MQTT: " + e.message, false); }
    ensureMqttRevealButton();
    const tlsSelect = $("#mq_tls");
    if (tlsSelect && !tlsSelect._mqttTlsBound){
      tlsSelect.addEventListener("change", syncMqttTlsUri);
      tlsSelect._mqttTlsBound = true;
    }
    const rediscoverBtn = $("#btnMqttRediscover");
    if (rediscoverBtn && !rediscoverBtn._mqttBound){
      rediscoverBtn.addEventListener("click", async () => {
        try{
          await apiPost("/api/admin/mqtt/rediscover", {});
          toast("Discovery ripubblicata");
        } catch(e){
          toast("Discovery MQTT: " + e.message, false);
        }
      });
      rediscoverBtn._mqttBound = true;
    }
    const saveBtn = $("#btnMqttSave");
    if (saveBtn && !saveBtn._mqttBound){
      saveBtn.addEventListener("click", async ()=>{
        syncMqttTlsUri();
        const tlsEnabled = ($("#mq_tls")?.value || "0") === "1";
        const body = {
          mqtt_enabled: ($("#mq_enabled")?.value || "1") === "1",
          broker_uri: normalizeMqttUriForTls($("#mq_uri")?.value || "", tlsEnabled),
          tls_enabled: tlsEnabled,
          client_id:  $("#mq_cid")?.value  || "",
          username: $("#mq_user")?.value || "",
          keepalive: parseInt($("#mq_keep")?.value || "60", 10) || 60,
          tenant_id: $("#mq_tenant")?.value || "default",
          site_id: $("#mq_site")?.value || "default",
          device_id: $("#mq_device")?.value || "",
          ha_discovery_enabled: ($("#mq_discovery")?.value || "1") === "1",
          discovery_prefix: $("#mq_disc_prefix")?.value || "homeassistant",
        };
        const passField = getMqttPassField();
        const passEdited = passField?.dataset.userEdited === "1";
        if (passEdited){
          body.pass = passField?.value ?? "";
        }
        try{
          const resp = await apiPost("/api/sys/mqtt", body);
          if (resp && resp.ok === false) throw new Error(resp.message || resp.error || "Salvataggio MQTT fallito");
          if (passField){
            if (passEdited){ passField.dataset.hasSecret = body.pass ? "1" : "0"; }
            initMqttPasswordField(passField.dataset.hasSecret === "1");
          }
          await loadMqtt();
          toast(resp?.message || "MQTT salvato");
        }
        catch(e){ toast("Errore salvataggio MQTT: " + e.message, false); }
      });
      saveBtn._mqttBound = true;
    }
  }


  function digitalFiltersStatus(text, isError = false){
    const el = $("#digitalFiltersStatus");
    if (!el) return;
    el.textContent = text || "";
    el.classList.toggle("error", !!isError);
    el.classList.toggle("muted", !isError);
  }

  function readDigitalFiltersForm(){
    const fast = Number.parseInt($("#filterFastMs")?.value ?? "", 10);
    const standard = Number.parseInt($("#filterStandardMs")?.value ?? "", 10);
    const protectedMs = Number.parseInt($("#filterProtectedMs")?.value ?? "", 10);
    if (!Number.isFinite(fast) || !Number.isFinite(standard) || !Number.isFinite(protectedMs)) {
      throw new Error("Inserisci valori numerici interi per tutti i filtri.");
    }
    if (fast < 10 || standard < 20 || protectedMs < 50) {
      throw new Error("Minimi: rapido 10 ms, standard 20 ms, protetto 50 ms.");
    }
    if (fast > 1000 || standard > 1000 || protectedMs > 1000) {
      throw new Error("Il massimo consigliato/accettato è 1000 ms.");
    }
    if (!(fast <= standard && standard <= protectedMs)) {
      throw new Error("Rispetta l'ordine rapido ≤ standard ≤ protetto.");
    }
    return { fast_ms: fast, standard_ms: standard, protected_ms: protectedMs };
  }

  function fillDigitalFiltersForm(filters){
    if ($("#filterFastMs")) $("#filterFastMs").value = String(filters?.fast_ms ?? 40);
    if ($("#filterStandardMs")) $("#filterStandardMs").value = String(filters?.standard_ms ?? 80);
    if ($("#filterProtectedMs")) $("#filterProtectedMs").value = String(filters?.protected_ms ?? 180);
  }

  async function loadDigitalFilters(){
    try{
      digitalFiltersStatus("Caricamento…");
      const data = await apiGet("/api/admin/filters");
      fillDigitalFiltersForm(data?.debounce_filters || data || {});
      digitalFiltersStatus("Filtri caricati.");
      return data;
    }catch(err){
      digitalFiltersStatus("Errore caricando filtri: " + err.message, true);
      throw err;
    }
  }

  function setupDigitalFiltersSection(){
    const reloadBtn = $("#digitalFiltersReloadBtn");
    const saveBtn = $("#digitalFiltersSaveBtn");
    reloadBtn?.addEventListener("click", () => { loadDigitalFilters().catch(()=>{}); });
    saveBtn?.addEventListener("click", async () => {
      try{
        const filters = readDigitalFiltersForm();
        saveBtn.disabled = true;
        digitalFiltersStatus("Salvataggio…");
        await apiPost("/api/admin/filters", { debounce_filters: filters });
        digitalFiltersStatus("Filtri salvati.");
        toast("Filtri digitali salvati");
      }catch(err){
        digitalFiltersStatus(err.message || "Errore durante il salvataggio filtri.", true);
        toast(err.message || "Errore filtri", false);
      }finally{
        saveBtn.disabled = false;
      }
    });
    return loadDigitalFilters().catch(()=>{});
  }

  // ---- Wrapper come da tua init() originale
  async function setupNetMqttForms(){
    await Promise.all([loadNetwork(), loadMqtt()]);
  }

  function renderWebSecStatus(data){
    const box = $("#websecStatus");
    const fb = $("#websecFeedback");
    if (!box) return;
    if (!data){
      box.textContent = "Stato non disponibile";
      if (fb) fb.textContent = "";
      return;
    }
    const activeLabel = data.using_builtin ? "Certificato predefinito incorporato" : "Certificato personalizzato";
    let html = `<div><strong>Attivo:</strong> ${escapeHtml(activeLabel)}</div>`;
    if (data.active_subject) html += `<div class="muted">Soggetto: ${escapeHtml(data.active_subject)}</div>`;
    if (data.active_not_after) html += `<div class="muted">Valido fino al: ${escapeHtml(data.active_not_after)}</div>`;
    if (data.active_fingerprint) html += `<div class="muted">SHA-256: <code>${escapeHtml(data.active_fingerprint)}</code></div>`;
    if (data.custom_available){
      if (data.custom_valid){
        const subj = data.custom_subject ? escapeHtml(data.custom_subject) : "";
        const installed = data.custom_installed_iso ? ` (${escapeHtml(data.custom_installed_iso)})` : "";
        html += `<div class="muted" style="margin-top:.4rem">Ultimo certificato installato: ${subj}${installed}</div>`;
        if (data.custom_not_after) html += `<div class="muted">Scadenza personalizzato: ${escapeHtml(data.custom_not_after)}</div>`;
      } else {
        html += `<div class="muted" style="margin-top:.4rem">Il certificato personalizzato salvato non è valido.</div>`;
      }
    } else {
      html += `<div class="muted" style="margin-top:.4rem">Nessun certificato personalizzato installato.</div>`;
    }
    if (data.restart_pending){
      html += `<div class="muted" style="margin-top:.4rem">Riavvio HTTPS in corso…</div>`;
    }
    box.innerHTML = html;
    if (fb){
      if (data.last_error){
        fb.textContent = `Ultimo errore: ${data.last_error}`;
      } else if (data.restart_pending){
        fb.textContent = "Il server si riavvierà automaticamente per applicare il certificato.";
      } else {
        fb.textContent = "";
      }
    }
  }

  async function loadWebSecStatus(){
    try{
      const data = await apiGet("/api/sys/websec");
      renderWebSecStatus(data);
      return data;
    }catch(err){
      const box = $("#websecStatus");
      if (box) box.textContent = "Errore caricando stato: " + err.message;
      const fb = $("#websecFeedback");
      if (fb) fb.textContent = "";
      throw err;
    }
  }

  async function setupWebSecForm(){
    const btn = $("#btnWebsecUpload");
    if (btn){
      btn.addEventListener("click", async () => {
        const certInput = $("#websecCert");
        const keyInput = $("#websecKey");
        const certFile = certInput?.files?.[0];
        const keyFile = keyInput?.files?.[0];
        if (!certFile || !keyFile){ toast("Seleziona certificato e chiave", false); return; }
        if (certFile.size > WEB_TLS_MAX_PEM_LEN || keyFile.size > WEB_TLS_MAX_PEM_LEN){
          toast("File troppo grandi (max 4 KB)", false);
          return;
        }
        const prevText = btn.textContent;
        btn.disabled = true;
        btn.textContent = "Caricamento…";
        const fb = $("#websecFeedback");
        if (fb) fb.textContent = "Caricamento in corso…";
        try{
          const [certB64, keyB64] = await Promise.all([fileToBase64(certFile), fileToBase64(keyFile)]);
          await apiPost("/api/sys/websec", { cert_b64: certB64, key_b64: keyB64 });
          toast("Certificato aggiornato. Riavvio in corso…");
          if (fb) fb.textContent = "Aggiornamento completato, il server HTTPS si riavvierà automaticamente.";
          setTimeout(() => { loadWebSecStatus().catch(()=>{}); }, 1500);
        }catch(err){
          toast("Aggiornamento certificato: " + err.message, false);
          const fb2 = $("#websecFeedback");
          if (fb2) fb2.textContent = "Errore: " + err.message;
        }finally{
          btn.disabled = false;
          btn.textContent = prevText;
          if ($("#websecCert")) $("#websecCert").value = "";
          if ($("#websecKey")) $("#websecKey").value = "";
        }
      });
    }
    try { await loadWebSecStatus(); } catch {}
  }

  // ========== Logout (eventuale)
  $("#btnLogout")?.addEventListener("click", async () => {
    try{ await apiPost("/api/logout"); }catch{}
    needLogin();
  });

  document.addEventListener('DOMContentLoaded', () => {
    const y = document.getElementById('year');
    if (y) y.textContent = new Date().getFullYear();
  });

  // ========== Init
  (async function init(){
    const me = await apiGet("/api/me");
    currentUser = me.user || "";
    const role = normalizeRole(me.role);
    isAdmin = role != null ? role >= ROLE_ADMIN : !!me.is_admin;
    syncHeader();
    mountUserMenu();
    updateAdminVisibility();
    setupSidebar();
    const setupPromises = [
      setupAdsDiagnostics(),
      setupAnalogGeneralSection(),
      setupDigitalFiltersSection(),
      setupSystemSection(),
      setupNetMqttForms(),
      setupNotificationsSection(),
      setupWebSecForm(),
      setupExpansionsSection()
    ];
    document.querySelector('[data-tab="home"]')?.addEventListener('click', (e) => {
      e.preventDefault();
      location.href = "/index.html";
    });
    if (!(await ensureAdmin())) return;     // ora è un no-op che sblocca la UI
    attachNewUser();
//    await Promise.all([loadUsers(), loadNetwork(), loadMqtt()]);
    await Promise.all([loadUsers(), ...setupPromises]);
  })();
})();
