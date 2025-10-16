import {
  apiGet,
  apiPost,
  clearSession,
  formatSystemId,
  getSystemSuffix,
  getToken,
  HttpError,
  onUnauthorized
} from './api.js';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const ROLE_ADMIN = 2;

const state = {
  currentUser: '',
  role: null,
  isAdmin: false,
  status: null,
  tamperAlarm: false,
  zones: [],
  boards: [],
  scenes: null,
  logs: [],
  logFilter: 'all',
  activeTab: ''
};

const STATUS_POLL_INTERVAL = 2000;
const ZONESS_POLL_INTERVAL = 2000;
let statusPollTimer = null;
let zonesPollTimer = null;

function stopStatusUpdates(){
  if (statusPollTimer) {
    clearInterval(statusPollTimer);
    statusPollTimer = null;
  }
}

function startStatusUpdates({ immediate = false } = {}){
  if (statusPollTimer || document.hidden || state.activeTab !== 'status') return;
  if (immediate) {
    refreshStatus();
  }
  statusPollTimer = window.setInterval(() => {
    if (document.hidden || state.activeTab !== 'status') {
      stopStatusUpdates();
      return;
    }
    refreshStatus();
  }, STATUS_POLL_INTERVAL);
}

function stopZonesUpdates(){
  if (zonesPollTimer) {
    clearInterval(zonesPollTimer);
    zonesPollTimer = null;
  }
}

function startZonesUpdates({ immediate = false } = {}){
  if (zonesPollTimer || document.hidden || state.activeTab !== 'zones') return;
  if (immediate) {
    refreshZones();
  }
  zonesPollTimer = window.setInterval(() => {
    if (document.hidden || state.activeTab !== 'zones') {
      stopZonesUpdates();
      return;
    }
    refreshZones();
  }, ZONESS_POLL_INTERVAL);
}

const dateTimeFormatter = new Intl.DateTimeFormat('it-IT', {
  dateStyle: 'short',
  timeStyle: 'medium'
});

const modalsRoot = document.getElementById('modals-root');

const boardsCache = {
  list: [],
  map: new Map(),
  pending: null
};

function normalizeBoard(node){
  if (!node) return null;
  const rawId = Number(node?.node_id);
  const nodeId = Number.isFinite(rawId) ? rawId : 0;
  const label = typeof node?.label === 'string' && node.label.trim()
    ? node.label.trim()
    : (nodeId === 0 ? 'Centrale' : `Scheda ${nodeId}`);
  const stateValue = (node?.state || (nodeId === 0 ? 'ONLINE' : 'UNKNOWN')).toString().toUpperCase();
  const inputs = Number(node?.inputs_count);
  return {
    node_id: nodeId,
    label,
    state: stateValue,
    kind: typeof node?.kind === 'string' ? node.kind : '',
    inputs_count: Number.isFinite(inputs) ? inputs : 0
  };
}

function setBoards(nodes){
  const normalized = [];
  if (Array.isArray(nodes)) {
    nodes.forEach((item) => {
      const norm = normalizeBoard(item);
      if (norm) normalized.push(norm);
    });
  }
  if (!normalized.some((item) => item.node_id === 0)) {
    normalized.unshift({ node_id: 0, label: 'Centrale', state: 'ONLINE', kind: 'master', inputs_count: 0 });
  }
  boardsCache.list = normalized;
  boardsCache.map = new Map(normalized.map((item) => [item.node_id, item]));
  state.boards = normalized;
}

function getBoardMeta(boardId){
  const id = Number(boardId);
  const safeId = Number.isFinite(id) ? id : 0;
  return boardsCache.map.get(safeId) || null;
}

function boardLabel(meta, boardId){
  if (meta?.label) return meta.label;
  return boardId === 0 ? 'Centrale' : `Scheda ${boardId}`;
}

function boardStatusDetails(meta){
  const raw = (meta?.state || '').toString().toUpperCase();
  switch (raw) {
    case 'ONLINE':
      return { className: 'online', label: 'Online' };
    case 'OFFLINE':
      return { className: 'offline', label: 'Offline' };
    case 'PREOP':
    case 'PRE-OP':
      return { className: 'preop', label: 'Pre-operativa' };
    default:
      return { className: 'unknown', label: raw && raw !== 'UNKNOWN' ? raw : 'Sconosciuto' };
  }
}

function renderBoardStatus(meta){
  const info = boardStatusDetails(meta);
  return `<span class="board-status ${info.className}">${escapeHtml(info.label)}</span>`;
}

function formatZoneCount(value){
  const count = Number(value) || 0;
  return count === 1 ? '1 zona' : `${count} zone`;
}

function sortBoardIds(a, b){
  if (a === b) return 0;
  if (a === 0) return -1;
  if (b === 0) return 1;
  return a - b;
}

async function ensureBoardsLoaded(force = false){
  if (!force && boardsCache.list.length && !boardsCache.pending) {
    return boardsCache.list;
  }
  if (boardsCache.pending) {
    return boardsCache.pending;
  }
  const request = apiGet('/api/can/nodes')
    .then((nodes) => {
      setBoards(nodes);
      boardsCache.pending = null;
      return boardsCache.list;
    })
    .catch((err) => {
      boardsCache.pending = null;
      throw err;
    });
  boardsCache.pending = request;
  return request;
}

setBoards([]);

function requireLogin(){
  clearSession();
  window.location.replace('./login.html');
}

onUnauthorized(requireLogin);

function setBrandSystem(){
  const label = $('#systemLabel');
  if (label) {
    const suffix = getSystemSuffix();
    label.textContent = suffix ? formatSystemId(suffix) : '';
  }
}

function setBrandCentralName(name){
  const label = document.querySelector('.brand-label');
  if (!label) return;
  const trimmed = (name ?? '').toString().trim();
  label.textContent = trimmed ? `Alarm Pro • ${trimmed}` : 'Alarm Pro';
}

function setActiveTab(name){
  $$('.tab-btn').forEach((btn) => btn.classList.toggle('active', btn.dataset.tab === name));
  $$('.tab').forEach((section) => section.classList.toggle('active', section.id === `tab-${name}`));
  state.activeTab = name;
  if (name !== 'status') {
    stopStatusUpdates();
  } else if (name !== 'zones') {
    stopZonesUpdates();
  }
  switch (name) {
    case 'status':
      refreshStatus();
      startStatusUpdates();
      break;
    case 'zones':
      refreshZones();
      startZonesUpdates();
      break;
    case 'scenes':
      refreshScenes();
      break;
    case 'log':
      refreshLogs();
      break;
    default:
      break;
  }
}

function setupTabs(){
  document.addEventListener('click', (event) => {
    const btn = event.target.closest('.tab-btn');
    if (btn && btn.dataset.tab) {
      setActiveTab(btn.dataset.tab);
    }
  });
}

function showNotice(text, type = 'info'){
  const el = $('#appNotice');
  if (!el) return;
  if (!text) {
    el.textContent = '';
    el.classList.add('hidden');
    return;
  }

  el.textContent = text;
  el.classList.remove('hidden');
  el.style.color = type === 'error' ? '#f87171' : '#a5f3fc';
}

function escapeHtml(str = ''){
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const STATE_LABELS = Object.freeze({
  DISARMED: 'Disarmato',
  ARMED_HOME: 'Attivo in casa',
  ARMED_AWAY: 'Attivo fuori casa',
  ARMED_NIGHT: 'Attivo notte',
  ARMED_CUSTOM: 'Attivo personalizzato',
  ALARM: 'Allarme',
  MAINT: 'Manutenzione',
  PRE_ARM: 'Attivazione in corso',
  PRE_DISARM: 'Pre allarme'
});

function renderAlarmState(el, status, { iconHTML = '' } = {}){
  if (!el || !status) return;
  if (el._blinkTimer) {
    clearInterval(el._blinkTimer);
    el._blinkTimer = null;
  }
  const stateName = status.state;
  const isPre = stateName === 'PRE_ARM' || stateName === 'PRE_DISARM';
  let label = STATE_LABELS[stateName] || stateName || '—';
  if (stateName === 'PRE_DISARM' && Number.isInteger(status.entry_zone)) {
    label += ` (Z${status.entry_zone})`;
  }
  if (!isPre) {
    el.innerHTML = `${iconHTML} ${escapeHtml(label)}`;
    return;
  }
  el.innerHTML = `${iconHTML} <span class="blink">${escapeHtml(label)}</span>`;
  const blinkEl = el.querySelector('.blink');
  el._blinkTimer = setInterval(() => {
    if (!blinkEl || !document.body.contains(blinkEl)) {
      clearInterval(el._blinkTimer);
      el._blinkTimer = null;
      return;
    }
    const on = (Math.floor(Date.now() / 500) % 2) === 0;
    blinkEl.style.opacity = on ? '1' : '0.35';
  }, 250);
}

function stateIcon(state){
  switch (state) {
    case 'DISARMED':
      return '<svg xmlns="http://www.w3.org/2000/svg" class="ico s ok" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="m9 12 2 2 4-4"/><circle cx="12" cy="12" r="9"/></svg>';
    case 'ALARM':
      return '<svg xmlns="http://www.w3.org/2000/svg" class="ico s" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>';
    default:
      return '<svg xmlns="http://www.w3.org/2000/svg" class="ico s" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="9"/></svg>';
  }
}

function kpiCard({ title, valueHTML }){
  return `<div class="card"><div class="kpi"><div class="kpi-title">${escapeHtml(title)}</div><div class="kpi-value">${valueHTML}</div></div></div>`;
}

async function refreshStatus(){
  try {
    const data = await apiGet('/api/status');
    state.status = data;
    state.tamperAlarm = Boolean(data?.tamper_alarm && data?.state === 'ALARM');
    setBrandCentralName(data?.central_name);
    const wrap = $('#statusCards');
    if (!wrap) return;
    const zonesActive = Array.isArray(data?.zones_active) ? data.zones_active.filter(Boolean).length : (data?.zones_active || 0);
    const zonesCount = data?.zones_count || (Array.isArray(data?.zones_active) ? data.zones_active.length : zonesActive);
    const tamper = data?.tamper ? '<span class="tag">TAMPER</span>' : '<span class="tag ok">OK</span>';
    wrap.innerHTML = [
      kpiCard({ title: 'Stato', valueHTML: '<span id="kpi-state-val"></span>' }),
      kpiCard({ title: 'Tamper', valueHTML: tamper }),
      kpiCard({ title: 'Zone attive', valueHTML: `${zonesActive} / ${zonesCount}` })
    ].join('');
    const tamperResetBtn = $('#tamperResetBtn');
    if (tamperResetBtn) {
      const shouldShow = state.tamperAlarm && Boolean(state.currentUser);
      tamperResetBtn.classList.toggle('hidden', !shouldShow);
    }
    const stateEl = document.getElementById('kpi-state-val');
    if (stateEl) renderAlarmState(stateEl, data, { iconHTML: stateIcon(data?.state) });
    if (state.activeTab === 'zones' && !document.hidden) {
      refreshZones();
    }
  } catch (err) {
    console.error('refreshStatus', err);
    showNotice('Impossibile recuperare lo stato.', 'error');
  }
}

function buildZoneBadge(zone){
  const badges = [];
  if (zone?.auto_exclude) badges.push('<span class="badge" title="Autoesclusione">AE</span>');
  if (zone?.zone_delay) badges.push('<span class="badge" title="Ritardo">R</span>');
  const time = Number(zone?.zone_time);
  if (Number.isFinite(time) && time > 0) badges.push(`<span class="badge" title="Tempo">${time}s</span>`);
  return badges.join('');
}

function renderZoneChip(zone){
  const id = Number(zone?.id);
  const boardId = Number(zone?.board);
  const zoneIdLabel = Number.isFinite(id) ? `Z${id}` : 'Z?';
  const nameSuffix = zone?.name ? ` – ${escapeHtml(zone.name)}` : '';
  const display = `${escapeHtml(zoneIdLabel)}${nameSuffix}`;
  const cls = zone?.active ? 'chip on' : 'chip';
  const badges = buildZoneBadge(zone);
  const titleParts = [zoneIdLabel];
  if (zone?.name) titleParts.push(zone.name);
  return `
    <div class="card mini zone-card" data-zone-id="${Number.isFinite(id) ? id : ''}" data-board-id="${Number.isFinite(boardId) ? boardId : 0}">
      <div class="${cls}" title="${escapeHtml(titleParts.join(' • '))}">
        ${display}
        ${badges ? `<span class="badges">${badges}</span>` : ''}
      </div>
    </div>`;
}

function renderBoardSection(boardId, zones){
  const meta = getBoardMeta(boardId);
  const label = escapeHtml(boardLabel(meta, boardId));
  const statusHtml = renderBoardStatus(meta);
  const zoneCount = escapeHtml(formatZoneCount(zones.length));
  const content = zones.length
    ? `<div class="zones-grid">${zones.map((zone) => renderZoneChip(zone)).join('')}</div>`
    : '<div class="log-empty small">Nessuna zona associata.</div>';
  return `
    <section class="board-section" data-board="${boardId}">
      <div class="board-header">
        <h4>${label}</h4>
        <div class="board-meta">
          ${statusHtml}
          <span class="board-count">${zoneCount}</span>
        </div>
      </div>
      ${content}
    </section>`;
}

async function refreshZones(){
  try {
    const data = await apiGet('/api/zones');
    const zones = Array.isArray(data?.zones) ? data.zones : [];
    state.zones = zones;
    const container = $('#zonesBoards');
    if (!container) return;

    try {
      await ensureBoardsLoaded();
    } catch (metaErr) {
      console.warn('boards metadata', metaErr);
    }

    const groups = new Map();
    zones.forEach((zone) => {
      const bid = Number(zone?.board);
      const boardId = Number.isFinite(bid) ? bid : 0;
      const arr = groups.get(boardId) || [];
      arr.push(zone);
      groups.set(boardId, arr);
    });

    for (const arr of groups.values()) {
      arr.sort((a, b) => {
        const ida = Number(a?.id) || 0;
        const idb = Number(b?.id) || 0;
        return ida - idb;
      });
    }

    const boardIdsSet = new Set(boardsCache.list.map((board) => board.node_id));
    for (const boardId of groups.keys()) boardIdsSet.add(boardId);
    const boardIds = Array.from(boardIdsSet).sort(sortBoardIds);

    if (!boardIds.length) {
      container.innerHTML = '<div class="log-empty">Nessuna zona configurata.</div>';
      return;
    }
    container.innerHTML = boardIds.map((boardId) => {
      const list = groups.get(boardId) || [];
      return renderBoardSection(boardId, list);
    }).join('');
  } catch (err) {
    console.error('refreshZones', err);
    showNotice('Errore durante il caricamento delle zone.', 'error');
  }
}

function renderBoardSelectField(selectedId){
  const boards = boardsCache.list.length
    ? [...boardsCache.list]
    : [{ node_id: 0, label: 'Centrale', state: 'ONLINE', kind: 'master', inputs_count: 0 }];
  boards.sort((a, b) => sortBoardIds(Number(a?.node_id) || 0, Number(b?.node_id) || 0));
  const options = boards.map((board) => {
    const rawId = Number(board?.node_id);
    const boardId = Number.isFinite(rawId) ? rawId : 0;
    const selected = boardId === selectedId ? ' selected' : '';
    const label = escapeHtml(boardLabel(board, boardId));
    return `<option value="${boardId}"${selected}>${label}</option>`;
  }).join('');
  return `
    <label class="field">
      <span>Scheda</span>
      <select data-field="board">
        ${options}
      </select>
    </label>`;
}

function renderZoneConfigCard(zone){
  const id = Number(zone?.id);
  const boardId = Number(zone?.board);
  const nameValue = zone?.name ? escapeHtml(zone.name) : '';
  const delayChecked = zone?.zone_delay ? 'checked' : '';
  const autoChecked = zone?.auto_exclude ? 'checked' : '';
  const timeValue = Number(zone?.zone_time);
  const safeTime = Number.isFinite(timeValue) && timeValue > 0 ? timeValue : 0;
  const badges = buildZoneBadge(zone);
  const boardField = renderBoardSelectField(Number.isFinite(boardId) ? boardId : 0);
  return `
    <div class="zone-config-card" data-zone-id="${Number.isFinite(id) ? id : ''}" data-board-id="${Number.isFinite(boardId) ? boardId : 0}">
      <div class="zone-config-card-head">
        <strong>Z${Number.isFinite(id) ? id : '?'}</strong>
        ${badges ? `<span class="badges">${badges}</span>` : ''}
      </div>
      ${boardField}
      <label class="field"><span>Nome</span><input type="text" data-field="name" value="${nameValue}" placeholder="Z${Number.isFinite(id) ? id : ''}"></label>
      <div class="zone-config-options">
        <label class="chk compact"><input type="checkbox" data-field="zone_delay" ${delayChecked}> Ritardo ingresso/uscita</label>
        <label class="chk compact"><input type="checkbox" data-field="auto_exclude" ${autoChecked}> Autoesclusione se aperta</label>
      </div>
      <label class="field"><span>Tempo ritardo (s)</span><input type="number" min="0" max="600" step="1" data-field="zone_time" value="${safeTime}"></label>
    </div>
  `;
}

function renderZonesConfigSection(boardId, zones){
  const meta = getBoardMeta(boardId);
  const label = escapeHtml(boardLabel(meta, boardId));
  const statusHtml = renderBoardStatus(meta);
  const zoneCount = escapeHtml(formatZoneCount(zones.length));
  const body = zones.length
    ? `<div class="zone-config-grid">${zones.map((zone) => renderZoneConfigCard(zone)).join('')}</div>`
    : '<div class="log-empty small">Nessuna zona configurata.</div>';
  return `
    <section class="zone-config-section" data-board="${boardId}">
      <div class="zone-config-section-head">
        <h4>${label}</h4>
        <div class="board-meta">
          ${statusHtml}
          <span class="board-count">${zoneCount}</span>
        </div>
      </div>
      ${body}
    </section>
  `;
}

async function openZonesConfig(){
  try {
    const payload = await apiGet('/api/zones/config');
    const items = Array.isArray(payload?.items) ? payload.items : [];

    try {
      await ensureBoardsLoaded();
    } catch (metaErr) {
      console.warn('boards metadata', metaErr);
    }

    const groups = new Map();
    items.forEach((item) => {
      const bid = Number(item?.board);
      const boardId = Number.isFinite(bid) ? bid : 0;
      const arr = groups.get(boardId) || [];
      arr.push(item);
      groups.set(boardId, arr);
    });

    for (const arr of groups.values()) {
      arr.sort((a, b) => (Number(a?.id) || 0) - (Number(b?.id) || 0));
    }

    const boardIdsSet = new Set(boardsCache.list.map((board) => board.node_id));
    for (const boardId of groups.keys()) boardIdsSet.add(boardId);
    const boardIds = Array.from(boardIdsSet).sort(sortBoardIds);

    const sectionsHtml = boardIds.length
      ? boardIds.map((boardId) => renderZonesConfigSection(boardId, groups.get(boardId) || [])).join('')
      : '<div class="log-empty small">Nessuna zona configurabile.</div>';

    const modal = showModal(`
      <div class="zones-config">
        <div class="zones-config-header">
          <h3>Configurazione zone</h3>
          <button class="btn tiny outline" type="button" id="zonesCfgClose">Chiudi</button>
        </div>
        <div class="zones-config-body">
          ${sectionsHtml}
        </div>
        <div id="zonesCfgMsg" class="msg small hidden"></div>
        <div class="row" style="justify-content:flex-end;gap:.5rem;margin-top:1rem">
          <button class="btn" type="button" id="zonesCfgCancel">Annulla</button>
          <button class="btn primary" type="button" id="zonesCfgSave">Salva</button>
        </div>
      </div>
    `, { modalClass: 'zones-config-modal' });

    if (!modal) return;

    const closeModal = () => { clearModals(); };
    $('#zonesCfgClose', modal)?.addEventListener('click', closeModal);
    $('#zonesCfgCancel', modal)?.addEventListener('click', closeModal);

    const zoneCards = $$('.zone-config-card', modal);
    zoneCards.forEach((card) => {
      const select = $('[data-field="board"]', card);
      if (!select) return;
      const initial = Number(card.dataset.boardId);
      select.value = Number.isFinite(initial) ? String(initial) : '0';
      select.addEventListener('change', () => {
        const value = Number.parseInt(select.value, 10);
        card.dataset.boardId = Number.isFinite(value) ? String(value) : '0';
      });
    });

    $('#zonesCfgSave', modal)?.addEventListener('click', async () => {
      const cards = $$('.zone-config-card', modal);
      const itemsPayload = cards.map((card) => {
        const id = Number(card.dataset.zoneId);
        if (!Number.isFinite(id)) return null;
        const nameInput = $('[data-field="name"]', card);
        const delayInput = $('[data-field="zone_delay"]', card);
        const timeInput = $('[data-field="zone_time"]', card);
        const autoInput = $('[data-field="auto_exclude"]', card);
        // const boardId = Number(card.dataset.boardId);
        const boardSelect = $('[data-field="board"]', card);
        const boardValue = Number.parseInt(boardSelect?.value ?? '', 10);
        return {
          id,
          name: nameInput?.value?.trim() || '',
          zone_delay: !!(delayInput && delayInput.checked),
          zone_time: Math.max(0, Number.parseInt(timeInput?.value ?? '0', 10) || 0),
          auto_exclude: !!(autoInput && autoInput.checked),
          // board: Number.isFinite(boardId) ? boardId : 0
          board: Number.isFinite(boardValue) ? boardValue : 0
        };
      }).filter(Boolean);

      const msg = $('#zonesCfgMsg', modal);
      if (msg) {
        msg.textContent = '';
        msg.classList.add('hidden');
      }

      try {
        await apiPost('/api/zones/config', { items: itemsPayload });
        showNotice('Configurazione zone aggiornata.', 'info');
        clearModals();
        refreshZones();
      } catch (err) {
        console.error('saveZonesConfig', err);
        if (msg) {
          msg.textContent = err instanceof HttpError ? err.message : 'Errore durante il salvataggio.';
          msg.classList.remove('hidden');
          msg.style.color = '#f87171';
        }
      }
    });
  } catch (err) {
    console.error('openZonesConfig', err);
    showNotice('Impossibile leggere la configurazione delle zone.', 'error');
  }
}

function renderSceneCard(name, mask, totalZones){
  const checks = [];
  for (let i = 1; i <= totalZones; i += 1) {
    const bit = 1 << (i - 1);
    const checked = (mask & bit) !== 0 ? 'checked' : '';
    checks.push(`<label class="chk"><input type="checkbox" data-scene="${name}" data-zone="${i}" ${checked}>Z${i}</label>`);
  }
  return `
    <div class="card">
      <div class="card-head"><div class="title"><h2>${escapeHtml(name.toUpperCase())}</h2></div></div>
      <div class="checks">${checks.join('')}</div>
      <div class="actions"><button class="btn small primary" data-save="${name}">Salva</button></div>
    </div>`;
}

async function refreshScenes(){
  try {
    const data = await apiGet('/api/scenes');
    state.scenes = data;
    const root = $('#scenesWrap');
    if (!root) return;
    const total = Number.isInteger(data?.zones) ? data.zones : 0;
    if (!total) {
      root.innerHTML = '<div class="log-empty">Configura almeno una zona per gestire gli scenari.</div>';
      return;
    }
    root.innerHTML = [
      renderSceneCard('home', data?.home ?? 0, total),
      renderSceneCard('night', data?.night ?? 0, total),
      renderSceneCard('custom', data?.custom ?? 0, total)
    ].join('');
    root.querySelectorAll('button[data-save]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const scene = btn.dataset.save;
        const boxes = root.querySelectorAll(`input[type="checkbox"][data-scene="${scene}"]`);
        const ids = Array.from(boxes)
          .filter((input) => input.checked)
          .map((input) => Number(input.dataset.zone))
          .filter((num) => Number.isFinite(num));
        try {
          await apiPost('/api/scenes', { scene, ids });
          showNotice('Scena aggiornata.', 'info');
          refreshScenes();
        } catch (err) {
          console.error('saveScene', err);
          showNotice('Errore durante il salvataggio della scena.', 'error');
        }
      });
    });
  } catch (err) {
    console.error('refreshScenes', err);
    showNotice('Impossibile caricare gli scenari.', 'error');
  }
}

function normalizeLogs(payload){
  if (Array.isArray(payload)) return payload;
  if (payload && Array.isArray(payload.entries)) return payload.entries;
  if (payload && Array.isArray(payload.items)) return payload.items;
  return [];
}

function getLogTimestampValue(entry){
  if (!entry || typeof entry === 'string') return Number.NEGATIVE_INFINITY;
  const raw = entry?.ts ?? entry?.timestamp ?? entry?.time ?? entry?.date;
  if (!raw && raw !== 0) return Number.NEGATIVE_INFINITY;
  if (raw instanceof Date) {
    const value = raw.getTime();
    return Number.isNaN(value) ? Number.NEGATIVE_INFINITY : value;
  }
  if (typeof raw === 'number') {
    const ts = raw > 1e12 ? raw : raw * 1000;
    return Number.isFinite(ts) ? ts : Number.NEGATIVE_INFINITY;
  }
  const parsed = Date.parse(raw);
  return Number.isNaN(parsed) ? Number.NEGATIVE_INFINITY : parsed;
}

function sortLogEntries(entries){
  return entries
    .map((entry, index) => ({ entry, index }))
    .sort((a, b) => {
      const diff = getLogTimestampValue(b.entry) - getLogTimestampValue(a.entry);
      if (diff !== 0) return diff;
      return a.index - b.index;
    })
    .map(({ entry }) => entry);
}

function getLogLevel(entry){
  if (!entry || typeof entry === 'string') return '';
  const level = entry?.level ?? entry?.severity ?? entry?.type;
  return typeof level === 'string' ? level.toUpperCase() : String(level ?? '');
}

function filterLogEntries(entries, filter){
  if (filter === 'all') return entries;
  return entries.filter((entry) => {
    const level = getLogLevel(entry);
    if (!level) return false;
    if (filter === 'info') return level.includes('INFO');
    if (filter === 'warn') return level.includes('WARN');
    if (filter === 'error') return level.includes('ERR');
    return true;
  });
}

function updateLogFilterButtons(){
  $$('#logsFilterGroup button[data-filter]').forEach((btn) => {
    const filter = btn.dataset.filter || 'all';
    btn.classList.toggle('active', filter === state.logFilter);
  });
}

function formatLogTimestamp(value){
  if (!value && value !== 0) return '';
  if (value instanceof Date) return dateTimeFormatter.format(value);
  if (typeof value === 'number') {
    const ts = value > 1e12 ? value : value * 1000;
    const date = new Date(ts);
    return Number.isNaN(date.getTime()) ? '' : dateTimeFormatter.format(date);
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : dateTimeFormatter.format(date);
}

function renderLogEntries(entries){
  const list = $('#logsList');
  if (!list) return;
  if (!entries.length) {
    list.innerHTML = '<div class="log-empty">Nessun evento registrato.</div>';
    return;
  }
  const filtered = filterLogEntries(entries, state.logFilter);
  if (!filtered.length) {
    list.innerHTML = '<div class="log-empty">Nessun evento per il filtro selezionato.</div>';
    return;
  }
  list.innerHTML = filtered.map((entry) => {
    if (typeof entry === 'string') {
      return `<div class="log-entry"><div class="log-body">${escapeHtml(entry)}</div></div>`;
    }
    const message = escapeHtml(entry?.message || entry?.msg || entry?.text || JSON.stringify(entry));
    const level = getLogLevel(entry);
    const ts = formatLogTimestamp(entry?.ts ?? entry?.timestamp ?? entry?.time ?? entry?.date);
    const levelTag = level ? `<span class="tag ${level.includes('ERR') ? 'err' : level.includes('WARN') ? 'warn' : ''}">${level}</span>` : '';
    return `
      <div class="log-entry">
        <div class="log-meta">
          <span>${escapeHtml(ts || '—')}</span>
          ${levelTag}
        </div>
        <div class="log-body">${message}</div>
      </div>`;
  }).join('');
}

async function refreshLogs(){
  try {
    const payload = await apiGet('/api/logs');
    const entries = sortLogEntries(normalizeLogs(payload));
    state.logs = entries;
    renderLogEntries(entries);
  } catch (err) {
    console.error('refreshLogs', err);
    showNotice('Impossibile recuperare il log eventi.', 'error');
  }
}

function setupLogFilters(){
  const group = $('#logsFilterGroup');
  if (!group) return;
  group.addEventListener('click', (event) => {
    const btn = event.target.closest('button[data-filter]');
    if (!btn) return;
    const filter = btn.dataset.filter || 'all';
    if (state.logFilter === filter) return;
    state.logFilter = filter;
    updateLogFilterButtons();
    if (state.logs.length) {
      renderLogEntries(state.logs);
    }
  });
  updateLogFilterButtons();
}

function setupCommands(){
  $$('#commandCards button[data-arm]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const mode = btn.dataset.arm;
      const pin = await promptForPin({
        title: 'Inserisci PIN per attivare',
        confirmLabel: 'Attiva',
        description: mode ? `Modalità: ${mode.toUpperCase()}` : ''
      });
      if (pin == null) {
        return;
      }
      try {
        await apiPost('/api/arm', { mode, pin });
        showNotice(`Comando ${mode?.toUpperCase()} inviato.`, 'info');
        refreshStatus();
        if (state.activeTab === 'zones') {
          refreshZones();
        }
      } catch (err) {
        console.error('arm', err);
        if (err instanceof HttpError) {
          if (err.status === 401) {
            showNotice('PIN errato.', 'error');
          } else if (err.status === 409) {
            showNotice('Impossibile attivare: zone aperte.', 'error');
          } else {
            showNotice(err.message || 'Errore durante l’invio del comando.', 'error');
          }
        } else {
          showNotice('Errore durante l’invio del comando.', 'error');
        }
      }
    });
  });
  $('#disarmBtn')?.addEventListener('click', async () => {
    if (state.status?.state === 'DISARMED') {
      showNotice('La centrale è già disarmata.', 'info');
      return;
    }
    const pin = await promptForPin({
      title: 'Inserisci PIN per disattivare',
      confirmLabel: 'Disattiva'
    });
    if (pin == null) {
      return;
    }
    try {
      await apiPost('/api/disarm', { pin });
      showNotice('Centrale disarmata.', 'info');
      refreshStatus();
      if (state.activeTab === 'zones') {
        refreshZones();
      }
    } catch (err) {
      console.error('disarm', err);
      if (err instanceof HttpError) {
        if (err.status === 401) {
          showNotice('PIN errato.', 'error');
        } else if (err.status === 409) {
          showNotice('Impossibile disarmare: zone aperte.', 'error');
        } else {
          showNotice(err.message || 'Errore durante il comando di disarmo.', 'error');
        }
      } else {
        showNotice('Errore durante il comando di disarmo.', 'error');
      }
    }
  });

  $('#tamperResetBtn')?.addEventListener('click', async () => {
    const password = await promptForPassword({
      title: 'Reset allarme tamper',
      confirmLabel: 'Reset',
      description: 'Inserisci la tua password per ripristinare la centrale.'
    });
    if (password == null) {
      return;
    }
    if (state.status?.tamper) {
      showNotice('Linea tamper ancora aperta. Chiudi il contatto prima di resettare.', 'error');
      return;
    }
    try {
      await apiPost('/api/tamper/reset', { password });
      showNotice('Allarme tamper resettato.', 'info');
      refreshStatus();
    } catch (err) {
      console.error('tamperReset', err);
      if (err instanceof HttpError) {
        if (err.status === 403) {
          showNotice('Password errata.', 'error');
        } else if (err.status === 409) {
          showNotice(err.message || 'Impossibile resettare: verifica lo stato del tamper.', 'error');
        } else {
          showNotice(err.message || 'Errore durante il reset tamper.', 'error');
        }
      } else {
        showNotice('Errore durante il reset tamper.', 'error');
      }
    }
  });
}

function normalizeRole(roleValue){
  if (typeof roleValue === 'number') return Number.isNaN(roleValue) ? null : roleValue;
  if (typeof roleValue === 'string' && roleValue.trim() !== '') {
    const parsed = Number.parseInt(roleValue, 10);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

function updateAdminVisibility(){
  document.body.classList.toggle('is-admin', state.isAdmin);
  $$('.admin-only').forEach((el) => {
    el.classList.toggle('hidden', !state.isAdmin);
    el.style.removeProperty('display');
  });
}

function setupZonesConfig(){
  $('#btnZonesCfg')?.addEventListener('click', () => {
    if (!state.isAdmin) return;
    openZonesConfig();
  });
}

function clearModals(){
  if (modalsRoot) modalsRoot.innerHTML = '';
  document.body.classList.remove('modal-open');
}

function showModal(innerHtml, options = {}){
  if (!modalsRoot) return null;
  clearModals();
  const modalClass = options.modalClass ? ` ${options.modalClass}` : '';
  modalsRoot.innerHTML = `<div class="modal-overlay"><div class="card modal${modalClass}">${innerHtml}</div></div>`;
  document.body.classList.add('modal-open');
  const overlay = modalsRoot.firstElementChild;
  overlay?.addEventListener('click', (event) => {
    if (event.target === overlay && !event.defaultPrevented) clearModals();
  });
  return overlay?.querySelector('.modal') || null;
}

function promptForPin({
  title = 'Inserisci PIN',
  confirmLabel = 'Conferma',
  description = ''
} = {}){
  return new Promise((resolve) => {
    const modal = showModal(`
      <h3 class="title">${escapeHtml(title)}</h3>
      ${description ? `<p class="muted">${escapeHtml(description)}</p>` : ''}
      <form class="form" id="pin_form">
        <label class="field"><span>PIN</span><input id="pin_input" type="password" inputmode="numeric" autocomplete="one-time-code"></label>
        <div class="row" style="justify-content:flex-end;gap:.5rem">
          <button type="button" class="btn secondary" data-act="cancel">Annulla</button>
          <button type="submit" class="btn primary" data-act="confirm">${escapeHtml(confirmLabel)}</button>
        </div>
      </form>
    `);
    if (!modal) {
      resolve(null);
      return;
    }

    const overlay = modal.parentElement;
    const form = modal.querySelector('#pin_form');
    const input = modal.querySelector('#pin_input');
    const cancelBtn = modal.querySelector('[data-act="cancel"]');
    let done = false;

    const cleanup = () => {
      modal.removeEventListener('keydown', onKeyDown);
      overlay?.removeEventListener('click', onOverlayClick, true);
      cancelBtn?.removeEventListener('click', onCancel);
      form?.removeEventListener('submit', onSubmit);
    };

    const close = (value) => {
      if (done) return;
      done = true;
      cleanup();
      clearModals();
      resolve(value);
    };

    const onKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        close(null);
      }
    };

    const onOverlayClick = (event) => {
      if (event.target === overlay) {
        event.preventDefault();
        close(null);
      }
    };

    const onCancel = (event) => {
      event.preventDefault();
      close(null);
    };

    const onSubmit = (event) => {
      event.preventDefault();
      const pin = (input?.value ?? '').trim();
      if (!pin) {
        input?.focus();
        return;
      }
      close(pin);
    };

    modal.addEventListener('keydown', onKeyDown);
    overlay?.addEventListener('click', onOverlayClick, true);
    cancelBtn?.addEventListener('click', onCancel);
    form?.addEventListener('submit', onSubmit);

    setTimeout(() => {
      input?.focus();
      input?.select();
    }, 0);
  });
}

function promptForPassword({
  title = 'Password utente',
  confirmLabel = 'Conferma',
  description = ''
} = {}){
  return new Promise((resolve) => {
    const modal = showModal(`
      <h3 class="title">${escapeHtml(title)}</h3>
      ${description ? `<p class="muted">${escapeHtml(description)}</p>` : ''}
      <form class="form" id="user_pw_form">
        <label class="field"><span>Password</span><input id="user_pw_input" type="password" autocomplete="current-password"></label>
        <div class="row" style="justify-content:flex-end;gap:.5rem">
          <button type="button" class="btn secondary" data-act="cancel">Annulla</button>
          <button type="submit" class="btn primary" data-act="confirm">${escapeHtml(confirmLabel)}</button>
        </div>
      </form>
    `);
    if (!modal) {
      resolve(null);
      return;
    }

    const overlay = modal.parentElement;
    const form = modal.querySelector('#user_pw_form');
    const input = modal.querySelector('#user_pw_input');
    const cancelBtn = modal.querySelector('[data-act="cancel"]');
    let done = false;

    const cleanup = () => {
      modal.removeEventListener('keydown', onKeyDown);
      overlay?.removeEventListener('click', onOverlayClick, true);
      cancelBtn?.removeEventListener('click', onCancel);
      form?.removeEventListener('submit', onSubmit);
    };

    const close = (value) => {
      if (done) return;
      done = true;
      cleanup();
      clearModals();
      resolve(value);
    };

    const onKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        close(null);
      }
    };

    const onOverlayClick = (event) => {
      if (event.target === overlay) {
        event.preventDefault();
        close(null);
      }
    };

    const onCancel = (event) => {
      event.preventDefault();
      close(null);
    };

    const onSubmit = (event) => {
      event.preventDefault();
      const password = input?.value ?? '';
      if (!password) {
        input?.focus();
        return;
      }
      close(password);
    };

    modal.addEventListener('keydown', onKeyDown);
    overlay?.addEventListener('click', onOverlayClick, true);
    cancelBtn?.addEventListener('click', onCancel);
    form?.addEventListener('submit', onSubmit);

    setTimeout(() => {
      input?.focus();
      input?.select();
    }, 0);
  });
}

function ensureQRCode(target, text){
  if (!target) return;
  try {
    target.innerHTML = '';
    if (window.QRCode) {
      new window.QRCode(target, { text, width: 160, height: 160, correctLevel: window.QRCode.CorrectLevel.M });
    } else {
      target.textContent = text || '';
    }
  } catch (err) {
    console.warn('QRCode error', err);
    target.textContent = text || '';
  }
}

async function showUserSettings(){
  let totp = { enabled: false };
  try {
    totp = await apiGet('/api/user/totp');
  } catch (err) {
    console.warn('totp info', err);
  }
  const modal = showModal(`
    <h3 class="title">Impostazioni utente</h3>
    <div class="form">
      <h4>Cambia password</h4>
      <label class="field"><span>Password attuale</span><input id="pw_cur" type="password" autocomplete="current-password"></label>
      <label class="field"><span>Nuova password</span><input id="pw_new" type="password" autocomplete="new-password"></label>
      <div class="row" style="justify-content:flex-end"><button class="btn small primary" id="pw_save">Salva</button></div>
      <div id="pw_msg" class="msg small hidden"></div>
    </div>
    <hr style="border:0;border-top:1px solid rgba(255,255,255,.06);margin:1rem 0">
    <div class="form" id="totp_block">
      <h4>Autenticazione a due fattori</h4>
      <p class="muted" id="totp_state">${totp?.enabled ? '2FA attiva' : '2FA non attiva'}</p>
      <div class="row" id="totp_actions" style="gap:.5rem;justify-content:flex-end"></div>
      <div id="totp_setup" class="hidden"></div>
      <div id="totp_msg" class="msg small hidden"></div>
    </div>
    <div class="row" style="justify-content:flex-end;margin-top:1rem"><button class="btn secondary" id="settings_close">Chiudi</button></div>
  `);
  if (!modal) return;

  const pwMsg = $('#pw_msg', modal);
  $('#pw_save', modal)?.addEventListener('click', async () => {
    const current = $('#pw_cur', modal)?.value || '';
    const next = $('#pw_new', modal)?.value || '';
    if (!current || !next) {
      if (pwMsg) {
        pwMsg.textContent = 'Compila tutti i campi.';
        pwMsg.classList.remove('hidden');
        pwMsg.style.color = '#f87171';
      }
      return;
    }
    try {
      await apiPost('/api/user/password', { current, newpass: next });
      if (pwMsg) {
        pwMsg.textContent = 'Password aggiornata.';
        pwMsg.classList.remove('hidden');
        pwMsg.style.color = '#34d399';
      }
      $('#pw_cur', modal).value = '';
      $('#pw_new', modal).value = '';
    } catch (err) {
      if (pwMsg) {
        pwMsg.textContent = err instanceof HttpError ? err.message : 'Errore durante l’aggiornamento.';
        pwMsg.classList.remove('hidden');
        pwMsg.style.color = '#f87171';
      }
    }
  });

  function updateTotpActions(info){
    const actions = $('#totp_actions', modal);
    const setup = $('#totp_setup', modal);
    const msg = $('#totp_msg', modal);
    const stateLabel = $('#totp_state', modal);
    if (!actions || !stateLabel) return;
    actions.innerHTML = '';
    setup?.classList.add('hidden');
    if (msg) msg.classList.add('hidden');
    if (info?.enabled) {
      stateLabel.textContent = '2FA attiva';
      const btn = document.createElement('button');
      btn.className = 'btn small';
      btn.textContent = 'Disattiva 2FA';
      btn.addEventListener('click', async () => {
        try {
          await apiPost('/api/user/totp/disable', {});
          updateTotpActions({ enabled: false });
        } catch (err) {
          if (msg) {
            msg.textContent = 'Errore durante la disattivazione.';
            msg.classList.remove('hidden');
            msg.style.color = '#f87171';
          }
        }
      });
      actions.appendChild(btn);
    } else {
      stateLabel.textContent = '2FA non attiva';
      const btn = document.createElement('button');
      btn.className = 'btn small primary';
      btn.textContent = 'Abilita 2FA';
      btn.addEventListener('click', async () => {
        try {
          const info = await apiPost('/api/user/totp/enable', {});
          if (setup) {
            setup.classList.remove('hidden');
            setup.innerHTML = `
              <p>Scansiona il QR con la tua app di autenticazione.</p>
              <div class="row" style="align-items:flex-start;gap:1rem;margin:.75rem 0">
                <div id="totp_qr" class="card" style="padding:.6rem"></div>
                <div class="card" style="padding:.6rem;max-width:100%;overflow:auto"><code>${escapeHtml(info?.otpauth_uri || '')}</code></div>
              </div>
              <label class="field"><span>Codice OTP</span><input id="totp_code" inputmode="numeric" maxlength="6" autocomplete="one-time-code"></label>
              <div class="row" style="justify-content:flex-end"><button class="btn small primary" id="totp_confirm">Conferma</button></div>
            `;
            ensureQRCode($('#totp_qr', setup), info?.otpauth_uri || '');
            $('#totp_confirm', setup)?.addEventListener('click', async () => {
              const otp = $('#totp_code', setup)?.value.trim();
              if (!otp) {
                if (msg) {
                  msg.textContent = 'Inserisci il codice OTP.';
                  msg.classList.remove('hidden');
                  msg.style.color = '#f87171';
                }
                return;
              }
              try {
                await apiPost('/api/user/totp/confirm', { otp });
                if (msg) {
                  msg.textContent = '2FA abilitata con successo.';
                  msg.classList.remove('hidden');
                  msg.style.color = '#34d399';
                }
                updateTotpActions({ enabled: true });
              } catch (err) {
                if (msg) {
                  const text = err instanceof HttpError && err.status === 409 ? 'Codice non valido o fuori tempo.' : 'Errore durante la conferma.';
                  msg.textContent = text;
                  msg.classList.remove('hidden');
                  msg.style.color = '#f87171';
                }
              }
            });
          }
        } catch (err) {
          if (msg) {
            msg.textContent = 'Errore durante l’abilitazione della 2FA.';
            msg.classList.remove('hidden');
            msg.style.color = '#f87171';
          }
        }
      });
      actions.appendChild(btn);
    }
  }

  updateTotpActions(totp);

  $('#settings_close', modal)?.addEventListener('click', () => {
    clearModals();
  });
}

function setupUserMenu(){
  const btn = $('#userBtn');
  const dropdown = $('#userDropdown');
  if (!btn || !dropdown) return;
  btn.addEventListener('click', (event) => {
    event.stopPropagation();
    dropdown.classList.toggle('hidden');
  });
  document.addEventListener('click', () => dropdown.classList.add('hidden'));
  dropdown.querySelector('[data-act="settings"]')?.addEventListener('click', () => {
    dropdown.classList.add('hidden');
    showUserSettings();
  });
  dropdown.querySelector('[data-act="sys_settings"]')?.addEventListener('click', () => {
    dropdown.classList.add('hidden');
    window.location.href = './admin.html';
  });
  dropdown.querySelector('[data-act="logout"]')?.addEventListener('click', async () => {
    dropdown.classList.add('hidden');
    try {
      await apiPost('/api/logout', {});
    } catch (err) {
      console.warn('logout', err);
    }
    requireLogin();
  });
}

async function loadSession(){
  const me = await apiGet('/api/me');
  state.currentUser = me?.user || '';
  const role = normalizeRole(me?.role);
  state.role = role;
  const fallbackAdmin = !!me?.is_admin;
  state.isAdmin = role != null ? role >= ROLE_ADMIN : fallbackAdmin;
  const label = $('#userLabel');
  if (label) {
    if (!state.currentUser) {
      label.textContent = '';
    } else {
      const userHtml = `<span class="user-name">${escapeHtml(state.currentUser)}</span>`;
      const roleHtml = state.isAdmin ? ' <span class="user-role tag warn">ADMIN</span>' : '';
      label.innerHTML = `${userHtml}${roleHtml}`;
    }
  }
  updateAdminVisibility();
}

async function init(){
  if (!getToken() || !getSystemSuffix()) {
    requireLogin();
    return;
  }

  document.getElementById('year').textContent = String(new Date().getFullYear());
  setBrandSystem();
  setupTabs();
  setupCommands();
  setupZonesConfig();
  setupUserMenu();
  setupLogFilters();

  $('#logsRefresh')?.addEventListener('click', () => refreshLogs());
  $('#logsClear')?.addEventListener('click', async () => {
    if (!state.isAdmin) return;
    if (!window.confirm('Sei sicuro di voler cancellare tutti i log?')) {
      return;
    }
    try {
      await apiPost('/api/logs/clear', {});
      state.logs = [];
      renderLogEntries([]);
      showNotice('Log cancellati con successo.', 'info');
    } catch (err) {
      console.error('logsClear', err);
      showNotice('Impossibile cancellare il log eventi.', 'error');
    }
  });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      stopStatusUpdates();
      stopZonesUpdates();
    } else if (state.activeTab === 'status') {
      startStatusUpdates({ immediate: true });
    } else if (state.activeTab === 'zones') {
      startZonessUpdates({ immediate: true });
    }
  });
  window.addEventListener('pagehide', () => {    
    stopStatusUpdates();
    stopZonesUpdates();    
  });
  window.addEventListener('beforeunload', () => {    
    stopStatusUpdates();
    stopZonesUpdates();    
  });

  try {
    await loadSession();
  } catch (err) {
    console.error('loadSession', err);
    requireLogin();
    return;
  }

  ensureBoardsLoaded().catch((err) => console.warn('boards metadata', err));

  $('#appRoot')?.classList.remove('hidden');
  setActiveTab('status');
}

init();