
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

const state = {
  currentUser: '',
  isAdmin: false,
  status: null,
  zones: [],
  scenes: null,
  logs: []
};

const dateTimeFormatter = new Intl.DateTimeFormat('it-IT', {
  dateStyle: 'short',
  timeStyle: 'medium'
});

const modalsRoot = document.getElementById('modals-root');

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

function setActiveTab(name){
  $$('.tab-btn').forEach((btn) => btn.classList.toggle('active', btn.dataset.tab === name));
  $$('.tab').forEach((section) => section.classList.toggle('active', section.id === `tab-${name}`));
  switch (name) {
    case 'status':
      refreshStatus();
      break;
    case 'zones':
      refreshZones();
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
    const stateEl = document.getElementById('kpi-state-val');
    if (stateEl) renderAlarmState(stateEl, data, { iconHTML: stateIcon(data?.state) });
  } catch (err) {
    console.error('refreshStatus', err);
    showNotice('Impossibile recuperare lo stato.', 'error');
  }
}

function buildZoneBadge(zone){
  const badges = [];
  if (zone?.auto_exclude) badges.push('<span class="badge" title="Autoesclusione">AE</span>');
  if (zone?.zone_delay) badges.push('<span class="badge" title="Ritardo">R</span>');
  if (zone?.zone_time) badges.push(`<span class="badge" title="Tempo">${zone.zone_time}s</span>`);
  return badges.join('');
}

async function refreshZones(){
  try {
    const data = await apiGet('/api/zones');
    state.zones = data;
    const grid = $('#zonesGrid');
    if (!grid) return;
    const zones = Array.isArray(data?.zones) ? data.zones : [];
    if (!zones.length) {
      grid.innerHTML = '<div class="log-empty">Nessuna zona configurata.</div>';
      return;
    }
    grid.innerHTML = zones.map((zone) => {
      const name = escapeHtml(zone?.name || `Z${zone?.id ?? '?'}`);
      const cls = zone?.active ? 'chip on' : 'chip';
      const badges = buildZoneBadge(zone);
      return `
        <div class="card mini">
          <div class="chip ${cls}" title="${name}">
            ${name}
            ${badges ? `<span class="badges">${badges}</span>` : ''}
          </div>
        </div>`;
    }).join('');
  } catch (err) {
    console.error('refreshZones', err);
    showNotice('Errore durante il caricamento delle zone.', 'error');
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
  list.innerHTML = entries.map((entry) => {
    if (typeof entry === 'string') {
      return `<div class="log-entry"><div class="log-body">${escapeHtml(entry)}</div></div>`;
    }
    const message = escapeHtml(entry?.message || entry?.msg || entry?.text || JSON.stringify(entry));
    const level = (entry?.level || entry?.severity || entry?.type || '').toString().toUpperCase();
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
    const entries = normalizeLogs(payload);
    state.logs = entries;
    renderLogEntries(entries);
  } catch (err) {
    console.error('refreshLogs', err);
    showNotice('Impossibile recuperare il log eventi.', 'error');
  }
}

function setupCommands(){
  $$('#commandCards button[data-arm]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const mode = btn.dataset.arm;
      try {
        await apiPost('/api/arm', { mode });
        showNotice(`Comando ${mode?.toUpperCase()} inviato.`, 'info');
        refreshStatus();
      } catch (err) {
        console.error('arm', err);
        showNotice('Errore durante l’invio del comando.', 'error');
      }
    });
  });
  $('#disarmBtn')?.addEventListener('click', async () => {
    try {
      await apiPost('/api/disarm', {});
      showNotice('Centrale disarmata.', 'info');
      refreshStatus();
    } catch (err) {
      console.error('disarm', err);
      showNotice('Errore durante il comando di disarmo.', 'error');
    }
  });
}

function updateAdminVisibility(){
  $$('.admin-only').forEach((el) => {
    el.style.display = state.isAdmin ? '' : 'none';
  });
}

function setupZonesConfig(){
  $('#btnZonesCfg')?.addEventListener('click', () => {
    window.location.href = './admin.html';
  });
}

function clearModals(){
  if (modalsRoot) modalsRoot.innerHTML = '';
  document.body.classList.remove('modal-open');
}

function showModal(innerHtml){
  if (!modalsRoot) return null;
  clearModals();
  modalsRoot.innerHTML = `<div class="modal-overlay"><div class="card modal">${innerHtml}</div></div>`;
  document.body.classList.add('modal-open');
  const overlay = modalsRoot.firstElementChild;
  overlay?.addEventListener('click', (event) => {
    if (event.target === overlay) clearModals();
  });
  return overlay?.querySelector('.modal') || null;
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
  state.isAdmin = !!me?.is_admin;
  const label = $('#userLabel');
  if (label) {
    label.textContent = state.currentUser ? `${state.currentUser}${state.isAdmin ? ' (admin)' : ''}` : '';
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

  $('#logsRefresh')?.addEventListener('click', () => refreshLogs());

  try {
    await loadSession();
  } catch (err) {
    console.error('loadSession', err);
    requireLogin();
    return;
  }

  $('#appRoot')?.classList.remove('hidden');
  setActiveTab('status');
  refreshStatus();
}

init();