import {
  apiGet,
  apiRequest,
  clearSession,
  formatSystemId,
  getSystemSuffix,
  getToken,
  HttpError,
  sanitizeSystemId,
  setApiBase,
  setSystemId,
  setToken
} from './api.js';

const form = document.getElementById('loginForm');
const systemInput = document.getElementById('systemId');
const userInput = document.getElementById('username');
const passInput = document.getElementById('password');
const otpField = document.getElementById('otpField');
const otpInput = document.getElementById('otp');
const submitBtn = document.getElementById('loginSubmit');
const recoveryField = document.getElementById('recoveryField');
const recoveryInput = document.getElementById('recoveryCode');
const fallbackActions = document.getElementById('fallbackActions');
const btnSetupLimited = document.getElementById('btnSetupLimited');
const btnBrowserTime = document.getElementById('btnBrowserTime');
const btnUseRecovery = document.getElementById('btnUseRecovery');
const messageEl = document.getElementById('loginMessage');
const footYear = document.getElementById('footYear');

let otpRequired = false;
let pendingRequest = false;
let recoveryMode = false;
let setupLimitedMode = false;
let lanSystemLocked = false;

if (footYear) footYear.textContent = String(new Date().getFullYear());

const savedSuffix = getSystemSuffix();
if (savedSuffix) {
  systemInput.value = savedSuffix;
}

function updateSystemInputLock(){
  if (!systemInput) return;
  if (lanSystemLocked) {
    systemInput.readOnly = true;
    systemInput.setAttribute('aria-readonly', 'true');
    systemInput.classList.add('input-readonly');
  } else {
    systemInput.readOnly = false;
    systemInput.removeAttribute('aria-readonly');
    systemInput.classList.remove('input-readonly');
  }
}

function isLanHostname(hostname){
  const value = (hostname || '').toLowerCase();
  if (!value) return false;
  if (value === 'localhost' || value === '::1') return true;
  if (value.startsWith('127.')) return true;
  const localSuffixes = ['.local', '.lan', '.home'];
  if (localSuffixes.some((suffix) => value.endsWith(suffix))) return true;
  if (value.includes(':')) {
    return value.startsWith('fe80:') || value.startsWith('fd') || value.startsWith('fc');
  }
  const segments = value.split('.');
  if (segments.length !== 4) return false;
  const octets = segments.map((segment) => {
    if (segment === '' || /[^0-9]/.test(segment)) return -1;
    const number = Number(segment);
    return Number.isInteger(number) ? number : -1;
  });
  if (octets.some((octet) => octet < 0 || octet > 255)) return false;
  const [a, b] = octets;
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

function extractSuffixFromHostname(hostname){
  if (!hostname) return '';
  const lower = hostname.toLowerCase();
  const prefix = 'nsalarmpro-';
  if (!lower.startsWith(prefix)) return '';
  const remainder = lower.slice(prefix.length);
  const stopIndex = remainder.indexOf('.');
  const raw = stopIndex >= 0 ? remainder.slice(0, stopIndex) : remainder;
  return sanitizeSystemId(raw);
}

function enforceLanSystemId(suffix){
  const cleaned = sanitizeSystemId(suffix);
  if (!systemInput || !cleaned) return;
  systemInput.value = cleaned;
  lanSystemLocked = true;
  updateSystemInputLock();
  setSystemId(cleaned);
}

async function initializeSystemId(){
  if (!systemInput || typeof window === 'undefined' || !window.location) return;
  const hostname = window.location.hostname || '';
  if (!isLanHostname(hostname)) return;

  setApiBase(window.location.origin);

  const hostSuffix = extractSuffixFromHostname(hostname);
  if (hostSuffix) {
    enforceLanSystemId(hostSuffix);
    return;
  }

  try {
    const response = await fetch(`${window.location.origin}/api/provision/status`, {
      credentials: 'include'
    });
    if (!response.ok) return;
    const data = await response.json().catch(() => null);
    if (!data || typeof data !== 'object') return;
    const deviceId = typeof data.device_id === 'string' ? data.device_id.trim() : '';
    if (!deviceId) return;
    const normalized = deviceId.toLowerCase().startsWith('nsalarmpro-')
      ? deviceId.slice('nsalarmpro-'.length)
      : deviceId;
    enforceLanSystemId(normalized);
  } catch (err) {
    console.warn('Impossibile recuperare ID sistema via LAN', err);
  }
}

initializeSystemId();

(async () => {
  if (getToken() && getSystemSuffix()) {
    try {
      await apiGet('/api/me');
      window.location.replace('./index.html');
    } catch {
      clearSession();
    }
  }
})();

function setMessage(text, type = 'error'){
  if (!messageEl) return;
  if (!text) {
    messageEl.textContent = '';
    messageEl.classList.add('hidden');
    return;
  }
  messageEl.textContent = text;
  messageEl.classList.remove('hidden');
  messageEl.style.color = type === 'success' ? '#22d3ee' : '#f87171';
}

function setDisabled(disabled){
  [userInput, passInput, otpInput, recoveryInput, submitBtn, btnSetupLimited, btnBrowserTime, btnUseRecovery].forEach((el) => {
    if (el) el.disabled = disabled;
  });
  if (systemInput) {
    systemInput.disabled = disabled;
    if (!disabled) {
      updateSystemInputLock();
    }
  }
  if (submitBtn) submitBtn.textContent = disabled ? 'Attendere…' : 'Accedi';
}

function hideFallbackChoices(){
  if (fallbackActions) fallbackActions.classList.add('hidden');
}

function showRecoveryField(){
  recoveryMode = true;
  setupLimitedMode = false;
  if (recoveryField) recoveryField.classList.remove('hidden');
  if (recoveryInput) { recoveryInput.required = true; recoveryInput.focus(); }
  if (otpField) otpField.classList.add('hidden');
  setMessage('Inserisci un codice di recupero monouso.');
}

function showTimeInvalidFallback(message){
  otpRequired = false;
  recoveryMode = false;
  setupLimitedMode = false;
  if (otpField) otpField.classList.add('hidden');
  if (fallbackActions) fallbackActions.classList.remove('hidden');
  setMessage(message || 'La centrale non ha un orario valido. Puoi configurare la rete, sincronizzare l\'ora da questo dispositivo o usare un codice di recupero.');
}

function showOtpField(){
  otpRequired = true;
  if (otpField) otpField.classList.remove('hidden');
  if (otpInput) {
    otpInput.required = true;
    otpInput.focus();
  }
  hideFallbackChoices();
  if (recoveryField) recoveryField.classList.add('hidden');
  if (recoveryInput) recoveryInput.required = false;
  setMessage('Inserisci il codice OTP generato dalla tua app.');
}

function markInvalid(input){
  if (!input) return;
  input.classList.add('input-error');
  input.addEventListener('input', () => input.classList.remove('input-error'), { once: true });
}

form?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (pendingRequest) return;

  const rawSuffix = systemInput?.value.trim() || '';
  const suffix = sanitizeSystemId(rawSuffix);
  const user = userInput?.value.trim() || '';
  const pass = passInput?.value || '';
  const otp = otpInput?.value.trim() || '';
  const recoveryCode = recoveryInput?.value.trim() || '';

  if (!suffix) {
    setMessage('Inserisci un ID sistema valido.');
    markInvalid(systemInput);
    return;
  }
  if (systemInput) systemInput.value = suffix;
  if (!user) {
    setMessage('Inserisci username.');
    markInvalid(userInput);
    return;
  }
  if (!pass) {
    setMessage('Inserisci password.');
    markInvalid(passInput);
    return;
  }
  if (recoveryMode && !recoveryCode) {
    setMessage('Inserisci il codice di recupero.');
    markInvalid(recoveryInput);
    return;
  }
  if (otpRequired && !otp) {
    setMessage('Inserisci il codice OTP.');
    markInvalid(otpInput);
    return;
  }

  setMessage('');
  setDisabled(true);
  pendingRequest = true;

  try {
    setSystemId(suffix);
    const payload = { user, pass, system_id: formatSystemId(suffix) };
    if (otpRequired) payload.otp = otp;
    if (recoveryMode) payload.recovery_code = recoveryCode;
    if (setupLimitedMode) payload.setup_limited = true;
    const response = await apiRequest('/api/login', { method: 'POST', body: payload, auth: false });
    if (response && typeof response === 'object' && response.otp_required && !response.token) {
      showOtpField();
      return;
    }
    const token = response && typeof response === 'object' ? response.token : null;
    if (!token) {
      throw new HttpError('Token non ricevuto dal server', { status: 500 });
    }
    setToken(token);
    setMessage(response.message || 'Autenticazione riuscita.', 'success');
    window.location.replace(response.redirect || './index.html');
  } catch (err) {
    if (err instanceof HttpError) {
      if (err.status === 401 && err.data && err.data.requires_setup_limited) {
        showTimeInvalidFallback(err.data.message);
      } else if (err.status === 401 && err.data && err.data.otp_required) {
        showOtpField();
      } else if (err.status === 401 || err.status === 403) {
        setMessage('Credenziali non valide.');
      } else {
        const msg = err.message || 'Errore del server.';
        setMessage(msg);
      }
    } else {
      setMessage('Impossibile contattare il server.');
    }
  } finally {
    pendingRequest = false;
    setDisabled(false);
  }
});

btnUseRecovery?.addEventListener('click', () => showRecoveryField());
btnSetupLimited?.addEventListener('click', () => { setupLimitedMode = true; recoveryMode = false; otpRequired = false; form?.requestSubmit(); });
btnBrowserTime?.addEventListener('click', async () => {
  try {
    const unix_time = Math.floor(Date.now() / 1000);
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'browser';
    await apiRequest('/api/setup/time', { method: 'POST', body: { unix_time, timezone }, auth: true });
    hideFallbackChoices();
    showOtpField();
    setMessage('Ora sincronizzata da browser. Inserisci OTP per completare accesso admin.', 'success');
  } catch (err) {
    setMessage('Sincronizzazione ora non disponibile: prima entra in modalità Configura rete.');
  }
});