import {
  apiGet,
  apiRequest,
  clearSession,
  formatSystemId,
  getSystemSuffix,
  getToken,
  HttpError,
  sanitizeSystemId,
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
const messageEl = document.getElementById('loginMessage');
const footYear = document.getElementById('footYear');

let otpRequired = false;
let pendingRequest = false;

if (footYear) footYear.textContent = String(new Date().getFullYear());

const savedSuffix = getSystemSuffix();
if (savedSuffix) {
  systemInput.value = savedSuffix;
}

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
  [systemInput, userInput, passInput, otpInput, submitBtn].forEach((el) => {
    if (el) el.disabled = disabled;
  });
  if (submitBtn) submitBtn.textContent = disabled ? 'Attendere…' : 'Accedi';
}

function showOtpField(){
  otpRequired = true;
  if (otpField) otpField.classList.remove('hidden');
  if (otpInput) {
    otpInput.required = true;
    otpInput.focus();
  }
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
    if (otpRequired) {
      payload.otp = otp;
    }
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
    setMessage('Autenticazione riuscita.', 'success');
    window.location.replace('./index.html');
  } catch (err) {
    if (err instanceof HttpError) {
      if (err.status === 401 && err.data && err.data.otp_required) {
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