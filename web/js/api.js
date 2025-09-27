const STORAGE_KEYS = {
  token: 'alarmpro.token',
  systemSuffix: 'alarmpro.systemSuffix',
  apiBase: 'alarmpro.apiBase'
};

const unauthorizedHandlers = new Set();
let tokenCache = '';

export class HttpError extends Error {
  constructor(message, { status = 0, data = null } = {}) {
    super(message || 'HTTP error');
    this.name = 'HttpError';
    this.status = status;
    this.data = data;
  }
}

function safeGet(storage, key){
  try { return storage.getItem(key) || ''; } catch { return ''; }
}
function safeSet(storage, key, value){
  try {
    if (value == null || value === '') storage.removeItem(key);
    else storage.setItem(key, value);
  } catch {}
}

export function sanitizeSystemId(value){
  return (value || '').toLowerCase().replace(/[^a-z0-9-]/g, '');
}

export function formatSystemId(suffix){
  const cleaned = sanitizeSystemId(suffix);
  return cleaned ? `nsalarmpro-${cleaned}` : '';
}

export function getSystemSuffix(){
  return safeGet(window.localStorage, STORAGE_KEYS.systemSuffix) || safeGet(window.sessionStorage, STORAGE_KEYS.systemSuffix) || '';
}

export function getSystemId(){
  const suffix = getSystemSuffix();
  return suffix ? formatSystemId(suffix) : '';
}

function computeOriginForSuffix(suffix){
  const cleaned = sanitizeSystemId(suffix);
  const loc = window.location;
  const protocol = loc.protocol || 'https:';
  const host = loc.hostname || '';
  const port = loc.port ? `:${loc.port}` : '';
  if (!cleaned) {
    return `${protocol}//${host}${port}`;
  }
  const lowerHost = host.toLowerCase();
  const localSuffixes = ['.local', '.lan', '.home'];
  const isLanHostname = localSuffixes.some((suffix) => lowerHost.endsWith(suffix));
  const segments = host.split('.');
  const isIPv4 = segments.length === 4 && segments.every((segment) => {
    if (segment === '' || /[^0-9]/.test(segment)) return false;
    const value = Number(segment);
    return Number.isInteger(value) && value >= 0 && value <= 255;
  });
  const isLocal =
    lowerHost === 'localhost' ||
    lowerHost.startsWith('127.') ||
    isLanHostname ||
    isIPv4;
  if (isLocal) {
    return `${protocol}//${host}${port}`;
  }
  const parts = host.split('.');
  if (parts.length <= 1) {
    return `${protocol}//${host}${port}`;
  }
  const domain = parts.slice(1).join('.');
  return `${protocol}//${formatSystemId(cleaned)}.${domain}`;
}

export function setSystemId(suffix){
  const cleaned = sanitizeSystemId(suffix);
  if (cleaned) {
    safeSet(window.localStorage, STORAGE_KEYS.systemSuffix, cleaned);
    safeSet(window.sessionStorage, STORAGE_KEYS.systemSuffix, cleaned);
  } else {
    safeSet(window.localStorage, STORAGE_KEYS.systemSuffix, '');
    safeSet(window.sessionStorage, STORAGE_KEYS.systemSuffix, '');
  }
  const base = computeOriginForSuffix(cleaned);
  safeSet(window.localStorage, STORAGE_KEYS.apiBase, base);
  safeSet(window.sessionStorage, STORAGE_KEYS.apiBase, base);
  return cleaned;
}

export function getApiBase(){
  const stored = safeGet(window.localStorage, STORAGE_KEYS.apiBase) || safeGet(window.sessionStorage, STORAGE_KEYS.apiBase);
  if (stored) return stored;
  const suffix = getSystemSuffix();
  const base = computeOriginForSuffix(suffix);
  if (base) {
    safeSet(window.localStorage, STORAGE_KEYS.apiBase, base);
    safeSet(window.sessionStorage, STORAGE_KEYS.apiBase, base);
  }
  return base;
}

export function setApiBase(base){
  if (!base) return;
  safeSet(window.localStorage, STORAGE_KEYS.apiBase, base);
  safeSet(window.sessionStorage, STORAGE_KEYS.apiBase, base);
}

export function setToken(token, { persist = true } = {}){
  tokenCache = token || '';
  if (persist) {
    safeSet(window.localStorage, STORAGE_KEYS.token, tokenCache);
    safeSet(window.sessionStorage, STORAGE_KEYS.token, tokenCache);
  } else {
    safeSet(window.localStorage, STORAGE_KEYS.token, '');
    safeSet(window.sessionStorage, STORAGE_KEYS.token, tokenCache);
  }
}

export function getToken(){
  if (tokenCache) return tokenCache;
  const stored = safeGet(window.sessionStorage, STORAGE_KEYS.token) || safeGet(window.localStorage, STORAGE_KEYS.token);
  tokenCache = stored || '';
  return tokenCache;
}

export function clearSession(){
  tokenCache = '';
  safeSet(window.localStorage, STORAGE_KEYS.token, '');
  safeSet(window.sessionStorage, STORAGE_KEYS.token, '');
}

export function onUnauthorized(handler){
  if (typeof handler === 'function') unauthorizedHandlers.add(handler);
  return () => unauthorizedHandlers.delete(handler);
}

function notifyUnauthorized(){
  unauthorizedHandlers.forEach((fn) => {
    try { fn(); } catch (err) { console.error('Unauthorized handler error', err); }
  });
}

function buildUrl(path){
  if (/^https?:\/\//i.test(path)) return path;
  const base = getApiBase() || window.location.origin;
  if (path.startsWith('/')) return `${base}${path}`;
  return `${base}/${path}`;
}

export async function apiRequest(path, { method = 'GET', headers = {}, body, auth = true, raw = false, signal } = {}){
  const init = { method, headers: new Headers(headers), signal, credentials: 'include' };
  if (auth) {
    const token = getToken();
    if (token && !init.headers.has('Authorization')) {
      init.headers.set('Authorization', `Bearer ${token}`);
    }
  }
  const systemId = getSystemId();
  if (systemId && !init.headers.has('X-System-Id')) {
    init.headers.set('X-System-Id', systemId);
  }
  if (body != null) {
    if (typeof body === 'string' || body instanceof FormData || body instanceof Blob) {
      init.body = body;
    } else {
      init.headers.set('Content-Type', 'application/json');
      init.body = JSON.stringify(body);
    }
  }

  const url = buildUrl(path);
  let response;
  try {
    response = await fetch(url, init);
  } catch (err) {
    throw new HttpError('Errore di rete', { status: 0 });
  }

  const contentType = response.headers.get('content-type') || '';
  let payload = null;
  if (contentType.includes('application/json')) {
    try { payload = await response.json(); } catch { payload = null; }
  } else if (!raw) {
    try { payload = await response.text(); } catch { payload = null; }
  }

  if (!response.ok) {
    if (response.status === 401) {
      notifyUnauthorized();
    }
    const message = payload && typeof payload === 'object' && payload !== null && 'message' in payload
      ? payload.message
      : (typeof payload === 'string' && payload.trim() ? payload : response.statusText || 'Errore');
    throw new HttpError(message, { status: response.status, data: payload });
  }

  if (raw) {
    return response;
  }
  return payload;
}

export const apiGet = (path, options = {}) => apiRequest(path, { ...options, method: 'GET' });
export const apiPost = (path, body, options = {}) => apiRequest(path, { ...options, method: 'POST', body });