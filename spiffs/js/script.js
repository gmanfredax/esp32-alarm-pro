const DEFAULT_CLOUDFLARE_UI = 'https://ui.nsalarm.pro';
const stepsOrder = ['general', 'network', 'expansions', 'mqtt', 'cloudflare', 'summary'];
let currentStep = 0;

const state = {
  provisioned: false,
  general: {
    centralName: '',
  },
  deviceId: '',
  network: {
    dhcp: true,
    ip: '',
    gw: '',
    mask: '',
    dns: '',
  },
  expansions: {
    items: [],
    lastScan: null,
    loading: false,
    completed: false,
    error: '',
  },
  mqtt: {
    uri: '',
    cid: '',
    user: '',
    pass: '',
    keepalive: null,
    default_uri: '',
    default_keepalive: null,
    testedOk: false,
    testStatus: 'info',
    testMessage: 'Esegui il test connessione per continuare.',
  },
  cloudflare: {
    ui_url: '',
  },
};

const MQTT_PASSWORD_POLICY_MESSAGE = 'Password MQTT non valida: usa 12-63 caratteri con lettere maiuscole, minuscole, numeri e simboli. Lascia il campo vuoto se il broker non richiede autenticazione.';

function isMqttPasswordValid(pass){
  if (!pass) return true;
  if (pass.length < 12 || pass.length > 63) return false;
  let hasUpper = false;
  let hasLower = false;
  let hasDigit = false;
  let hasSpecial = false;
  for (let i = 0; i < pass.length; i += 1){
    const code = pass.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
    if (code >= 0x41 && code <= 0x5a){
      hasUpper = true;
    } else if (code >= 0x61 && code <= 0x7a){
      hasLower = true;
    } else if (code >= 0x30 && code <= 0x39){
      hasDigit = true;
    } else {
      hasSpecial = true;
    }
  }
  return hasUpper && hasLower && hasDigit && hasSpecial;
}

function $(sel){ return document.querySelector(sel); }
function $all(sel){ return Array.from(document.querySelectorAll(sel)); }

function escapeHtml(str){
  return (str ?? '').replace(/[&<>"']/g, (c)=>({
    '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'
  })[c]);
}

function showMessage(message, type='info'){
  const box = $('#wizardMessage');
  if (!box) return;
  box.textContent = message;
  box.classList.remove('hidden', 'error', 'success');
  if (type === 'error') box.classList.add('error');
  else if (type === 'success') box.classList.add('success');
}

function clearMessage(){
  const box = $('#wizardMessage');
  if (!box) return;
  box.classList.add('hidden');
  box.classList.remove('error', 'success');
  box.textContent = '';
}

async function apiRequest(path, options={}){
  const res = await fetch(path, options);
  if (!res.ok){
    let detail = '';
    try {
      const ct = res.headers.get('content-type') || '';
      if (ct.includes('application/json')){
        const data = await res.json();
        detail = data?.error || data?.message || JSON.stringify(data);
      } else {
        detail = await res.text();
      }
    } catch (err) {
      detail = err?.message || '';
    }
    const msg = detail ? `${res.status} ${res.statusText}: ${detail}` : `${res.status} ${res.statusText}`;
    throw new Error(msg);
  }
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  return res.text();
}

function apiGet(path){
  return apiRequest(path, { headers: { 'Accept': 'application/json' } });
}

function apiPost(path, body){
  return apiRequest(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
}

function toggleNetStatic(dhcpEnabled){
  const box = $('#netStaticFields');
  if (!box) return;
  box.classList.toggle('hidden', dhcpEnabled);
  $all('#netStaticFields input').forEach((input)=>{
    const optional = input.dataset.optional === 'true';
    input.disabled = dhcpEnabled;
    if (dhcpEnabled) input.required = false;
    else input.required = !optional;
  });
}

function formatDateTime(ts){
  if (!ts && ts !== 0) return '';
  let date;
  if (ts instanceof Date) date = ts;
  else if (typeof ts === 'string' && ts) date = new Date(ts);
  else if (typeof ts === 'number') date = new Date(ts);
  else return '';
  if (Number.isNaN(date.getTime())) return '';
  try {
    return date.toLocaleString('it-IT');
  } catch (err) {
    return date.toISOString();
  }
}

function renderExpansionsSection(){
  const items = Array.isArray(state.expansions.items) ? state.expansions.items : [];
  const list = $('#expansionList');
  if (list){
    list.innerHTML = items.map((node)=>{
      if (!node) return '';
      const titleParts = [];
      if (typeof node.label === 'string' && node.label.trim()){
        titleParts.push(node.label.trim());
      } else if (typeof node.kind === 'string' && node.kind.trim()){
        titleParts.push(node.kind.trim());
      } else {
        titleParts.push(`Nodo ${node.node_id ?? '?'}`);
      }
      const metaParts = [];
      if (node.node_id != null) metaParts.push(`ID ${node.node_id}`);
      if (node.kind) metaParts.push(String(node.kind));
      if (node.state) metaParts.push(String(node.state));
      const ioInfo = [];
      if (node.inputs_count != null) ioInfo.push(`${node.inputs_count} ingressi`);
      if (node.outputs_count != null) ioInfo.push(`${node.outputs_count} uscite`);
      if (ioInfo.length) metaParts.push(ioInfo.join(' · '));
      const meta = metaParts.filter(Boolean).map((part)=>escapeHtml(String(part))).join(' · ');
      return `<li class="expansion-item"><div class="expansion-title">${escapeHtml(titleParts.join(' – '))}</div>${meta ? `<div class="expansion-meta">${meta}</div>` : ''}</li>`;
    }).join('');
  }
  const empty = $('#expansionEmpty');
  if (empty){
    const expansionsCount = items.filter((node)=>node && Number(node.node_id) > 0).length;
    const showEmpty = !state.expansions.loading && !state.expansions.error && expansionsCount === 0;
    empty.classList.toggle('hidden', !showEmpty);
  }
  const status = $('#expansionStatus');
  if (status){
    status.classList.remove('hidden', 'error', 'success');
    if (state.expansions.loading){
      status.textContent = 'Ricerca nodi in corso...';
    } else if (state.expansions.error){
      status.textContent = state.expansions.error;
      status.classList.add('error');
    } else if (state.expansions.completed){
      const when = formatDateTime(state.expansions.lastScan);
      status.textContent = when ? `Ultimo aggiornamento: ${when}` : 'Elenco aggiornato.';
      status.classList.add('success');
    } else {
      status.textContent = '';
      status.classList.add('hidden');
    }
  }
  const scanBtn = $('#expansionScanBtn');
  if (scanBtn) scanBtn.disabled = state.expansions.loading;
  const nextBtn = $('#expansionsNext');
  if (nextBtn) nextBtn.disabled = !state.expansions.completed || state.expansions.loading;
}

async function loadCanNodes(){
  state.expansions.loading = true;
  state.expansions.error = '';
  state.expansions.completed = false;
  renderExpansionsSection();
  updateSummary();
  updateProgress();
  try {
    const nodes = await apiGet('/api/can/nodes');
    if (Array.isArray(nodes)){
      state.expansions.items = nodes;
    } else {
      state.expansions.items = [];
    }
    state.expansions.completed = true;
    state.expansions.lastScan = Date.now();
  } catch (err) {
    state.expansions.error = err?.message || 'Impossibile recuperare le schede CAN.';
    state.expansions.items = [];
    state.expansions.completed = false;
  }
  state.expansions.loading = false;
  renderExpansionsSection();
  updateSummary();
  updateProgress();
}

async function requestCanScan(){
  state.expansions.loading = true;
  state.expansions.error = '';
  state.expansions.completed = false;
  renderExpansionsSection();
  updateSummary();
  updateProgress();
  try {
    await apiPost('/api/can/scan', {});
  } catch (err) {
    state.expansions.loading = false;
    state.expansions.error = err?.message || 'Impossibile avviare la scansione del bus CAN.';
    renderExpansionsSection();
    updateSummary();
    updateProgress();
    return;
  }
  await loadCanNodes();
}

function renderMqttTestFeedback(){
  const box = $('#mqttTestStatus');
  if (!box) return;
  box.classList.remove('success', 'error');
  const message = state.mqtt.testMessage || '';
  if (!message){
    box.textContent = '';
    box.classList.add('hidden');
    return;
  }
  box.textContent = message;
  box.classList.remove('hidden');
  if (state.mqtt.testStatus === 'success') box.classList.add('success');
  else if (state.mqtt.testStatus === 'error') box.classList.add('error');
}

function refreshMqttControls(){
  const saveBtn = $('#mqttNext');
  if (saveBtn){
    const allowSave = state.mqtt.testedOk && state.mqtt.testStatus !== 'testing';
    saveBtn.disabled = !allowSave;
  }
  const testBtn = $('#mqttTestBtn');
  if (testBtn){
    testBtn.disabled = state.mqtt.testStatus === 'testing';
  }
  renderMqttTestFeedback();
}

function invalidateMqttTest(silent = false){
  const hadSuccess = state.mqtt.testedOk;
  state.mqtt.testedOk = false;
  state.mqtt.testStatus = 'info';
  if (!silent){
    state.mqtt.testMessage = hadSuccess ? 'Modifiche rilevate: rieseguire il test connessione.' : 'Esegui il test connessione per continuare.';
  } else if (!state.mqtt.testMessage){
    state.mqtt.testMessage = 'Esegui il test connessione per continuare.';
  }
  refreshMqttControls();
  updateSummary();
  updateProgress();
}

function setStep(index){
  if (index < 0 || index >= stepsOrder.length) return;
  currentStep = index;
  const stepName = stepsOrder[index];
  clearMessage();
  $all('.wizard-step').forEach((section)=>{
    section.classList.toggle('active', section.dataset.step === stepName);
  });
  if (stepName === 'expansions' && !state.expansions.completed && !state.expansions.loading){
    loadCanNodes();
  }
  updateProgress();
  updateSummary();
  refreshMqttControls();
}

function goToStep(stepName){
  const idx = stepsOrder.indexOf(stepName);
  if (idx >= 0){
    setStep(idx);
  }
}

function updateProgress(){
  const completion = {
    general: isGeneralComplete(),
    network: isNetworkComplete(),
    expansions: isExpansionsComplete(),
    mqtt: isMqttComplete(),
    cloudflare: isCloudflareComplete(),
    summary: state.provisioned,
  };
  $all('#wizardSteps li').forEach((item)=>{
    const key = item.dataset.stepLabel;
    const idx = stepsOrder.indexOf(key);
    item.classList.toggle('active', idx === currentStep);
    item.classList.toggle('done', completion[key]);
    const indexBadge = item.querySelector('.step-index');
    if (indexBadge && idx >= 0){
      indexBadge.textContent = String(idx + 1);
    }
  });
}

function updateSummary(){
  const box = $('#summaryStatus');
  if (!box) return;
  const rows = [];
  const generalDetails = [];
  generalDetails.push(`Nome centrale: ${state.general.centralName || '-'}`);
  rows.push({
    id: 'general',
    title: 'Generale',
    ok: isGeneralComplete(),
    details: generalDetails,
  });
  const networkDetails = [];
  networkDetails.push(`DHCP: ${state.network.dhcp ? 'sì' : 'no'}`);
  if (!state.network.dhcp){
    networkDetails.push(`IP: ${state.network.ip || '-'}`);
    networkDetails.push(`Gateway: ${state.network.gw || '-'}`);
    networkDetails.push(`Subnet: ${state.network.mask || '-'}`);
    networkDetails.push(`DNS: ${state.network.dns || '-'}`);
  }
  rows.push({
    id: 'network',
    title: 'Rete locale',
    ok: isNetworkComplete(),
    details: networkDetails,
  });
  
  const expansionItems = Array.isArray(state.expansions.items) ? state.expansions.items : [];
  const expansionsDetails = [];
  const masterNode = expansionItems.find((node)=>node && Number(node.node_id) === 0);
  if (masterNode){
    const label = (masterNode.label && String(masterNode.label).trim()) || (masterNode.kind && String(masterNode.kind).trim()) || 'Master';
    expansionsDetails.push(`Master: ${label}`);
  }
  const expansionsCount = expansionItems.filter((node)=>node && Number(node.node_id) > 0).length;
  expansionsDetails.push(`Schede collegate: ${expansionsCount}`);
  const lastScan = formatDateTime(state.expansions.lastScan);
  if (lastScan){
    expansionsDetails.push(`Ultimo aggiornamento: ${lastScan}`);
  }
  if (state.expansions.loading){
    expansionsDetails.push('Ricerca nodi CAN in corso…');
  }
  if (state.expansions.error){
    expansionsDetails.push(`Errore: ${state.expansions.error}`);
  }
  if (!expansionsDetails.length){
    expansionsDetails.push('Nessun dato disponibile.');
  }
  rows.push({
    id: 'expansions',
    title: 'Espansioni CAN',
    ok: isExpansionsComplete(),
    details: expansionsDetails,
  });


  const mqttDetails = [];
  const deviceId = state.deviceId || state.mqtt.cid || state.mqtt.user || '';
  const mqttUri = state.mqtt.uri || state.mqtt.default_uri || '-';
  mqttDetails.push(`Broker: ${mqttUri}`);
  mqttDetails.push(`Device ID: ${deviceId || '-'}`);
  mqttDetails.push(`Client ID: ${state.mqtt.cid || deviceId || '-'}`);
  mqttDetails.push(`Username: ${state.mqtt.user || deviceId || '-'}`);
  const keepaliveValue = state.mqtt.keepalive ?? state.mqtt.default_keepalive;
  mqttDetails.push(`Keep alive: ${keepaliveValue != null ? `${keepaliveValue}s` : '-'}`);
  let testDetail = 'Test connessione: non ancora eseguito.';
  if (state.mqtt.testStatus === 'success' || state.mqtt.testedOk){
    testDetail = 'Test connessione: riuscito.';
  } else if (state.mqtt.testStatus === 'error' && state.mqtt.testMessage){
    testDetail = state.mqtt.testMessage;
  } else if (state.mqtt.testStatus === 'testing'){
    testDetail = 'Test connessione in corso...';
  } else if (state.mqtt.testStatus === 'info' && state.mqtt.testMessage){
    testDetail = state.mqtt.testMessage;
  }
  mqttDetails.push(testDetail);
  rows.push({
    id: 'mqtt',
    title: 'MQTT',
    ok: isMqttComplete(),
    details: mqttDetails,
  });

  const cfDetails = [];
  cfDetails.push(`UI Cloudflare: ${state.cloudflare.ui_url || DEFAULT_CLOUDFLARE_UI}`);
  rows.push({
    id: 'cloudflare',
    title: 'Cloudflare',
    ok: isCloudflareComplete(),
    details: cfDetails,
  });

  rows.push({
    id: 'provisioning',
    title: 'Provisioning',
    ok: state.provisioned,
    // details: [state.provisioned ? 'Completato: il dispositivo reindirizzerà alla Dashboard.' : 'In attesa di completamento.'],
    details: [state.provisioned ? 'Completato: reindirizzamento alla schermata di login.' : 'In attesa di completamento.'],
  });
  
  box.innerHTML = rows.map((row)=>{
    const cls = row.ok ? 'summary-item ok' : 'summary-item';
    const badge = row.ok ? '<span class="tag">OK</span>' : '';
    const details = row.details.map((d)=>`<li>${escapeHtml(d)}</li>`).join('');
    return `<div class="${cls}"><h3>${escapeHtml(row.title)} ${badge}</h3><ul>${details}</ul></div>`;
  }).join('');

  const finish = $('#finishBtn');
  if (finish){
    finish.disabled = !(isGeneralComplete() && isNetworkComplete() && isMqttComplete() && isCloudflareComplete()) || state.provisioned;
  }
  const link = $('#cloudflareLink');
  if (link){
    const url = state.cloudflare.ui_url?.trim() || DEFAULT_CLOUDFLARE_UI;
    link.href = url;
    link.classList.toggle('hidden', !state.provisioned);
  }
}

function readGeneralForm(){
  const centralName = ($('#general_name')?.value || '').trim();
  return { centralName };
}

function readNetworkForm(){
  const dhcp = !!$('#net_dhcp')?.checked;
  const ip = ($('#net_ip')?.value || '').trim();
  const gw = ($('#net_gw')?.value || '').trim();
  const mask = ($('#net_mask')?.value || '').trim();
  const dns = ($('#net_dns')?.value || '').trim();
  return { dhcp, ip, gw, mask, dns };
}

function readMqttForm(){
  const uri = ($('#mqtt_uri')?.value || '').trim();
  const storedId = (state.deviceId || '').trim();
  const domId = ($('#mqtt_device_id')?.value || '').trim();
  const cidInput = ($('#mqtt_cid')?.value || '').trim();
  const userInput = ($('#mqtt_user')?.value || '').trim();
  const deviceId = storedId || domId || cidInput || userInput;
  const cid = deviceId;
  const user = deviceId;
  const pass = ($('#mqtt_pass')?.value || '').trim();
  const rawKeepalive = ($('#mqtt_keep')?.value ?? '').trim();
  let keepalive = Number.parseInt(rawKeepalive, 10);
  if (Number.isNaN(keepalive)){
    const fallback = state.mqtt.keepalive ?? state.mqtt.default_keepalive ?? 60;
    keepalive = fallback;
  }
  return { uri, cid, user, pass, keepalive };
}

function readCloudflareForm(){
  let ui_url = ($('#cf_ui')?.value || '').trim();
  if (!ui_url) ui_url = DEFAULT_CLOUDFLARE_UI;
  return { ui_url };
}

function isNetworkComplete(){
  const cfg = state.network;
  if (cfg.dhcp) return true;
  return !!(cfg.ip && cfg.gw && cfg.mask);
}

function isGeneralComplete(){
  return !!state.general.centralName;
}

function isExpansionsComplete(){
  return !!state.expansions.completed;
}

function isMqttComplete(){
  return !!((state.mqtt.uri || state.mqtt.default_uri) && state.mqtt.testedOk);
}

function isCloudflareComplete(){
  const cf = state.cloudflare;
  return !!(cf.ui_url);
}

async function submitGeneral(event){
  event?.preventDefault();
  const btn = $('#generalNext');
  if (btn) btn.disabled = true;
  try {
    const payload = readGeneralForm();
    if (!payload.centralName){ throw new Error('Specifica un nome per la centrale.'); }
    await apiPost('/api/provision/general', { central_name: payload.centralName });
    state.general = { ...state.general, ...payload };
    showMessage('Dati generali salvati.', 'success');
    goToStep('network');
  } catch (err) {
    showMessage(err.message || 'Salvataggio dati generali fallito.', 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function submitNetwork(event){
  event?.preventDefault();
  const btn = $('#networkNext');
  if (btn) btn.disabled = true;
  try {
    const payload = readNetworkForm();
    if (!payload.dhcp && (!payload.ip || !payload.gw || !payload.mask)){
      throw new Error('Compila IP, gateway e subnet per configurazione statica.');
    }
    await apiPost('/api/sys/net', {
      dhcp: payload.dhcp,
      ip: payload.ip,
      gw: payload.gw,
      mask: payload.mask,
      dns: payload.dns,
    });
    state.network = { ...state.network, ...payload };
    toggleNetStatic(payload.dhcp);
    showMessage('Configurazione di rete salvata.', 'success');
    goToStep('expansions');
  } catch (err) {
    showMessage(err.message || 'Salvataggio rete fallito.', 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function testMqttConnection(event){
  event?.preventDefault();
  const payload = readMqttForm();
  if (!payload.uri){
    state.mqtt.testedOk = false;
    state.mqtt.testStatus = 'error';
    state.mqtt.testMessage = 'Specifica l\'URI del broker MQTT.';
    refreshMqttControls();
    updateSummary();
    updateProgress();
    return;
  }
  state.mqtt = { ...state.mqtt, ...payload };
  state.mqtt.testedOk = false;
  state.mqtt.testStatus = 'testing';
  state.mqtt.testMessage = 'Test connessione in corso...';
  refreshMqttControls();
  updateSummary();
  updateProgress();
  try {
    const response = await apiPost('/api/sys/mqtt/test', payload);
    const detail = response && response.error != null ? String(response.error).trim() : '';
    if (response?.success){
      state.mqtt.testedOk = true;
      state.mqtt.testStatus = 'success';
      state.mqtt.testMessage = 'Connessione riuscita.';
    } else {
      state.mqtt.testedOk = false;
      state.mqtt.testStatus = 'error';
      state.mqtt.testMessage = detail ? `Connessione non riuscita: ${detail}` : 'Connessione non riuscita.';
    }
  } catch (err) {
    const msg = err?.message ? String(err.message).trim() : '';
    state.mqtt.testedOk = false;
    state.mqtt.testStatus = 'error';
    state.mqtt.testMessage = msg ? `Connessione non riuscita: ${msg}` : 'Connessione non riuscita.';
  }
  refreshMqttControls();
  updateSummary();
  updateProgress();
}

async function submitMqtt(event){
  event?.preventDefault();
  if (!state.mqtt.testedOk){
    showMessage('Esegui prima il test di connessione MQTT.', 'error');
    refreshMqttControls();
    return;
  }
  const btn = $('#mqttNext');
  if (btn) btn.disabled = true;
  try {
    const payload = readMqttForm();
    if (!payload.uri){ throw new Error('Specifica l\'URI del broker MQTT.'); }
    if (!isMqttPasswordValid(payload.pass)){
      showMessage(MQTT_PASSWORD_POLICY_MESSAGE, 'error');
      return;
    }
    const deviceId = payload.cid || state.deviceId || '';
    payload.cid = deviceId;
    payload.user = deviceId;
    await apiPost('/api/sys/mqtt', payload);
    if (deviceId) state.deviceId = deviceId;
    state.mqtt = { ...state.mqtt, ...payload, cid: deviceId, user: deviceId };
    showMessage('Parametri MQTT aggiornati.', 'success');
    goToStep('cloudflare');
  } catch (err) {
    let message = err?.message || '';
    const httpMatch = message.match(/^[0-9]{3} [^:]+: (.+)$/);
    if (httpMatch && httpMatch[1]) message = httpMatch[1].trim();
    if (message && /password mqtt/i.test(message)) message = MQTT_PASSWORD_POLICY_MESSAGE;
    showMessage(message || 'Salvataggio MQTT fallito.', 'error');
  } finally {
    refreshMqttControls();
  }
}

async function submitCloudflare(event){
  event?.preventDefault();
  const btn = $('#cloudflareNext');
  if (btn) btn.disabled = true;
  try {
    const payload = readCloudflareForm();
    await apiPost('/api/sys/cloudflare', payload);
    state.cloudflare = { ...state.cloudflare, ...payload };
    showMessage('Dati Cloudflare salvati.', 'success');
    goToStep('summary');
  } catch (err) {
    showMessage(err.message || 'Salvataggio Cloudflare fallito.', 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function finishProvisioning(){
  const btn = $('#finishBtn');
  if (btn) btn.disabled = true;
  try {
    // const response = await apiPost('/api/provision/finish', {});
    await apiPost('/api/provision/finish', {});
    state.provisioned = true;
    // const redirect = response?.redirect || state.cloudflare.ui_url || DEFAULT_CLOUDFLARE_UI;
    updateSummary();
    // showMessage('Provisioning completato! Reindirizzamento automatico tra pochi secondi...', 'success');
    showMessage('Provisioning completato! Reindirizzamento alla schermata di login…', 'success');
    const link = $('#cloudflareLink');
    if (link){
      // link.href = redirect;
      link.href = '/login.html';
      link.textContent = 'Apri login';
      link.classList.remove('hidden');
    }
    // setTimeout(()=>{ window.location.href = redirect; }, 5000);
    setTimeout(()=>{ window.location.href = '/login.html'; }, 1500);
  } catch (err) {
    showMessage(err.message || 'Impossibile completare il provisioning.', 'error');
    if (btn) btn.disabled = false;
  }
}

function bindPrevButtons(){
  $all('[data-prev]').forEach((btn)=>{
    btn.addEventListener('click', ()=>{
      const target = btn.getAttribute('data-prev');
      const idx = stepsOrder.indexOf(target);
      if (idx >= 0) setStep(idx);
    });
  });
}

function hydrateForms(){
  $('#general_name') && ($('#general_name').value = state.general.centralName || '');
  const dhcp = state.network.dhcp !== false;
  if ($('#net_dhcp')) $('#net_dhcp').checked = dhcp;
  const ipInput = $('#net_ip');
  if (ipInput) ipInput.value = state.network.ip || '';
  const gwInput = $('#net_gw');
  if (gwInput) gwInput.value = state.network.gw || '';
  const maskInput = $('#net_mask');
  if (maskInput) maskInput.value = state.network.mask || '';
  const dnsInput = $('#net_dns');
  if (dnsInput) dnsInput.value = state.network.dns || '';
  toggleNetStatic(dhcp);

  const mqttUriInput = $('#mqtt_uri');
  if (mqttUriInput){
    const uriValue = state.mqtt.uri || state.mqtt.default_uri || '';
    mqttUriInput.value = uriValue;
    mqttUriInput.placeholder = state.mqtt.default_uri || '';
  }

  const deviceId = (state.deviceId || state.mqtt.cid || state.mqtt.user || '').trim();
  if (deviceId) {
    state.deviceId = deviceId;
    state.mqtt.cid = deviceId;
    state.mqtt.user = deviceId;
  }
  $('#mqtt_device_id') && ($('#mqtt_device_id').value = deviceId || '');
  $('#mqtt_cid') && ($('#mqtt_cid').value = deviceId || '');
  $('#mqtt_user') && ($('#mqtt_user').value = deviceId || '');

  // const mqttCidInput = $('#mqtt_cid');
  // if (mqttCidInput) mqttCidInput.value = state.mqtt.cid || '';
  // const mqttUserInput = $('#mqtt_user');
  // if (mqttUserInput) mqttUserInput.value = state.mqtt.user || '';
  const mqttPassInput = $('#mqtt_pass');
  if (mqttPassInput) mqttPassInput.value = state.mqtt.pass || '';
  const mqttKeepInput = $('#mqtt_keep');
  if (mqttKeepInput){
    const keepaliveVal = state.mqtt.keepalive ?? state.mqtt.default_keepalive;
    mqttKeepInput.value = keepaliveVal != null ? keepaliveVal : '';
    mqttKeepInput.placeholder = state.mqtt.default_keepalive != null ? `${state.mqtt.default_keepalive}` : '';
  }

  const cfUiInput = $('#cf_ui');
  if (cfUiInput) cfUiInput.value = state.cloudflare.ui_url || '';
}

async function loadInitialStatus(){
  try {
    const data = await apiGet('/api/provision/status');
    if (data){
      state.provisioned = !!data.provisioned;
      if (data.general){
        const centralName = data.general.central_name ?? data.general.centralName;
        if (typeof centralName === 'string'){
          state.general.centralName = centralName;
        }
      }
      const rootDeviceId = typeof data.device_id === 'string' ? data.device_id.trim() : '';
      if (rootDeviceId) state.deviceId = rootDeviceId;
      if (data.network) state.network = { ...state.network, ...data.network };
      if (data.mqtt){
        const { default_uri, default_keepalive, ...mqttCfg } = data.mqtt;
        state.mqtt = { ...state.mqtt, ...mqttCfg };
        if (default_uri !== undefined) state.mqtt.default_uri = default_uri;
        if (default_keepalive !== undefined) state.mqtt.default_keepalive = default_keepalive;
      }
      if (data.cloudflare) state.cloudflare = { ...state.cloudflare, ...data.cloudflare };
      if (state.provisioned && state.mqtt.uri){
        state.mqtt.testedOk = true;
        state.mqtt.testStatus = 'success';
        state.mqtt.testMessage = 'Connessione già verificata.';
      } else {
        state.mqtt.testedOk = false;
        state.mqtt.testStatus = 'info';
        if (!state.mqtt.testMessage){
          state.mqtt.testMessage = 'Esegui il test connessione per continuare.';
        }
      }
      if (!state.deviceId){
        const fallback = (state.mqtt.cid || state.mqtt.user || '').trim();
        if (fallback) state.deviceId = fallback;
      }
      if (state.deviceId){
        state.mqtt.cid = state.deviceId;
        state.mqtt.user = state.deviceId;
      }
    }
  } catch (err) {
    showMessage('Impossibile leggere lo stato iniziale: ' + (err.message || ''), 'error');
  }
  await loadCanNodes();
  hydrateForms();
  refreshMqttControls();
  updateSummary();
  updateProgress();
}

function initWizard(){
  $('#net_dhcp')?.addEventListener('change', (ev)=>{
    toggleNetStatic(ev.target.checked);
  });
  $('#generalForm')?.addEventListener('submit', submitGeneral);
  $('#networkForm')?.addEventListener('submit', submitNetwork);
  $('#mqttForm')?.addEventListener('submit', submitMqtt);
  $('#mqttTestBtn')?.addEventListener('click', testMqttConnection);
  $('#expansionScanBtn')?.addEventListener('click', ()=>{ requestCanScan(); });
  $('#expansionsNext')?.addEventListener('click', ()=>{
    if (state.expansions.completed){
      goToStep('mqtt');
    } else if (!state.expansions.loading){
      showMessage('Attendi il completamento del caricamento delle schede CAN prima di proseguire.', 'error');
    }
  });
  $('#cloudflareForm')?.addEventListener('submit', submitCloudflare);
  $('#finishBtn')?.addEventListener('click', finishProvisioning);
  ['#mqtt_uri', '#mqtt_cid', '#mqtt_user', '#mqtt_pass', '#mqtt_keep'].forEach((sel)=>{
    const input = document.querySelector(sel);
    if (!input) return;
    input.addEventListener('input', ()=>invalidateMqttTest());
  });
  bindPrevButtons();
  refreshMqttControls();
  renderExpansionsSection();
  loadInitialStatus().then(()=>{
    if (state.provisioned){
      const summaryIdx = stepsOrder.indexOf('summary');
      currentStep = summaryIdx >= 0 ? summaryIdx : stepsOrder.length - 1;
      updateProgress();
      updateSummary();
      setStep(currentStep);
      showMessage('Il dispositivo risulta già provisionato. Puoi aprire direttamente la UI Cloudflare.', 'success');
      const link = $('#cloudflareLink');
      if (link){
        link.href = state.cloudflare.ui_url || DEFAULT_CLOUDFLARE_UI;
        link.classList.remove('hidden');
      }
    } else {
      if (document.querySelector('.wizard-step[data-step="general"]')){
        goToStep('general');
      } else if (document.querySelector('.wizard-step[data-step="network"]')){
        goToStep('network');
      } else {
        setStep(0);
      }
    }
  });
}

window.addEventListener('DOMContentLoaded', initWizard);