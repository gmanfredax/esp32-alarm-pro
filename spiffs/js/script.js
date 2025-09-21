const DEFAULT_CLOUDFLARE_UI = 'https://dash.cloudflare.com/';
const stepsOrder = ['network', 'mqtt', 'cloudflare', 'summary'];
let currentStep = 0;

const state = {
  provisioned: false,
  network: {
    hostname: 'nsalarmpro',
    dhcp: true,
    ip: '',
    gw: '',
    mask: '',
    dns: '',
  },
  mqtt: {
    uri: '',
    cid: '',
    user: '',
    pass: '',
    keepalive: 60,
  },
  cloudflare: {
    account_id: '',
    tunnel_id: '',
    auth_token: '',
    ui_url: DEFAULT_CLOUDFLARE_UI,
  },
};

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

function setStep(index){
  if (index < 0 || index >= stepsOrder.length) return;
  currentStep = index;
  const stepName = stepsOrder[index];
  clearMessage();
  $all('.wizard-step').forEach((section)=>{
    section.classList.toggle('active', section.dataset.step === stepName);
  });
  updateProgress();
  updateSummary();
}

function updateProgress(){
  const completion = {
    network: isNetworkComplete(),
    mqtt: isMqttComplete(),
    cloudflare: isCloudflareComplete(),
    summary: state.provisioned,
  };
  $all('#wizardSteps li').forEach((item)=>{
    const key = item.dataset.stepLabel;
    const idx = stepsOrder.indexOf(key);
    item.classList.toggle('active', idx === currentStep);
    item.classList.toggle('done', completion[key]);
  });
}

function updateSummary(){
  const box = $('#summaryStatus');
  if (!box) return;
  const rows = [];
  const networkDetails = [];
  networkDetails.push(`Hostname: ${state.network.hostname || '-'}`);
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

  const mqttDetails = [];
  mqttDetails.push(`Broker: ${state.mqtt.uri || '-'}`);
  mqttDetails.push(`Client ID: ${state.mqtt.cid || '-'}`);
  mqttDetails.push(`Username: ${state.mqtt.user || '-'}`);
  mqttDetails.push(`Keep alive: ${state.mqtt.keepalive || 60}s`);
  rows.push({
    id: 'mqtt',
    title: 'MQTT',
    ok: isMqttComplete(),
    details: mqttDetails,
  });

  const cfDetails = [];
  cfDetails.push(`Account ID: ${state.cloudflare.account_id || '-'}`);
  cfDetails.push(`Tunnel ID: ${state.cloudflare.tunnel_id || '-'}`);
  cfDetails.push(`Token: ${state.cloudflare.auth_token ? 'presente' : 'non impostato'}`);
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
    details: [state.provisioned ? 'Completato: il dispositivo reindirizzerà alla UI Cloudflare.' : 'In attesa di completamento.'],
  });
  
  box.innerHTML = rows.map((row)=>{
    const cls = row.ok ? 'summary-item ok' : 'summary-item';
    const badge = row.ok ? '<span class="tag">OK</span>' : '';
    const details = row.details.map((d)=>`<li>${escapeHtml(d)}</li>`).join('');
    return `<div class="${cls}"><h3>${escapeHtml(row.title)} ${badge}</h3><ul>${details}</ul></div>`;
  }).join('');

  const finish = $('#finishBtn');
  if (finish){
    finish.disabled = !(isNetworkComplete() && isMqttComplete() && isCloudflareComplete()) || state.provisioned;
  }
  const link = $('#cloudflareLink');
  if (link){
    const url = state.cloudflare.ui_url?.trim() || DEFAULT_CLOUDFLARE_UI;
    link.href = url;
    link.classList.toggle('hidden', !state.provisioned);
  }
}

function readNetworkForm(){
  const hostname = ($('#net_hostname')?.value || '').trim();
  const dhcp = !!$('#net_dhcp')?.checked;
  const ip = ($('#net_ip')?.value || '').trim();
  const gw = ($('#net_gw')?.value || '').trim();
  const mask = ($('#net_mask')?.value || '').trim();
  const dns = ($('#net_dns')?.value || '').trim();
  return { hostname, dhcp, ip, gw, mask, dns };
}

function readMqttForm(){
  const uri = ($('#mqtt_uri')?.value || '').trim();
  const cid = ($('#mqtt_cid')?.value || '').trim();
  const user = ($('#mqtt_user')?.value || '').trim();
  const pass = ($('#mqtt_pass')?.value || '').trim();
  const keepalive = parseInt((($('#mqtt_keep')?.value || '').trim()) || '60', 10) || 60;
  return { uri, cid, user, pass, keepalive };
}

function readCloudflareForm(){
  const account_id = ($('#cf_account')?.value || '').trim();
  const tunnel_id = ($('#cf_tunnel')?.value || '').trim();
  const auth_token = ($('#cf_token')?.value || '').trim();
  let ui_url = ($('#cf_ui')?.value || '').trim();
  if (!ui_url) ui_url = DEFAULT_CLOUDFLARE_UI;
  return { account_id, tunnel_id, auth_token, ui_url };
}

function isNetworkComplete(){
  const cfg = state.network;
  if (!cfg.hostname) return false;
  if (cfg.dhcp) return true;
  return !!(cfg.ip && cfg.gw && cfg.mask);
}

function isMqttComplete(){
  return !!state.mqtt.uri;
}

function isCloudflareComplete(){
  const cf = state.cloudflare;
  return !!(cf.account_id && cf.tunnel_id && cf.ui_url);
}

async function submitNetwork(event){
  event?.preventDefault();
  const btn = $('#networkNext');
  if (btn) btn.disabled = true;
  try {
    const payload = readNetworkForm();
    if (!payload.hostname){ throw new Error('Indica un hostname valido.'); }
    if (!payload.dhcp && (!payload.ip || !payload.gw || !payload.mask)){
      throw new Error('Compila IP, gateway e subnet per configurazione statica.');
    }
    await apiPost('/api/sys/net', {
      hostname: payload.hostname,
      dhcp: payload.dhcp,
      ip: payload.ip,
      gw: payload.gw,
      mask: payload.mask,
      dns: payload.dns,
    });
    state.network = { ...state.network, ...payload };
    toggleNetStatic(payload.dhcp);
    showMessage('Configurazione di rete salvata.', 'success');
    setStep(1);
  } catch (err) {
    showMessage(err.message || 'Salvataggio rete fallito.', 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function submitMqtt(event){
  event?.preventDefault();
  const btn = $('#mqttNext');
  if (btn) btn.disabled = true;
  try {
    const payload = readMqttForm();
    if (!payload.uri){ throw new Error('Specifica l\'URI del broker MQTT.'); }
    await apiPost('/api/sys/mqtt', payload);
    state.mqtt = { ...state.mqtt, ...payload };
    showMessage('Parametri MQTT aggiornati.', 'success');
    setStep(2);
  } catch (err) {
    showMessage(err.message || 'Salvataggio MQTT fallito.', 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function submitCloudflare(event){
  event?.preventDefault();
  const btn = $('#cloudflareNext');
  if (btn) btn.disabled = true;
  try {
    const payload = readCloudflareForm();
    if (!payload.account_id || !payload.tunnel_id){
      throw new Error('Completa account e tunnel ID di Cloudflare.');
    }
    await apiPost('/api/sys/cloudflare', payload);
    state.cloudflare = { ...state.cloudflare, ...payload };
    showMessage('Dati Cloudflare salvati.', 'success');
    setStep(3);
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
    const response = await apiPost('/api/provision/finish', {});
    state.provisioned = true;
    const redirect = response?.redirect || state.cloudflare.ui_url || DEFAULT_CLOUDFLARE_UI;
    updateSummary();
    showMessage('Provisioning completato! Reindirizzamento automatico tra pochi secondi...', 'success');
    const link = $('#cloudflareLink');
    if (link){
      link.href = redirect;
      link.classList.remove('hidden');
    }
    setTimeout(()=>{ window.location.href = redirect; }, 5000);
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
  $('#net_hostname') && ($('#net_hostname').value = state.network.hostname || '');
  const dhcp = state.network.dhcp !== false;
  if ($('#net_dhcp')) $('#net_dhcp').checked = dhcp;
  $('#net_ip') && ($('#net_ip').value = state.network.ip || '');
  $('#net_gw') && ($('#net_gw').value = state.network.gw || '');
  $('#net_mask') && ($('#net_mask').value = state.network.mask || '');
  $('#net_dns') && ($('#net_dns').value = state.network.dns || '');
  toggleNetStatic(dhcp);

  $('#mqtt_uri') && ($('#mqtt_uri').value = state.mqtt.uri || '');
  $('#mqtt_cid') && ($('#mqtt_cid').value = state.mqtt.cid || '');
  $('#mqtt_user') && ($('#mqtt_user').value = state.mqtt.user || '');
  $('#mqtt_pass') && ($('#mqtt_pass').value = state.mqtt.pass || '');
  $('#mqtt_keep') && ($('#mqtt_keep').value = state.mqtt.keepalive || 60);

  $('#cf_account') && ($('#cf_account').value = state.cloudflare.account_id || '');
  $('#cf_tunnel') && ($('#cf_tunnel').value = state.cloudflare.tunnel_id || '');
  $('#cf_token') && ($('#cf_token').value = state.cloudflare.auth_token || '');
  $('#cf_ui') && ($('#cf_ui').value = state.cloudflare.ui_url || DEFAULT_CLOUDFLARE_UI);
}

async function loadInitialStatus(){
  try {
    const data = await apiGet('/api/provision/status');
    if (data){
      state.provisioned = !!data.provisioned;
      if (data.network) state.network = { ...state.network, ...data.network };
      if (data.mqtt) state.mqtt = { ...state.mqtt, ...data.mqtt };
      if (data.cloudflare) state.cloudflare = { ...state.cloudflare, ...data.cloudflare };
    }
  } catch (err) {
    showMessage('Impossibile leggere lo stato iniziale: ' + (err.message || ''), 'error');
  }
  hydrateForms();
  updateSummary();
  updateProgress();
}

function initWizard(){
  $('#net_dhcp')?.addEventListener('change', (ev)=>{
    toggleNetStatic(ev.target.checked);
  });
  $('#networkForm')?.addEventListener('submit', submitNetwork);
  $('#mqttForm')?.addEventListener('submit', submitMqtt);
  $('#cloudflareForm')?.addEventListener('submit', submitCloudflare);
  $('#finishBtn')?.addEventListener('click', finishProvisioning);
  bindPrevButtons();
  loadInitialStatus().then(()=>{
    if (state.provisioned){
      currentStep = 3;
      updateProgress();
      updateSummary();
      setStep(3);
      showMessage('Il dispositivo risulta già provisionato. Puoi aprire direttamente la UI Cloudflare.', 'success');
      const link = $('#cloudflareLink');
      if (link){
        link.href = state.cloudflare.ui_url || DEFAULT_CLOUDFLARE_UI;
        link.classList.remove('hidden');
      }
    } else {
      setStep(0);
    }
  });
}

window.addEventListener('DOMContentLoaded', initWizard);