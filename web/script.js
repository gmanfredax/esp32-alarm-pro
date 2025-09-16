let token='';

// Se c'è un token, prova ad usarlo e costruisci la UI
token = localStorage.getItem('token') || '';
if (token) {
  api('/api/status').then(()=>{
    document.getElementById('login').style.display='none';
    document.getElementById('app').style.display='block';
    connectWS();
    refresh();
    loadScenes();
  }).catch(()=>{});
}

let ws;

// WebSocket per aggiornamento zone in tempo reale
function connectWS(){
  if (!token) return;
  const proto = (location.protocol === 'https:') ? 'wss' : 'ws';
  const url = `${proto}://${location.host}/ws?token=${encodeURIComponent(token)}`;

  try{
    ws = new WebSocket(url);
    ws.onmessage = (ev)=>{
      try{
        const m = JSON.parse(ev.data);
        if (m && m.type === "zones") {
          const z = (Array.isArray(m.z) && m.z.length && typeof m.z[0] !== 'object')
            ? m.z.map((lv, i)=>({ id: i+1, level: lv ? 1 : 0 }))
            : m.z;
          document.getElementById('zones').textContent = JSON.stringify(z, null, 2);
        }
      }catch(e){}
    };
    ws.onclose = ()=>{ setTimeout(()=>{ if(token) connectWS(); }, 2000); };
  }catch(e){
    setTimeout(()=>{ if(token) connectWS(); }, 2000);
  }
}

// Wrapper fetch con gestione 401 → torna alla login
async function api(path, opt = {}){
  opt.headers = Object.assign({'Content-Type':'application/json'}, opt.headers||{});
  if(token) opt.headers['X-Auth-Token'] = token;

  const r = await fetch(path, opt);

  if (r.status === 401) {
    try { localStorage.removeItem('token'); } catch(e){}
    token = '';
    if (ws) { try { ws.close(); } catch(e){} }
    document.getElementById('app').style.display   = 'none';
    document.getElementById('login').style.display = 'block';
    throw new Error('Unauthorized');
  }

  if(!r.ok){
    throw new Error(await r.text());
  }
  const ct = r.headers.get('content-type')||'';
  return ct.includes('application/json') ? r.json() : r.text();
}

// Login
function login_on_submit(e){
  e.preventDefault();
  login();
  return false;
}

async function login(){
  const user = document.getElementById('u').value.trim();
  const pass = document.getElementById('p').value;
  const otp  = document.getElementById('o').value.trim();
  const errBox = document.getElementById('loginerr');
  errBox.textContent = '';
  try{
    const r = await api('/api/login', { method:'POST', body: JSON.stringify({user, pass, otp}) });
    token = r.token;
    try { localStorage.setItem('token', token); } catch(e){}
    document.getElementById('login').style.display='none';
    document.getElementById('app').style.display='block';
    connectWS();
    refresh();
    loadScenes();
  }catch(e){
    errBox.textContent = (e && e.message) ? e.message : 'Errore di login';
  }
}

// Dati base
async function refresh(){
  const s = await api('/api/status');
  document.getElementById('status').innerHTML=`<b>Stato:</b> ${s.state} | <b>Zones:</b> ${s.zones_count}`;
  const z = await api('/api/zones');
  document.getElementById('zones').textContent=JSON.stringify(z,null,2);
  const l = await api('/api/logs');
  document.getElementById('logs').textContent=JSON.stringify(l,null,2);
}

// Comandi
async function arm(mode){ await api('/api/arm',{method:'POST',body:JSON.stringify({mode})}); refresh(); }
async function disarm(){ await api('/api/disarm',{method:'POST'}); refresh(); }
async function setOutputs(){
  await api('/api/outputs', {
    method: 'POST',
    body: JSON.stringify({
      relay: document.getElementById('relay').checked ? 1 : 0,
      ls:    document.getElementById('leds').checked  ? 1 : 0,
      lm:    document.getElementById('ledm').checked  ? 1 : 0
    })
  });
}

// Scenes UI --------------------------------------------------------------
let sceneCfg = { home: [], night: [], custom: [] };
let zonesCount = 12;

function buildSceneGrid(selectedIds){
  const g = document.getElementById('sceneGrid');
  g.innerHTML = '';
  for (let i=1;i<=zonesCount;i++){
    const lbl = document.createElement('label');
    const ck = document.createElement('input');
    ck.type = 'checkbox';
    ck.dataset.zoneId = String(i);
    ck.checked = selectedIds.includes(i);
    lbl.appendChild(ck);
    lbl.appendChild(document.createTextNode(' '+i));
    g.appendChild(lbl);
  }
}

async function loadScenes(){
  const cfg = await api('/api/scenes');
  zonesCount = cfg.zones_count || 12;
  sceneCfg.home   = cfg.home   || [];
  sceneCfg.night  = cfg.night  || [];
  sceneCfg.custom = cfg.custom || [];
  showSceneForEdit();
}

function currentSceneName(){ return document.getElementById('sceneSel').value; }

function showSceneForEdit(){
  const s = currentSceneName();
  buildSceneGrid(sceneCfg[s] || []);
}

function collectGridIds(){
  const ids = [];
  document.querySelectorAll('#sceneGrid input[type=checkbox]').forEach(ck=>{
    if (ck.checked) ids.push(parseInt(ck.dataset.zoneId,10));
  });
  return ids;
}

async function saveCurrentScene(){
  const s = currentSceneName();
  const ids = collectGridIds();
  await api('/api/scenes', { method:'POST', body: JSON.stringify({ scene:s, zones: ids }) });
  sceneCfg[s] = ids.slice();
  alert('Scena salvata');
}

function selAll(){
  document.querySelectorAll('#sceneGrid input[type=checkbox]').forEach(ck=>ck.checked=true);
}
function selNone(){
  document.querySelectorAll('#sceneGrid input[type=checkbox]').forEach(ck=>ck.checked=false);
}
function selInvert(){
  document.querySelectorAll('#sceneGrid input[type=checkbox]').forEach(ck=>ck.checked=!ck.checked);
}
function copyFrom(){
  const src = document.getElementById('copyFromSel').value;
  buildSceneGrid((sceneCfg[src] || []).slice());
}

// Logout
async function logout(){
  try { await api('/api/logout', { method:'POST' }); } catch(e) {}
  if (ws) { try { ws.close(); } catch(e){} }
  token = '';
  try { localStorage.removeItem('token'); } catch(e){}
  document.getElementById('app').style.display = 'none';
  document.getElementById('login').style.display = 'block';
}
