// script.js — UI minima per Centrale ESP32
let token = localStorage.getItem('token') || '';

const hdrs = () => token ? {'X-Auth-Token': token, 'Content-Type':'application/json'} : {'Content-Type':'application/json'};

async function api(path, opt={}){
  const r = await fetch(path, {headers: hdrs(), ...opt});
  if(!r.ok){
    let t = '';
    try{ t = await r.text(); }catch{}
    throw new Error(t || r.statusText || 'HTTP '+r.status);
  }
  const ct = r.headers.get('content-type') || '';
  return ct.includes('application/json') ? r.json() : r.text();
}

function setToken(t){
  token = t || '';
  if(token) localStorage.setItem('token', token);
  else localStorage.removeItem('token');
}

// Tabs
function setActiveTab(name){
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.toggle('active', b.dataset.tab===name));
  document.querySelectorAll('.tab').forEach(s=>s.classList.toggle('active', s.id === 'tab-'+name));
  if(name==='status' && window.refreshStatus) window.refreshStatus();
if(name==='zones'  && window.refreshZones)  window.refreshZones();
if(name==='scenes' && window.refreshScenes) window.refreshScenes();
}
document.querySelectorAll('.tab-btn').forEach(b=>b.addEventListener('click', ()=> setActiveTab(b.dataset.tab)));

// QR fallback (no lib esterne)
function drawQRCodeToCanvas(text, canvas){
  try{
    const ctx=canvas.getContext('2d');
    ctx.fillStyle='#fff'; ctx.fillRect(0,0,canvas.width,canvas.height);
    ctx.fillStyle='#000'; ctx.font='14px monospace';
    const lines=(text||'').match(/.{1,18}/g)||[text];
    lines.forEach((ln,i)=>ctx.fillText(ln,8,24+i*18));
  }catch(e){ console.warn('QR fallback', e); }
}
function drawQR(text, canvas){ drawQRCodeToCanvas(text, canvas); }

// Login UI
function showLogin(){
  const box = document.getElementById('loginBox');
  const main = document.getElementById('content');
  const logoutBtn = document.getElementById('btnLogout');
  if(box){ box.classList.remove('hidden'); }
  if(main){ main.classList.add('hidden'); }
  if(logoutBtn){ logoutBtn.style.display='none'; }
  document.getElementById('currentUserLabel').textContent='';
}
function showApp(){
  const box = document.getElementById('loginBox');
  const main = document.getElementById('content');
  const logoutBtn = document.getElementById('btnLogout');
  if(box){ box.classList.add('hidden'); }
  if(main){ main.classList.remove('hidden'); }
  if(logoutBtn){ logoutBtn.style.display=''; }
  refreshStatus(); refreshZones(); refreshScenes();
}

const loginForm = document.getElementById('formLogin');
if(loginForm){
  loginForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const d = Object.fromEntries(new FormData(loginForm).entries());
    try{
      const res = await api('/api/login', {method:'POST', body: JSON.stringify({user:d.user, pass:d.pass, otp:d.otp||''})});
      setToken(res.token);
      loginForm.reset();
      showApp();
      await refreshMe();
      await refreshTotp();
    }catch(err){
      alert('Login fallito: '+err.message);
    }
  });
}

// Logout
document.getElementById('btnLogout')?.addEventListener('click', async ()=>{
  try{ await api('/api/logout', {method:'POST'}); }catch{}
  setToken('');
  showLogin();
});

// Rotazione token
document.getElementById('btnRotateToken')?.addEventListener('click', async ()=>{
  try{
    const r = await api('/api/session/rotate', {method:'POST'});
    setToken(r.token);
    alert('Nuovo token generato.');
  }catch(e){ alert('Errore rotazione token: '+e.message); }
});

// Cambio password (utente corrente)
document.getElementById('formPassword')?.addEventListener('submit', async (e)=>{
  e.preventDefault();
  const d = Object.fromEntries(new FormData(e.target).entries());
  if(d.new1 !== d.new2){ alert('Le nuove password non coincidono.'); return; }
  try{
    await api('/api/user/password', {method:'POST', body: JSON.stringify({current:d.current, newpass:d.new1})});
    e.target.reset(); alert('Password aggiornata.');
  }catch(err){ alert('Errore: '+err.message); }
});

// 2FA TOTP
const stateEl = document.getElementById('totpState');
const setupBox = document.getElementById('totpSetup');
const btnEnable = document.getElementById('btnEnableTotp');
const btnDisable = document.getElementById('btnDisableTotp');
const secretEl = document.getElementById('totpSecret');
const qrCanvas = document.getElementById('qrcanvas');

async function refreshTotp(){
  if(!token) return;
  try{
    const s = await api('/api/user/totp');
    stateEl.textContent = s.enabled ? '2FA attiva' : '2FA disattivata';
    btnEnable.classList.toggle('hidden', !!s.enabled);
    btnDisable.classList.toggle('hidden', !s.enabled);
  }catch(e){
    stateEl.textContent='';
    btnEnable.classList.add('hidden');
    btnDisable.classList.add('hidden');
  }
}
btnEnable?.addEventListener('click', async ()=>{
  try{
    const s = await api('/api/user/totp/enable', {method:'POST'});
    secretEl.textContent = s.secret_base32 || '';
    drawQR(s.otpauth_uri || '', qrCanvas);
    setupBox.classList.remove('hidden');
  }catch(err){ alert('Errore: '+err.message); }
});
btnDisable?.addEventListener('click', async ()=>{
  if(!confirm('Disabilitare 2FA?')) return;
  try{ await api('/api/user/totp/disable', {method:'POST'}); await refreshTotp(); }
  catch(err){ alert('Errore: '+err.message); }
});
document.getElementById('formTotpConfirm')?.addEventListener('submit', async (e)=>{
  e.preventDefault();
  const otp = new FormData(e.target).get('otp');
  try{
    await api('/api/user/totp/confirm', {method:'POST', body: JSON.stringify({otp})});
    alert('2FA abilitata!'); setupBox.classList.add('hidden'); await refreshTotp();
  }catch(err){ alert('Codice non valido: '+err.message); }
});
document.getElementById('btnCancelTotp')?.addEventListener('click', ()=> setupBox.classList.add('hidden'));

// Admin UI
async function refreshMe(){
  if(!token) return;
  try{
    const me = await api('/api/me');
    const lbl = document.getElementById('currentUserLabel');
    if(lbl) lbl.textContent = (me.user || '') + (me.is_admin ? ' (admin)' : '');
    const adm = document.getElementById('adminUsers');
    if(adm) adm.style.display = me.is_admin ? 'block' : 'none';
    if(me.is_admin){ await refreshUsers(); }
  }catch(e){
    const lbl = document.getElementById('currentUserLabel');
    if(lbl) lbl.textContent='';
    const adm = document.getElementById('adminUsers');
    if(adm) adm.style.display='none';
  }
}

async function refreshUsers(){
  if(!token) return;
  try{
    const users = await api('/api/users');
    const box = document.getElementById('usersList'); 
    if(box){
      box.innerHTML='';
      users.forEach(u=>{
        const div = document.createElement('div'); div.className='card';
        div.innerHTML = '<div><strong>'+u+'</strong></div><div class="small muted">Gestisci password e 2FA</div>';
        box.appendChild(div);
      });
    }
  }catch(e){ console.warn('users list', e); }
}

// --- HOME: STATO
window.refreshStatus = async function(){
  if(!token) return;
  try{
    const s = await api('/api/status');
    const wrap = document.getElementById('statusCards');
    if(!wrap) return;
    wrap.innerHTML = '';
    const card = (title, value) => `<div class="card"><div class="kpi"><div class="kpi-title">${title}</div><div class="kpi-value">${value}</div></div></div>`;
    wrap.insertAdjacentHTML('beforeend', card('Stato', s.state));
    wrap.insertAdjacentHTML('beforeend', card('Tamper', s.tamper ? 'ATTIVO' : 'OK'));
    wrap.insertAdjacentHTML('beforeend', card('Zone attive', s.zones_active.filter(Boolean).length + ' / ' + s.zones_count));
  }catch(e){ console.warn(e); }
};

// --- HOME: ZONE
window.refreshZones = async function(){
  if(!token) return;
  try{
    const z = await api('/api/zones');
    const g = document.getElementById('zonesGrid');
    if(!g) return;
    g.innerHTML = '';
    z.zones.forEach(zz=>{
      const cls = zz.active ? 'chip on' : 'chip';
      g.insertAdjacentHTML('beforeend', `<div class="card mini"><div class="${cls}">${zz.name}</div></div>`);
    });
  }catch(e){ console.warn(e); }
};

// --- HOME: SCENARI
window.refreshScenes = async function(){
  if(!token) return;
  try{
    const s = await api('/api/scenes');
    const root = document.getElementById('scenesWrap');
    if(!root) return;
    root.innerHTML = '';

    function renderScene(name, mask){
      const num = s.zones;
      const ids = [];
      for(let i=1;i<=num;i++){ if(mask & (1<<(i-1))) ids.push(i); }
      const checks = Array.from({length:num}, (_,i)=>{
        const id=i+1; const on = ids.includes(id);
        return `<label class="chk"><input type="checkbox" data-sc="${name}" data-id="${id}" ${on?'checked':''}>Z${id}</label>`;
      }).join('');
      return `<div class="card"><h2>${name.toUpperCase()}</h2><div class="checks">${checks}</div><div class="actions"><button class="primary" data-save="${name}">Salva</button></div></div>`;
    }

    root.insertAdjacentHTML('beforeend', renderScene('home', s.home));
    root.insertAdjacentHTML('beforeend', renderScene('night', s.night));
    root.insertAdjacentHTML('beforeend', renderScene('custom', s.custom));

    root.querySelectorAll('button[data-save]').forEach(btn=>{
      btn.addEventListener('click', async ()=>{
        const name = btn.dataset.save;
        const boxes = root.querySelectorAll(`input[type=checkbox][data-sc="${name}"]`);
        const ids = Array.from(boxes).filter(b=>b.checked).map(b=>parseInt(b.dataset.id,10));
        try{
          await api('/api/scenes', {method:'POST', body: JSON.stringify({scene:name, ids})});
          alert('Scena salvata.');
          if(window.refreshScenes) window.refreshScenes();
        }catch(e){ alert('Errore: '+e.message); }
      });
    });
  }catch(e){ console.warn(e); }
};


document.getElementById('adm_set_pass')?.addEventListener('click', async ()=>{
  const usr = document.getElementById('adm_user_name').value.trim();
  const np  = document.getElementById('adm_new_pass').value;
  if(!usr || !np) { alert('Inserisci utente e nuova password'); return; }
  try{ await api('/api/users/password', {method:'POST', body: JSON.stringify({user:usr, newpass:np})}); alert('Password aggiornata.'); }
  catch(e){ alert('Errore: '+e.message); }
});

document.getElementById('adm_reset_totp')?.addEventListener('click', async ()=>{
  const usr = document.getElementById('adm_user_name').value.trim();
  if(!usr) { alert('Inserisci utente'); return; }
  if(!confirm('Reset 2FA per '+usr+'?')) return;
  try{ await api('/api/users/totp/reset', {method:'POST', body: JSON.stringify({user:usr})}); alert('2FA resettata.'); }
  catch(e){ alert('Errore: '+e.message); }
});

// Startup
setActiveTab('status');
if(token){ 
  showApp(); 
  refreshMe(); 
  refreshTotp(); 
} else { 
  showLogin(); 
}