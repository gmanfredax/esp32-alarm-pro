// /spiffs/app.js
(() => {
  const $  = (s, r=document) => r.querySelector(s);
  const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));

  let token = localStorage.getItem("token") || "";
  let isAdmin = false;
  let currentUser = "";

  // stato login 2-step
  let pendingUser = null, pendingPass = null;

  // ---------------- HTTP helpers ----------------
  async function apiGet(path){
    const r = await fetch(path, { headers: token ? { "X-Auth-Token": token } : {} });
    if (r.status === 401) { needLogin(); throw new Error("401"); }
    if (!r.ok) throw new Error(path+" -> "+r.status);
    return r.json();
  }
  async function apiPost(path, body){
    const r = await fetch(path, {
      method: "POST",
      headers: Object.assign({ "Content-Type":"application/json" }, token ? { "X-Auth-Token": token } : {}),
      body: body!=null ? JSON.stringify(body) : undefined
    });
    return r;
  }

  // ---------------- UI helpers -----------------
  function needLogin(){
    $("#appRoot")?.classList.add("hidden");
    $("#authCover")?.classList.remove("hidden");
    showLoginStep1();
  }
  function afterLoginUI(){
    $("#authCover")?.classList.add("hidden");
    $("#appRoot")?.classList.remove("hidden");
  }
  function clearModals(){ $("#modals-root").innerHTML = ""; }
  function showModal(innerHtml){
    clearModals();
    const root = $("#modals-root");
    root.innerHTML = `<div class="modal-overlay"><div class="card modal">${innerHtml}</div></div>`;
    return root.firstElementChild;
  }

  // -------------- Login STEP 1 --------------
  function showLoginStep1(){
    const m = showModal(`
      <h3 class="title" style="text-align:center">LOGIN</h3>
      <form id="f1" class="form" autocomplete="on">
        <label class="field"><span>Username</span><input id="lg_user" autocomplete="username" /></label>
        <label class="field"><span>Password</span><input id="lg_pass" type="password" autocomplete="current-password" /></label>
        <div class="row" style="justify-content:center; margin-top:.5rem">
          <button type="submit" class="btn primary">Login</button>
        </div>
        <div id="lg_err" class="msg small" style="color:#f66; text-align:center; display:none"></div>
      </form>
    `);
    $("#f1").onsubmit = async (e)=>{
      e.preventDefault();
      $("#lg_err").style.display="none";
      const user = $("#lg_user").value.trim();
      const pass = $("#lg_pass").value;
      if(!user||!pass){ $("#lg_err").textContent="Compila utente e password."; $("#lg_err").style.display="block"; return; }
      const r = await apiPost("/api/login", { user, pass });
      if (r.status === 200) {
        const j = await r.json(); token=j.token; localStorage.setItem("token", token); clearModals(); await afterLogin();
      } else if (r.status === 409) {
        pendingUser=user; pendingPass=pass; showLoginStep2();
      } else {
        $("#lg_err").textContent = "Credenziali non valide."; $("#lg_err").style.display="block";
      }
    };
    $("#lg_user").focus();
  }

  // -------------- Login STEP 2 (OTP) --------------
  function showLoginStep2(){
    const m = showModal(`
      <h3 class="title" style="text-align:center">LOGIN</h3>
      <form id="f2" class="form" autocomplete="one-time-code">
        <label class="field"><span>Google Auth OTP</span><input id="lg_otp" inputmode="numeric" maxlength="6" /></label>
        <div class="row" style="justify-content:center; margin-top:.5rem">
          <button type="submit" class="btn primary">Login</button>
        </div>
        <div id="lg_err2" class="msg small" style="color:#f66; text-align:center; display:none"></div>
      </form>
    `);
    $("#f2").onsubmit = async (e)=>{
      e.preventDefault();
      $("#lg_err2").style.display="none";
      const otp = $("#lg_otp").value.trim();
      const r = await apiPost("/api/login", { user: pendingUser, pass: pendingPass, otp });
      if (r.status === 200) {
        const j = await r.json(); token=j.token; localStorage.setItem("token", token); pendingUser=pendingPass=null; clearModals(); await afterLogin();
      } else {
        $("#lg_err2").textContent = "OTP non valido."; $("#lg_err2").style.display="block";
      }
    };
    $("#lg_otp").focus();
  }

  // -------------- Header / menu utente --------------
  function syncHeader(){
    $("#userLabel").textContent = `${currentUser}${isAdmin ? " (admin)" : ""}`;
  }
  function mountUserMenu(){
    const btn = $("#userBtn"), dd = $("#userDropdown");
    btn.onclick = (e)=>{ e.stopPropagation(); dd.classList.toggle("hidden"); };
    document.addEventListener("click", ()=>dd.classList.add("hidden"));
    dd.querySelector("[data-act=settings]").onclick = ()=>{ dd.classList.add("hidden"); showUserSettings(); };
    dd.querySelector("[data-act=logout]").onclick   = async ()=>{ dd.classList.add("hidden"); try{await apiPost("/api/logout",{});}catch{} token=""; localStorage.removeItem("token"); needLogin(); };
  }

  // -------------- Impostazioni utente (pwd + TOTP) --------------
  async function showUserSettings(){
    // leggo stato TOTP
    let totp = {enabled:false};
    try{ totp = await apiGet("/api/user/totp"); }catch{}
    const m = showModal(`
      <h3 class="title">Impostazioni utente</h3>
      <div class="form">
        <h4>Cambia password</h4>
        <label class="field"><span>Password attuale</span><input id="pw_cur" type="password" autocomplete="current-password"></label>
        <label class="field"><span>Nuova password</span><input id="pw_new" type="password" autocomplete="new-password"></label>
        <div class="row" style="justify-content:flex-end"><button class="btn small" id="pw_save">Salva</button></div>
        <div id="pw_msg" class="msg small" style="display:none"></div>
      </div>
      <hr style="border:0;border-top:1px solid rgba(255,255,255,.06);margin:.75rem 0">
      <div class="form">
        <h4>Autenticazione a 2 fattori (TOTP)</h4>
        <div id="totp_block">
          ${totp.enabled ? `
            <p>2FA attiva.</p>
            <div class="row" style="justify-content:flex-end; gap:.5rem">
              <button class="btn small" id="totp_disable">Disattiva</button>
            </div>
          ` : `
            <p>2FA non attiva.</p>
            <div class="row" style="justify-content:flex-end; gap:.5rem">
              <button class="btn small" id="totp_enable">Abilita</button>
            </div>
          `}
        </div>
        <div id="totp_msg" class="msg small" style="display:none"></div>
      </div>
      <div class="row" style="justify-content:flex-end; margin-top:.75rem"><button class="btn" id="close_modal">Chiudi</button></div>
    `);
    $("#close_modal").onclick = clearModals;

    // cambio password
    $("#pw_save").onclick = async ()=>{
      $("#pw_msg").style.display="none";
      const current = $("#pw_cur").value, newpass = $("#pw_new").value;
      if(!current||!newpass){ msg("#pw_msg","Compila i campi"); return; }
      const r = await apiPost("/api/user/password",{current,newpass});
      if(r.ok){ msg("#pw_msg","Password aggiornata",true); $("#pw_cur").value=""; $("#pw_new").value=""; }
      else { msg("#pw_msg","Errore "+r.status); }
    };

    // TOTP enable/confirm/disable
    $("#totp_enable")?.addEventListener("click", async ()=>{
      const info = await (await apiPost("/api/user/totp/enable",{})).json();
      // mostro secret + campo OTP per conferma
      $("#totp_block").innerHTML = `
        <p>Scansiona in Google Authenticator:</p>
        <div class="card" style="padding:.6rem"><code style="user-select:all">${info.otpauth_uri}</code></div>
        <label class="field" style="margin-top:.5rem"><span>Inserisci OTP</span><input id="totp_code" inputmode="numeric" maxlength="6"></label>
        <div class="row" style="justify-content:flex-end; gap:.5rem">
          <button class="btn small" id="totp_confirm">Conferma</button>
        </div>`;
      $("#totp_confirm").onclick = async ()=>{
        const otp = $("#totp_code").value.trim();
        const r = await apiPost("/api/user/totp/confirm",{otp});
        if(r.ok){ msg("#totp_msg","2FA abilitata",true); showUserSettings(); }
        else { msg("#totp_msg","OTP non valido"); }
      };
    });
    $("#totp_disable")?.addEventListener("click", async ()=>{
      const r = await apiPost("/api/user/totp/disable",{});
      if(r.ok){ msg("#totp_msg","2FA disattivata",true); showUserSettings(); }
      else { msg("#totp_msg","Errore "+r.status); }
    });

    function msg(sel, text, ok=false){ const n=$(sel); n.textContent=text; n.style.color = ok ? "#7fdc9f" : "#f66"; n.style.display="block"; }
  }

  // -------------- STATUS --------------
  function kpiCard({title, valueHTML}) {
    return `<div class="card"><div class="kpi"><div class="kpi-title">${title}</div><div class="kpi-value">${valueHTML}</div></div></div>`;
  }
  async function refreshStatus(){
    try{
      const s = await apiGet("/api/status");
      let icon = "";
      switch (s.state) {
        case "DISARMED": icon = `<svg xmlns="http://www.w3.org/2000/svg" class="ico s ok" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="m9 12 2 2 4-4"/><circle cx="12" cy="12" r="9"/></svg>`; break;
        case "ALARM": icon = `<svg xmlns="http://www.w3.org/2000/svg" class="ico s" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>`; break;
        default: icon = `<svg xmlns="http://www.w3.org/2000/svg" class="ico s" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="9"/></svg>`;
      }
      const activeCount = Array.isArray(s.zones_active) ? s.zones_active.filter(Boolean).length : 0;
      const total = s.zones_count || (s.zones_active ? s.zones_active.length : 0);
      const tamper = s.tamper ? `<span class="tag">ALLARME</span>` : `<span class="tag ok">OK</span>`;
      $("#statusCards").innerHTML = [
        kpiCard({ title:"Stato", valueHTML:`${icon} ${s.state}` }),
        kpiCard({ title:"Tamper", valueHTML: tamper }),
        kpiCard({ title:"Zone attive", valueHTML:`${activeCount} / ${total}` }),
      ].join("");
    }catch(_){}
  }
  window.refreshStatus = refreshStatus;

  // -------------- ZONES (view + rename + config) --------------
  async function refreshZones(){
    try{
      const z = await apiGet("/api/zones"); // {zones:[{id,name,active}]}
      $("#zonesGrid").innerHTML = z.zones.map(zz =>
        `<div class="card mini">
           <div class="chip ${zz.active ? "on":""}" data-zone-id="${zz.id}" title="${zz.name}">${zz.name || ("Z"+zz.id)}</div>
           ${isAdmin ? `<button class="btn tiny" data-rename="${zz.id}" style="margin-top:.3rem">Rinomina</button>`:""}
         </div>`
      ).join("");
      if (isAdmin){
        $$("button[data-rename]").forEach(b=>{
          b.onclick = async ()=>{
            const id = +b.dataset.rename;
            const cur = $(`.chip[data-zone-id="${id}"]`).textContent.trim();
            const nu = prompt(`Nome per zona ${id}:`, cur);
            if (nu && nu !== cur) {
              const r = await apiPost("/api/zones/name", { id, name: nu });
              if (r.ok) refreshZones(); else alert("Errore salvataggio nome");
            }
          };
        });
      }
    }catch(_){}
  }
  window.refreshZones = refreshZones;

  // bottone "Configura zone"
  $("#btnZonesCfg")?.addEventListener("click", async ()=>{
    try{
      const cfg = await apiGet("/api/zones/config"); // {items:[{id,name,entry_delay,entry_time,exit_delay,exit_time,auto_exclude}]}
      const body = cfg.items.map(it => `
        <div class="card" data-zid="${it.id}" style="margin-bottom:.5rem">
          <div class="row between"><strong>${it.name || ("Z"+it.id)}</strong><small>ID ${it.id}</small></div>
          <div class="form">
            <div class="row"><label class="chk"><input type="checkbox" data-k="entry_delay" ${it.entry_delay?"checked":""}> Ritardo ingresso</label><input type="number" min="0" max="300" value="${it.entry_time||0}" data-k="entry_time" style="width:6rem"> <small>s</small></div>
            <div class="row"><label class="chk"><input type="checkbox" data-k="exit_delay"  ${it.exit_delay ?"checked":""}> Ritardo uscita</label><input type="number" min="0" max="300" value="${it.exit_time ||0}" data-k="exit_time"  style="width:6rem"> <small>s</small></div>
            <div class="row"><label class="chk"><input type="checkbox" data-k="auto_exclude" ${it.auto_exclude?"checked":""}> Esclusione automatica</label></div>
          </div>
        </div>`).join("");

      const m = showModal(`
        <h3 class="title">Configurazione zone</h3>
        <div class="scroll" style="max-height:60vh; overflow:auto; padding-right:.5rem">${body}</div>
        <div class="row" style="justify-content:flex-end; gap:.5rem; margin-top:.75rem">
          <button class="btn" id="zc_close">Chiudi</button>
          <button class="btn primary" id="zc_save">Salva</button>
        </div>
      `);
      $("#zc_close").onclick = clearModals;
      $("#zc_save").onclick = async ()=>{
        const items = $$(".card[data-zid]").map(card=>{
          const id = +card.dataset.zid;
          const val = k=> card.querySelector(`[data-k="${k}"]`);
          return {
            id,
            entry_delay:  !!val("entry_delay").checked,
            entry_time:   +val("entry_time").value||0,
            exit_delay:   !!val("exit_delay").checked,
            exit_time:    +val("exit_time").value||0,
            auto_exclude: !!val("auto_exclude").checked,
          };
        });
        const r = await apiPost("/api/zones/config", { items });
        if (r.ok){ clearModals(); refreshZones(); } else alert("Errore salvataggio");
      };
    }catch(_){ alert("Impossibile leggere configurazione zone"); }
  });

  // -------------- SCENES --------------
  function buildSceneCard({label, sceneKey, mask, zonesCount}){
    const checks = Array.from({length: zonesCount}, (_,i)=>{
      const id = i+1, on = (mask >>> i) & 1;
      return `<label class="chk"><input type="checkbox" data-scene="${sceneKey}" data-zone="${id}" ${on?"checked":""}> Z${id}</label>`;
    }).join("");
    return `
      <div class="card">
        <div class="card-head">
          <div class="title">
            ${sceneKey==="home" ? `<svg xmlns="http://www.w3.org/2000/svg" class="ico s" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M3 10.5 12 3l9 7.5"/><path d="M5 9.5v11h14v-11"/></svg>`
             : sceneKey==="night" ? `<svg xmlns="http://www.w3.org/2000/svg" class="ico s" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z"/></svg>`
             : `<svg xmlns="http://www.w3.org/2000/svg" class="ico s" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>`}
            <h2>${label}</h2>
          </div>
          <button class="btn primary small" data-save="${sceneKey}" ${isAdmin?"":"disabled title='Solo admin'"}>Salva</button>
        </div>
        <div class="checks">${checks}</div>
      </div>`;
  }
  async function refreshScenes(){
    try{
      const s = await apiGet("/api/scenes"); // {zones, home, night, custom, active}
      $("#scenesWrap").innerHTML = [
        buildSceneCard({label:"HOME",   sceneKey:"home",   mask:s.home,   zonesCount:s.zones}),
        buildSceneCard({label:"NOTTE",  sceneKey:"night",  mask:s.night,  zonesCount:s.zones}),
        buildSceneCard({label:"CUSTOM", sceneKey:"custom", mask:s.custom, zonesCount:s.zones}),
      ].join("");
      $$("button[data-save]").forEach(btn=>{
        btn.onclick = async ()=>{
          if (!isAdmin) return;
          const scene = btn.dataset.save;
          const checks = $$(`input[type=checkbox][data-scene="${scene}"]`);
          let mask = 0; checks.forEach(ch => { const z = +ch.dataset.zone; if (ch.checked) mask |= (1 << (z-1)); });
          const r = await apiPost("/api/scenes", { scene, mask });
          if (!r.ok) alert("Errore salvataggio scena");
        };
      });
    }catch(_){}
  }
  window.refreshScenes = refreshScenes;

  // -------------- After login --------------
  async function afterLogin(){
    try{
      const me = await apiGet("/api/me"); // {user,is_admin}
      currentUser = me.user || "";
      isAdmin = !!me.is_admin;
      syncHeader();
      mountUserMenu();
      afterLoginUI();
      await Promise.all([refreshStatus(), refreshZones(), refreshScenes()]);
      setInterval(refreshStatus, 2000);
      setInterval(refreshZones,  2000);
    setInterval(refreshScenes, 10000);
    }catch(_){ needLogin(); }
  }

  // boot
  window.addEventListener("DOMContentLoaded", async () => {
    if (!token) needLogin();
    else await afterLogin();
  });
})();
