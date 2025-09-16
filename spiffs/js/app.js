// /spiffs/js/app.js
(() => {
  const $  = (s, r=document) => r.querySelector(s);
  const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));

  // === SHIM GLOBALE FETCH: cookie same-origin + Authorization: Bearer ========
  (function installAuthFetchShim(){
    const _fetch = window.fetch;
    window.fetch = (input, init = {}) => {
      const headers = new Headers(init.headers || {});
      const t = (()=>{ try { return localStorage.getItem("token") || sessionStorage.getItem("token") || ""; } catch { return ""; }})();
      if (t && !headers.has("Authorization")) headers.set("Authorization", "Bearer " + t);
      const creds = init.credentials ? init.credentials : "same-origin";
      return _fetch(input, { ...init, headers, credentials: creds });
    };
  })();

  const getToken = () => { try { return localStorage.getItem("token") || sessionStorage.getItem("token") || ""; } catch { return ""; } };

  let isAdmin = false;
  let currentUser = "";

  // ---------------- HTTP helpers ----------------
  function authHeaders(extra = {}) {
    const h = { ...extra };
    const t = getToken();
    if (t && !h["Authorization"]) h["Authorization"] = "Bearer " + t;
    return h;
  }
  async function apiGet(path){
    const r = await fetch(path, { headers: authHeaders() });
    if (r.status === 401) { needLogin(); throw new Error("401"); }
    if (!r.ok) throw new Error(path+" -> "+r.status);
    return r.json();
  }
  async function apiPost(path, body){
    const r = await fetch(path, {
      method: "POST",
      headers: authHeaders({ "Content-Type":"application/json" }),
      body: body!=null ? JSON.stringify(body) : undefined
    });
    if (r.status === 401) { needLogin(); throw new Error("401"); }
    return r;
  }

  // ---------------- UI helpers -----------------

  // --- Stato: labels + renderer DRY -------------------------------------------
  const STATE_LABELS = Object.freeze({
    DISARMED:     "Disarmato",
    ARMED_HOME:   "Attivo in casa",
    ARMED_AWAY:   "Attivo fuori casa",
    ARMED_NIGHT:  "Attivo Notte",
    ARMED_CUSTOM: "Attivo Personalizzato",
    ALARM:        "Allarme",
    MAINT:        "Manutenzione",
    PRE_ARM:      "Attivazione in corso",
    PRE_DISARM:   "Pre allarme",
  });

  function stateText(status){
    if (status.state === "PRE_DISARM") {
      const z = Number.isInteger(status.entry_zone) && status.entry_zone > 0 ? ` (Z${status.entry_zone})` : "";
      return STATE_LABELS.PRE_DISARM + z;
    }
    return STATE_LABELS[status.state] || status.state;
  }

  function renderAlarmState(containerEl, status, { iconHTML = "" } = {}){
    try{
      if (containerEl._preTimer) { clearInterval(containerEl._preTimer); containerEl._preTimer = null; }
      const isPre = (status.state === "PRE_ARM" || status.state === "PRE_DISARM");
      const label = stateText(status);

      // PRE_*: solo testo lampeggiante, nessun countdown
      if (isPre){
        containerEl.innerHTML = `${iconHTML} <span class="blink">${label}</span>`;
        const labelEl = containerEl.querySelector('.blink');
        containerEl._preTimer = setInterval(() => {
          if (!labelEl || !document.body.contains(labelEl)) {
            clearInterval(containerEl._preTimer); containerEl._preTimer = null; return;
          }
          const on = (Math.floor(Date.now() / 500) % 2) === 0;
          labelEl.style.opacity = on ? "1" : "0.35";
        }, 250);
        return;
      }

      // Stati normali: testo fisso
      containerEl.innerHTML = `${iconHTML} ${label}`;
    }catch(e){ console.warn("renderAlarmState error", e); }
  }

  function needLogin(){
    try { localStorage.removeItem("token"); } catch(_) {}
    try { sessionStorage.removeItem("token"); } catch(_) {}
    window.location.replace("/login.html");
  }
  function afterLoginUI(){
    $("#appRoot")?.classList.remove("hidden");
  }

  // tabs
  function setActiveTab(name){
    $$(".tab-btn").forEach(b => b.classList.toggle('active', b.dataset.tab===name));
    $$(".tab").forEach(s => s.classList.toggle('active', s.id === 'tab-'+name));
    if (name==='status') refreshStatus();
    if (name==='zones')  refreshZones();
    if (name==='scenes') refreshScenes();
  }
  document.addEventListener("click", (e)=>{
    const b = e.target.closest(".tab-btn");
    if (b) setActiveTab(b.dataset.tab);
  });

  function clearModals(){ const el=$("#modals-root"); if (el) el.innerHTML=""; }
  function promptPin(onSubmit){
    const m = showModal(`
      <h3>Inserisci PIN</h3>
      <div class="form">
        <label class="field"><span>PIN</span><input id="pin_input" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="12" autofocus></label>
        <div class="row" style="justify-content:flex-end; gap:.5rem">
          <button class="btn secondary" id="pin_cancel">Annulla</button>
          <button class="btn" id="pin_ok">OK</button>
        </div>
        <div id="pin_msg" class="msg small" style="display:none"></div>
      </div>
    `);
    if (!m) return;
    const _pinInput = m.querySelector('#pin_input');
    const _okBtn = m.querySelector('#pin_ok');
    if (_pinInput && _okBtn) {
      _pinInput.addEventListener('keydown', (e)=>{ if (e.key === 'Enter') { e.preventDefault(); _okBtn.click(); } });
    }
    $("#pin_cancel").onclick = ()=> clearModals();
    $("#pin_ok").onclick = async ()=> {
      const pin = $("#pin_input").value.trim();
      if (!pin) { const n=$("#pin_msg"); n.style.display="block"; n.textContent="PIN richiesto"; n.style.color="#f66"; return; }
      await onSubmit(pin);
      clearModals();
    };
  }

  function showModal(innerHtml){
    clearModals();
    const root = $("#modals-root");
    if (!root) return null;
    root.innerHTML = `<div class="modal-overlay"><div class="card modal">${innerHtml}</div></div>`;
    return root.firstElementChild;
  }

  // -------------- Header / menu utente --------------
  function syncHeader(){ $("#userLabel") && ($("#userLabel").textContent = `${currentUser}${isAdmin ? " (admin)" : ""}`); }
  
  function updateAdminVisibility(){
    $$('.admin-only').forEach(el => { el.style.display = isAdmin ? '' : 'none'; });
    const zBtn = $('#btnZonesCfg');
    if (zBtn) zBtn.style.display = isAdmin ? '' : 'none';
  }

  function mountUserMenu(){
    const btn = $("#userBtn"), dd = $("#userDropdown");
    if (!btn || !dd) return;
    btn.onclick = (e)=>{ e.stopPropagation(); dd.classList.toggle("hidden"); };
    document.addEventListener("click", ()=>dd.classList.add("hidden"));
    dd.querySelector("[data-act=sys_settings]")?.addEventListener("click", ()=>{ dd.classList.add("hidden"); location.href="/admin.html"; });
    dd.querySelector("[data-act=settings]")?.addEventListener("click", ()=>{ dd.classList.add("hidden"); showUserSettings(); });
    dd.querySelector("[data-act=logout]")?.addEventListener("click", async ()=>{
      dd.classList.add("hidden");
      try{ await apiPost("/api/logout",{});}catch{}
      try { localStorage.removeItem("token"); } catch(_){}
      try { sessionStorage.removeItem("token"); } catch(_){}
      needLogin();
    });
  }

  // -------------- Impostazioni utente (pwd + TOTP) --------------
  async function showUserSettings(){
    let totp = {enabled:false};
    try{ totp = await apiGet("/api/user/totp"); }catch{}
    showModal(`
      <h3 class="title">Impostazioni utente</h3>
      <div class="form">
        <h4>Cambia password</h4>
        <label class="field"><span>Password attuale</span><input id="pw_cur" type="password" autocomplete="current-password"></label>
        <label class="field"><span>Nuova password</span><input id="pw_new" type="password" autocomplete="new-password"></label>
        <div class="row" style="justify-content:flex-end"><button class="btn small" id="pw_save">Salva</button></div>
        <div id="pw_msg" class="msg small" style="display:none"></div>
      </div>
      <!--<hr style="border:0;border-top:1px solid rgba(255,255,255,.06);margin:.75rem 0">
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
      </div>-->
      <hr style="border:0;border-top:1px solid rgba(255,255,255,.06);margin:.75rem 0">
      <div class="form">
        <h4>PIN allarme</h4>
        <label class="field"><span>Nuovo PIN (4-12 cifre)</span><input id="pin_new" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="12"></label>
        <div class="row" style="justify-content:flex-end"><button class="btn small" id="pin_save">Salva PIN</button></div>
        <div id="pin_msg_save" class="msg small" style="display:none"></div>
      </div>
      <div id="totp_msg" class="msg small" style="display:none"></div>
      <div class="row" style="justify-content:flex-end; margin-top:.75rem"><button class="btn" id="close_modal">Chiudi</button></div>
      </div>
      
    `);
    $("#close_modal").onclick = clearModals;

    // cambio password
    $("#pw_save").onclick = async ()=>{
      const current = $("#pw_cur").value, newpass = $("#pw_new").value;
      try{
        const r = await apiPost("/api/user/password",{current,newpass});
        const n = $("#pw_msg"); n.style.display="block";
        if(r.ok){ n.textContent="Password aggiornata"; n.style.color="#7fdc9f"; $("#pw_cur").value=""; $("#pw_new").value=""; }
        else { n.textContent="Errore "+r.status; n.style.color="#f66"; }
      }catch{ const n=$("#pw_msg"); n.style.display="block"; n.textContent="Errore di rete"; n.style.color="#f66"; }
    };

    // Salvataggio PIN
    $("#pin_save")?.addEventListener("click", async ()=>{
      try{
        const pin = $("#pin_new").value.trim();
        const r = await fetch("/api/user/pin", {method:"POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({pin})});
        const n = $("#pin_msg_save"); n.style.display="block";
        if(r.ok){ n.textContent="PIN salvato"; n.style.color="#7fdc9f"; $("#pin_new").value=""; }
        else { n.textContent="Errore "+r.status; n.style.color="#f66"; }
      }catch{ const n=$("#pin_msg_save"); n.style.display="block"; n.textContent="Errore di rete"; n.style.color="#f66"; }
    });

    // TOTP enable/confirm/disable
    $("#totp_enable")?.addEventListener("click", async ()=>{
      const info = await (await apiPost("/api/user/totp/enable",{})).json();
      $("#totp_block").innerHTML = `
        <p>Scansiona con Google Authenticator:</p>
        <div class="row" style="gap:1rem; align-items:flex-start; margin:.5rem 0">
          <div id="totp_qr" class="card" style="padding:.6rem"></div>
          <div class="card" style="padding:.6rem; max-width:100%; overflow:auto">
            <code style="user-select:all; word-break:break-all">${info.otpauth_uri || "(URI non fornito)"}</code>
          </div>
        </div>
        <label class="field" style="margin-top:.5rem">
          <span>Inserisci OTP</span>
          <input id="totp_code" inputmode="numeric" maxlength="6">
        </label>
        <div class="row" style="justify-content:flex-end; gap:.5rem">
          <button class="btn small" id="totp_confirm">Conferma</button>
        </div>`;
      await ensureQRCodeLib();
      try {
        if (info.otpauth_uri) {
          new QRCode(document.getElementById("totp_qr"), {
            text: info.otpauth_uri, width: 180, height: 180, correctLevel: QRCode.CorrectLevel.M
          });
        }
      } catch(e) { console.warn("QRCode generation failed", e); }
      $("#totp_confirm").onclick = async ()=>{
        const otp = $("#totp_code").value.trim();
        try{
          const r = await apiPost("/api/user/totp/confirm",{otp});
          const n = $("#totp_msg"); n.style.display="block";
          if (r.ok){ n.textContent="2FA abilitata"; n.style.color="#7fdc9f"; showUserSettings(); }
          else if (r.status === 409){ n.textContent="Orologio non sincronizzato. Riprova."; n.style.color="#ff0"; }
          else { n.textContent="OTP non valido"; n.style.color="#f66"; }
        }catch{ const n=$("#totp_msg"); n.style.display="block"; n.textContent="Errore di rete"; n.style.color="#f66"; }
      };
    });
    $("#totp_disable")?.addEventListener("click", async ()=>{
      try{
        const r = await apiPost("/api/user/totp/disable",{});
        const n = $("#totp_msg"); n.style.display="block";
        if(r.ok){ n.textContent="2FA disattivata"; n.style.color="#7fdc9f"; showUserSettings(); }
        else { n.textContent="Errore "+r.status; n.style.color="#f66"; }
      }catch{ const n=$("#totp_msg"); n.style.display="block"; n.textContent="Errore di rete"; n.style.color="#f66"; }
    });
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
      // const activeCount = Array.isArray(s.zones_active) ? s.zones_active.filter(Boolean).length : 0;
      // const total = s.zones_count || (s.zones_active ? s.zones_active.length : 0);
      // const tamper = s.tamper ? `<span class="tag">ALLARME</span>` : `<span class="tag ok">OK</span>`;
      // $("#statusCards") && ($("#statusCards").innerHTML = [
      //   kpiCard({ title:"Stato", valueHTML:`${icon} ${s.state}` }),
      // Stato (con PRE_* e countdown)
      const activeCount = Array.isArray(s.zones_active) ? s.zones_active.filter(Boolean).length : 0;
      const total = s.zones_count || (s.zones_active ? s.zones_active.length : 0);
      const tamper = s.tamper ? `<span class="tag">ALLARME</span>` : `<span class="tag ok">OK</span>`;
      
      if ($("#statusCards")){
        $("#statusCards").innerHTML = [
          kpiCard({ title:"Stato", valueHTML:`<span id="kpi-state-val"></span>` }),
          kpiCard({ title:"Tamper", valueHTML: tamper }),
          kpiCard({ title:"Zone attive", valueHTML:`${activeCount} / ${total}` }),
        ].join("");
        const stateEl = document.getElementById("kpi-state-val");
        if (stateEl) renderAlarmState(stateEl, s, { iconHTML: icon });
      }
    
    }catch(_){}
  }
  window.refreshStatus = refreshStatus;

  // // -------------- ZONES --------------
  // async function refreshZones(){
  //   try{
  //     const z = await apiGet("/api/zones");
  //     $("#zonesGrid") && ($("#zonesGrid").innerHTML = z.zones.map(zz =>
  //       `<div class="card mini">
  //          <div class="chip ${zz.active ? "on":""}" data-zone-id="${zz.id}" title="${zz.name}">${zz.name || ("Z"+zz.id)}</div>
  //          <div style="display: flex; align-items: center; margin-top: .3rem; justify-content: space-between;">
  //           <div>${isAdmin ? `<button class="btn tiny" data-rename="${zz.id}" style="margin-top:.3rem">Rinomina</button>`:""}</div>
  //           <div style="display: flex;justify-content: space-between;">
  //             <p class="" style="padding: 0 .25rem 0 0; color: yellow;">AE</p><p class="" style="color: yellow; padding: 0 .25rem 0 0;">R</p>
  //           </div>
  //         </div>
  //        </div>`
  //     ).join(""));
  //     if (isAdmin){
  //       $$("button[data-rename]").forEach(b=>{
  //         b.onclick = async ()=>{
  //           const id = +b.dataset.rename;
  //           const node = $(`.chip[data-zone-id="${id}"]`);
  //           const cur = node ? node.textContent.trim() : "";
  //           const nu = prompt(`Nome per zona ${id}:`, cur);
  //           if (nu && nu !== cur) {
  //             const r = await apiPost("/api/zones/config", { items:[{id, name: nu}] });
  //             if (r.ok) refreshZones(); else alert("Errore salvataggio nome");
  //           }
  //         };
  //       });
  //     }
  //   }catch(_){}
  // }
  // window.refreshZones = refreshZones;

  // -------------- ZONES --------------
  async function refreshZones(){
    try{
      const z = await apiGet("/api/zones");

      // Se /api/zones non porta i flag, recupera /api/zones/config come fallback.
      let _zonesCfgMap = null;
      try{
        const sample = (z && z.zones && z.zones.length) ? z.zones[0] : {};
        if (sample && (typeof sample.auto_exclude === "undefined" ||
                      typeof sample.zone_delay   === "undefined" ||
                      typeof sample.zone_time    === "undefined")){
          const cfgResp = await apiGet("/api/zones/config");
          _zonesCfgMap = {};
          (cfgResp.items || []).forEach(it => { _zonesCfgMap[it.id] = it; });
        }
      }catch(_){}

      const html = (z.zones || []).map(zz => {
        const cfg = _zonesCfgMap && _zonesCfgMap[zz.id] ? _zonesCfgMap[zz.id] : null;

        const auto_exclude = (typeof zz.auto_exclude !== "undefined") ? !!zz.auto_exclude : !!(cfg && cfg.auto_exclude);
        const zone_delay   = (typeof zz.zone_delay   !== "undefined") ? !!zz.zone_delay   : !!(cfg && cfg.zone_delay);
        const zone_time    = (typeof zz.zone_time    !== "undefined") ? (+zz.zone_time||0): ((cfg && +cfg.zone_time)||0);

        const aeBadge = auto_exclude ? `<span class="badge" title="Autoesclusione">AE</span>` : "";
        const rBadge  = (zone_delay && zone_time > 0) ? `<span class="badge" title="Ritardo">R</span>` : "";

        return `
        <div class="card mini">
          <div class="chip ${zz.active ? "on":""}" data-zone-id="${zz.id}" title="${zz.name}">
            ${zz.name || ("Z"+zz.id)}
          </div>
          <div class="row" style="align-items:center; margin-top:.3rem; display: flex; justify-content: space-between;">
            <div class="row">
              ${isAdmin ? `<button class="btn tiny" data-rename="${zz.id}" style="margin-top:.3rem">Rinomina</button>` : ""}
            </div>
            <span>${aeBadge}${rBadge}</span>
          </div>
        </div>`;
      }).join("");

      const host = $("#zonesGrid");
      if (host) host.innerHTML = html;

      if (isAdmin){
        $$("button[data-rename]").forEach(b=>{
          b.onclick = async ()=>{
            const id   = +b.dataset.rename;
            const node = $(`.chip[data-zone-id="${id}"]`);
            const cur  = node ? node.textContent.trim() : "";
            const nu   = prompt(`Nome per zona ${id}:`, cur);
            if (nu && nu !== cur) {
              const r = await apiPost("/api/zones/config", { items:[{id, name: nu}] });
              if (r.ok) refreshZones(); else alert("Errore salvataggio nome");
            }
          };
        });
      }
    }catch(_){}
  }
  window.refreshZones = refreshZones;


  // Configura zone
  async function openZonesConfig(){
    let cfg;
    try { cfg = await apiGet("/api/zones/config"); }
    catch (e) { console.error(e); alert("Impossibile leggere configurazione zone"); return; }
    const body = (cfg.items||[]).map(it => `
      <div class="card" data-zid="${it.id}" style="margin-bottom:.5rem">
        <div class="row between"><strong>${it.name || ("Z"+it.id)}</strong><small>ID ${it.id}</small></div>
        <div class="form">
          <div class="row"><label class="chk"><input type="checkbox" data-k="zone_delay" ${it.zone_delay?"checked":""}> Ritardo ingresso/uscita</label><input type="number" min="0" max="300" value="${it.zone_time||0}" data-k="zone_time" style="width:6rem"> <small>s</small></div>
          <div class="row"><label class="chk"><input type="checkbox" data-k="auto_exclude" ${it.auto_exclude?"checked":""}> Esclusione automatica</label></div>
        </div>
      </div>`).join("");

    const modal = showModal(`
      <h3 class="title">Configurazione zone</h3>
      <div class="scroll" style="max-height:60vh; overflow:auto; padding-right:.5rem">${body}</div>
      <div class="row" style="justify-content:flex-end; gap:.5rem; margin-top:.75rem">
        <button class="btn" id="zc_close">Chiudi</button>
        <button class="btn primary" id="zc_save">Salva</button>
      </div>
    `);
    // Disabilita 'Esclusione automatica' se è impostato un ritardo (zone_delay && zone_time>0)
    try {
      const cards = Array.from(modal.querySelectorAll('.card[data-zid]'));
      cards.forEach(card => {
        const chkDelay = card.querySelector('[data-k="zone_delay"]');
        const inTime   = card.querySelector('[data-k="zone_time"]');
        const chkAE    = card.querySelector('[data-k="auto_exclude"]');
        const update = ()=>{
          const t = parseInt(inTime && inTime.value || '0', 10) || 0;
          const lock = !!(chkDelay && chkDelay.checked) && t > 0;
          if (chkAE) {
            chkAE.disabled = lock;
            if (lock) chkAE.checked = false;
          }
          // Evidenzia errore se Ritardo spuntato ma Tempo non > 0
          if (inTime) {
            const invalid = !!(chkDelay && chkDelay.checked) && t <= 0;
            inTime.classList.toggle('input-error', invalid);
            if (invalid) inTime.style.outline = '2px solid #f66';
            else inTime.style.removeProperty('outline');
          }
        };
        if (chkDelay) chkDelay.addEventListener('change', update);
        if (inTime) inTime.addEventListener('input', update);
        update();
      });
    } catch (_e) { console.warn('Lock AE failed', _e); }
    modal.querySelector("#zc_close").onclick = clearModals;
    modal.querySelector("#zc_save").onclick = async ()=>{
      const cards = Array.from(modal.querySelectorAll(".card[data-zid]"));
      // --- VALIDAZIONE: se zone_delay è attivo ma zone_time <= 0, blocca il salvataggio ---
      const invalid = [];
      cards.forEach(card=>{
        const id       = +card.dataset.zid;
        const chkDelay = card.querySelector('[data-k="zone_delay"]');
        const inTime   = card.querySelector('[data-k="zone_time"]');
        const t        = parseInt(inTime && inTime.value || '0', 10) || 0;
        const bad      = !!(chkDelay && chkDelay.checked) && t <= 0;
        if (bad) {
          invalid.push(id);
          if (inTime){
            inTime.classList.add('input-error');
            inTime.style.outline = '2px solid #f66';
          }
        }
      });
      if (invalid.length){
        alert("Tempo ritardo deve essere maggiore di 0 secondi per: " + invalid.map(z=>"Z"+z).join(", "));
        return; // non procedere al POST
      }
      const items = cards.map(card=>{
        const id = +card.dataset.zid;
        const val = k=> card.querySelector(`[data-k="${k}"]`);
        return {
          id,
          zone_delay:  !!val("zone_delay").checked,
          zone_time:   +val("zone_time").value||0,
          auto_exclude: !!val("auto_exclude").checked,
        };
      });
      try{
        const r = await apiPost("/api/zones/config", { items });
        if (r.ok){ clearModals(); refreshZones(); }
        else { alert("Errore salvataggio ("+r.status+")"); }
      }catch(e){ console.error(e); alert("Errore di rete nel salvataggio"); }
    };
  }
  document.addEventListener("click", (ev)=>{
    const btn = ev.target.closest("#btnZonesCfg");
    if (btn) { ev.preventDefault(); openZonesConfig(); }
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
          ${isAdmin ? `<button class="btn primary small" data-save="${sceneKey}">Salva</button>` : ""}
          <!-- <button class="btn primary small" data-save="${sceneKey}" ${isAdmin?"":"disabled title='Solo admin'"}>Salva</button> -->
        </div>
        <div class="checks">${checks}</div>
      </div>`;
  }
  async function refreshScenes(){
    try{
      const s = await apiGet("/api/scenes");
      $("#scenesWrap") && ($("#scenesWrap").innerHTML = [
        buildSceneCard({label:"HOME",   sceneKey:"home",   mask:s.home,   zonesCount:s.zones}),
        buildSceneCard({label:"NOTTE",  sceneKey:"night",  mask:s.night,  zonesCount:s.zones}),
        buildSceneCard({label:"CUSTOM", sceneKey:"custom", mask:s.custom, zonesCount:s.zones}),
      ].join(""));
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
    const me = await apiGet("/api/me"); // 401 => needLogin()
    currentUser = me.user || "";
    // Usa solo 'role': admin se role >= 2 (gestisce sia number che string)
    isAdmin = (typeof me.role === "number" ? me.role : parseInt(me.role, 10) || 0) >= 2;
    syncHeader();
    mountUserMenu();
    updateAdminVisibility();
    afterLoginUI();
    await Promise.all([refreshStatus(), refreshZones(), refreshScenes()]);
    setInterval(refreshStatus, 2000);
    setInterval(refreshZones,  2000);
    // setInterval(refreshScenes, 30000);
  }

  // boot
  window.addEventListener("DOMContentLoaded", async () => {
    const y = document.getElementById('year');
    if (y) y.textContent = new Date().getFullYear();
    const bindArm = (sel, mode) => {
      const b = document.querySelector(sel);
      if (!b) return;
      b.onclick = () => {
        promptPin(async (pin) => {
          try {
            const r = await fetch("/api/arm", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ mode, pin }),
            });
            if (!r.ok) {
              if (r.status === 401) {
                alert("PIN errato");
              } else if (r.status === 409) {
                // Zone aperte non auto-escludibili
                try {
                  const j = await r.json();
                  const items = (j.open_blocking || [])
                    .map(o => (o.name ? `${o.id} - ${o.name}` : `Z${o.id}`))
                    .join("\n");
                  alert("ARM rifiutato:\nZone aperte non auto-escludibili:\n" + items);
                } catch {
                  alert("ARM rifiutato: zone aperte non auto-escludibili");
                }
              } else {
                alert("Errore ARM: " + r.status + " " + r.statusText);
              }
              return;
            }
            refreshStatus();
          } catch {
            alert("Errore rete ARM");
          }
        });
      };
    };

    bindArm("#armAwayBtn",   "away");
    bindArm("#armHomeBtn",   "home");
    bindArm("#armNightBtn",  "night");
    bindArm("#armCustomBtn", "custom");

    const disarm = document.querySelector("#disarmBtn");
    if (disarm) {
      disarm.onclick = () => {
        promptPin(async (pin) => {
          try {
            const r = await fetch("/api/disarm", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ pin }),
            });
            if (!r.ok) { if (r.status===401){ alert("PIN errato"); } else { alert("Errore DISARM: " + r.status + " " + r.statusText);} return; }
            refreshStatus();
          } catch {
            alert("Errore rete DISARM");
          }
        });
      };
    }
    try { await afterLogin(); } catch { needLogin(); }
  });

  // QR library on demand
  async function ensureQRCodeLib(){
    if (window.QRCode) return;
    await new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = "/js/qrcode.min.js";
      s.onload = resolve;
      s.onerror = reject;
      document.head.appendChild(s);
    });
  }
})();

// --- Idle Logout Manager (30 min inactivity) ---
(() => {
  const IDLE_MS = 30 * 60 * 1000; // 30 minutes
  let idleTimer = null;
  let lastActivity = Date.now();

  function clearToken() {
    try { localStorage.removeItem("token"); } catch {}
    try { sessionStorage.removeItem("token"); } catch {}
  }

  async function doLogout(reason="idle") {
    try { await fetch("/api/logout", { method: "POST", credentials: "include" }); } catch {}
    clearToken();
    // Prefer explicit login page if present
    const hasLogin = (document.querySelector('link[rel="preload"][href="/login.html"]') !== null) || true;
    location.replace("/login.html");
  }

  function resetTimer() {
    lastActivity = Date.now();
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      const inactive = Date.now() - lastActivity;
      if (inactive >= IDLE_MS) doLogout("idle");
      else resetTimer(); // edge case
    }, IDLE_MS);
  }

  ["mousemove","mousedown","keydown","scroll","touchstart","visibilitychange","pointerdown","click"].forEach(ev => {
    window.addEventListener(ev, () => {
      if (ev === "visibilitychange" && document.visibilityState !== "visible") return;
      resetTimer();
    }, { passive: true });
  });

  window.addEventListener("load", resetTimer);
})();