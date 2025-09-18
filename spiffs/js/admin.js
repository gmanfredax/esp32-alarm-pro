// /spiffs/js/admin.js — Admin UI (Utenti, Rete, MQTT)
(() => {
  const $  = (s, r=document) => r.querySelector(s);
  const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));

  // ========== FETCH shim: Authorization Bearer + cookie same-origin + redirect 401/403
  (function installAuthFetchShim(){
    const _fetch = window.fetch;
    window.fetch = (input, init = {}) => {
      const headers = new Headers(init.headers || {});
      const t = (()=>{ try { return localStorage.getItem("token") || sessionStorage.getItem("token") || ""; } catch { return ""; }})();
      if (t && !headers.has("Authorization")) headers.set("Authorization", "Bearer " + t);
      const creds = init.credentials ? init.credentials : "same-origin";
      return _fetch(input, { ...init, headers, credentials: creds }).then(resp => {
        if (resp.status === 401) { location.replace("/login.html"); }
        else if (resp.status === 403) { location.replace("/403.html"); }
        return resp;
      });
    };
  })();

  // ========== Helpers UI / auth ==========
  function toast(msg, ok=true){
    let el = $("#toast");
    if (!el){
      el = document.createElement("div");
      el.id = "toast";
      el.className = "toast";
      Object.assign(el.style, {position:"fixed",bottom:"18px",left:"18px",padding:".6rem .8rem",borderRadius:"10px",background:"rgba(20,28,44,.95)",border:"1px solid var(--border)",color:"var(--text)",zIndex:2000,boxShadow:"0 6px 24px rgba(0,0,0,.35)",maxWidth:"80%"});
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.style.borderColor = ok ? "rgba(16,185,129,.45)" : "rgba(239,68,68,.55)";
    el.style.background = ok ? "rgba(10,20,24,.95)" : "rgba(32,12,12,.95)";
    clearTimeout(el._t); el._t = setTimeout(()=>{ el.remove(); }, 2400);
  }
  const needLogin = () => location.replace("/login.html");

  async function apiGet(url){
    const r = await fetch(url, { headers: { "Accept":"application/json" } });
    if (r.status === 401) { needLogin(); throw new Error("401"); }
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  }
  async function apiPost(url, body){
    const r = await fetch(url, { method:"POST", headers:{ "Content-Type":"application/json" }, body: body!=null?JSON.stringify(body):undefined });
    if (r.status === 401) { needLogin(); throw new Error("401"); }
    if (!r.ok) throw new Error(await r.text());
    try { return await r.json(); } catch { return {}; }
  }

  const escapeHtml = (value = "") => (value ?? "").toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

  const fileToBase64 = (file) => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("lettura"));
    reader.onload = () => {
      try {
        const bytes = new Uint8Array(reader.result);
        let binary = "";
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        resolve(btoa(binary));
      } catch (e) {
        reject(e);
      }
    };
    reader.readAsArrayBuffer(file);
  });

  const WEB_TLS_MAX_PEM_LEN = 4096;

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
    dd.querySelector("[data-act=logout]")?.addEventListener("click", async ()=>{
      dd.classList.add("hidden");
      try{ await apiPost("/api/logout",{});}catch{}
      try { localStorage.removeItem("token"); } catch(_){}
      try { sessionStorage.removeItem("token"); } catch(_){}
      needLogin();
    });
  }

  // ========== Gate client-side (semplificato)
  // Il server decide già se servire admin.html o 403.html.
  // Qui sblocchiamo solo la UI e lasciamo al fetch-shim il redirect quando il token scade.
  async function ensureAdminOr403(){
    document.getElementById("appRoot")?.classList.remove("hidden");
    return true;
  }
  async function ensureAdmin(){ return ensureAdminOr403(); }

  // ========== Sidebar / Views
  function setupSidebar(){
    $$(".side button").forEach(btn => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-view");
        $$(".side button").forEach(b => b.classList.toggle("active", b===btn));
        $$(".view").forEach(v => v.classList.toggle("active", v.id === id));
      });
    });
  }

  // ========== USERS
  function renderUsers(list){
    const tb = $("#usersTbody");
    if (!Array.isArray(list) || !tb){ return; }
    tb.innerHTML = "";
    if (list.length === 0){
      tb.innerHTML = `<tr><td colspan="7" class="muted">Nessun utente</td></tr>`;
      return;
    }
    for(const u of list){
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${u.username}</td>
        <td>${u.first_name||""}</td>
        <td>${u.last_name||""}</td>
        <td>${u.has_pin ? "✅" : "—"}</td>
        <td>${u.has_rfid ? (u.rfid_uid||"✅") : "—"}</td>
        <td>${u.totp_enabled ? "✅" : "—"}</td>
        <td><button class="btn btn-sm" data-edit="${u.username}">Modifica</button></td>
      `;
      tb.appendChild(tr);
    }
    tb.querySelectorAll("[data-edit]").forEach(btn => btn.addEventListener("click", () => openEditUser(btn.getAttribute("data-edit"))));
  }

  async function loadUsers(){
    try{
      const list = await apiGet("/api/admin/users");
      renderUsers(list);
    }catch(e){ toast("Errore caricando utenti: " + e.message, false); }
  }

  // ---- Modals
  function closeModal(){ $("#modals-root").innerHTML = ""; }
  function modal(html){
    const root = $("#modals-root");
    root.innerHTML = `
      <div class="modal-overlay" style="position:fixed;inset:0;background:rgba(0,0,0,.45);backdrop-filter:blur(1px);display:grid;place-items:center;z-index:1500">
        <div class="modal card" style="width:min(720px, 96vw);max-height:88vh;overflow:auto">
          ${html}
        </div>
      </div>`;
    root.querySelector(".modal-overlay").addEventListener("click", (e)=>{ if(e.target.classList.contains("modal-overlay")) closeModal(); });
    window.addEventListener("keydown", function onK(e){ if(e.key==="Escape"){ closeModal(); window.removeEventListener("keydown", onK); } });
  }

  function newUserModal(){
    modal(`
      <div class="card-head row" style="justify-content:space-between;align-items:center"><h3>Nuovo utente</h3><button class="btn" id="mClose">Chiudi</button></div>
      <form class="form" id="newUserForm">
        <div class="row" style="gap:1rem;flex-wrap:wrap">
          <div class="field"><span>Username</span><input required id="nu_user" type="text" autocomplete="off"></div>          
        </div>
        <div class="row" style="gap:1rem;flex-wrap:wrap">
          <div class="field"><span>Nome</span><input id="nu_fn" type="text"></div>
          <div class="field"><span>Cognome</span><input id="nu_ln" type="text"></div>
        </div>
        <div class="row" style="gap:1rem;flex-wrap:wrap">
          <div class="field"><span>Password</span><input id="nu_pw" type="password" autocomplete="new-password"></div>
          <div class="field"><span>PIN (Allarme)</span><input id="nu_pin" type="password" pattern="\\d{4,8}" placeholder="4–8 cifre"></div>
        </div>
        <div class="row" style="justify-content:flex-end;margin-top:.6rem">
          <button class="btn" type="submit">Crea</button>
        </div>
      </form>
    `);
    $("#mClose").addEventListener("click", closeModal);
    $("#newUserForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = {
        user: $("#nu_user").value.trim(),
        first_name: $("#nu_fn").value.trim(),
        last_name: $("#nu_ln").value.trim(),
        password: $("#nu_pw").value,
        pin: $("#nu_pin").value
      };
      if (!payload.user){ toast("Username obbligatorio", false); return; }
      try{
        await apiPost("/api/users/create", payload);
        toast("Utente creato");
        closeModal();
        await loadUsers();
      }catch(err){
        toast("Errore creazione utente: " + err.message, false);
      }
    });
  }

  // HOME tab -> torna alla dashboard
  document.addEventListener("click", (e)=>{
    const b = e.target.closest(".tab-btn");
    if (b && b.dataset.tab === 'home') {
      e.preventDefault();
      location.replace("/");
    }
  });

  // async function openEditUser(username){
  //   // Recupera record corrente
  //   let list = [];
  //   try{ list = await apiGet("/api/admin/users"); }catch{}
  //   const rec = list.find(x => x.username === username) || { username, first_name:"", last_name:"", has_rfid:false, rfid_uid:"" };

  //   modal(`
  //     <div class="card-head row" style="justify-content:space-between;align-items:center">
  //       <h3>Modifica utente — <span class="muted">${username}</span></h3>
  //       <button class="btn" id="mClose">Chiudi</button>
  //     </div>
  //     <div class="form">
  //       <div class="row" style="gap:1rem;flex-wrap:wrap">
  //         <div class="field"><span>Nome</span><input id="ed_fn" type="text" value="${(rec.first_name||"").replace(/"/g,'&quot;')}"></div>
  //         <div class="field"><span>Cognome</span><input id="ed_ln" type="text" value="${(rec.last_name||"").replace(/"/g,'&quot;')}"></div>
  //       </div>
  //       <div class="row" style="gap:1rem;flex-wrap:wrap;align-items:flex-end">
  //         <div class="field" style="min-width:260px">
  //           <span>Tag RFID</span>
  //           <div id="rfidBox">
  //             ${rec.has_rfid ? `<div class="tag">UID: <strong>${rec.rfid_uid||"—"}</strong></div>` : `<div class="muted">Nessun tag associato</div>`}
  //           </div>
  //         </div>
  //         <div class="row" style="gap:.4rem">
  //           <button class="btn" id="btnRfidLearn">Aggiungi</button>
  //           <button class="btn btn-danger" id="btnRfidClear"${rec.has_rfid?"":" disabled"}>Rimuovi</button>
  //         </div>
  //         <div class="row" style="margin-left:auto;gap:.4rem">
  //           <button class="btn" id="btnSave">Salva</button>
  //         </div>
  //       </div>
  //       <small class="muted">Nota: l'aggiornamento di Nome/Cognome richiede supporto firmware.</small>
  //       <div class="row" style="gap:1rem;flex-wrap:wrap;margin-top:.6rem">
  //         <div class="field"><span>Nuova password</span><input id="ed_pw1" type="password" autocomplete="new-password"></div>
  //         <div class="field"><span>Conferma</span><input id="ed_pw2" type="password" autocomplete="new-password"></div>
  //         <div class="row" style="align-items:flex-end">
  //           <button class="btn" id="btnSetPw">Aggiorna password</button>
  //         </div>
  //       </div>
  //       <small class="muted">Come amministratore puoi resettare la password di questo utente senza conoscere quella attuale.</small>
  //     </div>
  //   `);
  //   $("#mClose").addEventListener("click", closeModal);

  //   $("#btnSave").addEventListener("click", async (e) => {
  //     e.preventDefault();
  //     const payload = { user: username, first_name: $("#ed_fn").value.trim(), last_name: $("#ed_ln").value.trim() };
  //     try{
  //       await apiPost("/api/users/name", payload); // se non supportato -> errore gestito
  //       toast("Dati salvati");
  //       closeModal();
  //       await loadUsers();
  //     }catch(err){
  //       toast("Salvataggio Nome/Cognome non supportato dal firmware: " + err.message, false);
  //     }
  //   });

  //   $("#btnSetPw")?.addEventListener("click", async (e) => {
  //     e.preventDefault();
  //     const p1 = $("#ed_pw1")?.value || "";
  //     const p2 = $("#ed_pw2")?.value || "";
  //     if (p1.length < 6) { toast("Password troppo corta (min 6 caratteri)", false); return; }
  //     if (p1 !== p2) { toast("Le password non coincidono", false); return; }
  //     try{
  //       await apiPost("/api/users/password", { user: username, newpass: p1 });
  //       toast("Password aggiornata");
  //       if ($("#ed_pw1")) $("#ed_pw1").value = "";
  //       if ($("#ed_pw2")) $("#ed_pw2").value = "";
  //     }catch(err){
  //       toast("Errore aggiornando la password: " + err.message, false);
  //     }
  //   });

  //   $("#btnRfidClear").addEventListener("click", async (e) => {
  //     e.preventDefault();
  //     try{
  //       await apiPost("/api/users/rfid/clear", { user: username });
  //       toast("Tag rimosso");
  //       closeModal(); await loadUsers();
  //     }catch(err){ toast("Errore rimozione tag: "+err.message, false); }
  //   });

  //   $("#btnRfidLearn").addEventListener("click", async (e) => {
  //     e.preventDefault();
  //     const overlay = document.createElement("div");
  //     overlay.className = "modal-overlay";
  //     overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,35);display:grid;place-items:center;z-index:1600";
  //     overlay.innerHTML = `<div class="card" style="padding:1rem 1.2rem"><strong>Scansione RFID in corso…</strong><div class="muted" style="margin-top:.4rem">Avvicina il tag al lettore</div></div>`;
  //     document.body.appendChild(overlay);
  //     try{
  //       const res = await apiPost("/api/users/rfid/learn", { user: username, timeout: 10 });
  //       toast("Tag associato: " + (res?.uid_hex || "OK"));
  //       closeModal(); await loadUsers();
  //     }catch(err){
  //       toast("RFID: " + err.message, false);
  //     }finally{
  //       overlay.remove();
  //     }
  //   });
  // }

  // Sostituisci integralmente la tua funzione con questa versione
  async function openEditUser(username){
    const esc = (s) => (s ?? "").toString()
      .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
      .replace(/"/g,"&quot;").replace(/'/g,"&#39;");

    // Prova a recuperare il record dalla lista admin; fallback a valori vuoti
    let rec = { username, first_name:"", last_name:"", has_rfid:false, rfid_uid:"" };
    try {
      const list = await apiGet("/api/admin/users");
      const found = Array.isArray(list) ? list.find(u => u.username === username) : null;
      if (found) rec = { ...rec, ...found };
    } catch {}

    modal(`
      <div class="card-head row" style="justify-content:space-between;align-items:center">
        <h3>Modifica utente — <span class="muted">${esc(username)}</span></h3>
        <button class="btn" id="mClose">Chiudi</button>
      </div>

      <div class="form" style="padding-bottom:.5rem">
        <!-- ===== Dati anagrafici ===== -->
        <h4>Dati</h4>
        <div class="row" style="gap:1rem;flex-wrap:wrap">
          <label class="field"><span>Nome</span>
            <input id="ed_fn" type="text" value="${esc(rec.first_name)}">
          </label>
          <label class="field"><span>Cognome</span>
            <input id="ed_ln" type="text" value="${esc(rec.last_name)}">
          </label>
          <div class="row" style="align-items:flex-end;margin-left:auto">
            <button class="btn" id="btnSave">Salva</button>
          </div>
        </div>

        <!-- ===== RFID ===== -->
        <h4 style="margin-top:1rem">RFID</h4>
        <div class="row" style="gap:.6rem;align-items:center;flex-wrap:wrap">
          <div id="rfidBox">
            ${
              rec.has_rfid
                ? `<div class="tag">UID: <strong>${esc(rec.rfid_uid || "—")}</strong></div>`
                : `<div class="muted">Nessun tag associato</div>`
            }
          </div>
          <div class="row" style="gap:.4rem">
            <button class="btn" id="btnRfidLearn">Aggiungi</button>
            <button class="btn btn-danger" id="btnRfidClear"${rec.has_rfid ? "" : " disabled"}>Rimuovi</button>
          </div>
        </div>

        <!-- ===== PIN ===== -->
        <h4 style="margin-top:1rem">PIN (Allarme)</h4>
        <div class="row" style="gap:1rem;flex-wrap:wrap;align-items:flex-end">
          <label class="field" style="min-width:240px"><span>Nuovo PIN</span>
            <input id="ed_pin" type="password" inputmode="numeric" pattern="\\d*" maxlength="12" autocomplete="off">
          </label>
          <button class="btn" id="btnSetPin">Aggiorna PIN</button>
        </div>

        <!-- ===== Password ===== -->
        <h4 style="margin-top:1rem">Password</h4>
        <div class="row" style="gap:1rem;flex-wrap:wrap;align-items:flex-end">
          <label class="field"><span>Nuova password</span>
            <input id="ed_pw1" type="password" autocomplete="new-password">
          </label>
          <label class="field"><span>Conferma</span>
            <input id="ed_pw2" type="password" autocomplete="new-password">
          </label>
          <button class="btn" id="btnSetPw">Aggiorna password</button>
        </div>
        <small class="muted">Come amministratore puoi resettare la password di questo utente senza conoscere quella attuale.</small>
      </div>
    `);

    // --- Handlers ---
    $("#mClose")?.addEventListener("click", () => closeModal());

    // Salva Nome/Cognome
    $("#btnSave")?.addEventListener("click", async (e) => {
      e.preventDefault();
      const payload = {
        user: username,
        first_name: $("#ed_fn")?.value?.trim() || "",
        last_name:  $("#ed_ln")?.value?.trim() || ""
      };
      try {
        await apiPost("/api/users/name", payload);
        toast("Dati salvati");
        closeModal(); // se preferisci non chiudere, rimuovi questa riga
        try { await loadUsers(); } catch {}
      } catch(err) {
        toast("Salvataggio Nome/Cognome non supportato o errore: " + err.message, false);
      }
    });

    // Aggiorna PIN
    $("#btnSetPin")?.addEventListener("click", async (e) => {
      e.preventDefault();
      const pin = ($("#ed_pin")?.value || "").trim();
      if (pin.length < 4) { toast("PIN troppo corto (min 4 cifre)", false); return; }
      if (!/^[0-9]{4,12}$/.test(pin)) { toast("PIN deve contenere solo cifre (4–12)", false); return; }
      try {
        await apiPost("/api/users/pin", { user: username, pin });
        toast("PIN aggiornato");
        if ($("#ed_pin")) $("#ed_pin").value = "";
      } catch(err) {
        toast("Errore aggiornando il PIN: " + err.message, false);
      }
    });

    // Aggiorna Password
    $("#btnSetPw")?.addEventListener("click", async (e) => {
      e.preventDefault();
      const p1 = $("#ed_pw1")?.value || "";
      const p2 = $("#ed_pw2")?.value || "";
      if (p1.length < 6) { toast("Password troppo corta (min 6 caratteri)", false); return; }
      if (p1 !== p2) { toast("Le password non coincidono", false); return; }
      try {
        await apiPost("/api/users/password", { user: username, newpass: p1 });
        toast("Password aggiornata");
        if ($("#ed_pw1")) $("#ed_pw1").value = "";
        if ($("#ed_pw2")) $("#ed_pw2").value = "";
      } catch(err) {
        toast("Errore aggiornando la password: " + err.message, false);
      }
    });

    // Rimuovi RFID
    $("#btnRfidClear")?.addEventListener("click", async (e) => {
      e.preventDefault();
      try {
        await apiPost("/api/users/rfid/clear", { user: username });
        toast("Tag rimosso");
        closeModal(); await loadUsers();
      } catch(err) {
        toast("Errore rimozione tag: " + err.message, false);
      }
    });

    // Apprendimento RFID
    $("#btnRfidLearn")?.addEventListener("click", async (e) => {
      e.preventDefault();
      const overlay = document.createElement("div");
      overlay.className = "modal-overlay";
      overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.35);display:grid;place-items:center;z-index:1600";
      overlay.innerHTML = `<div class="card" style="padding:1rem 1.2rem">
          <strong>Scansione RFID in corso…</strong>
          <div class="muted" style="margin-top:.4rem">Avvicina il tag al lettore</div>
        </div>`;
      document.body.appendChild(overlay);
      try{
        const res = await apiPost("/api/users/rfid/learn", { user: username, timeout: 10 });
        toast("Tag associato: " + (res?.uid_hex || "OK"));
        closeModal(); await loadUsers();
      } catch(err) {
        toast("RFID: " + err.message, false);
      } finally {
        overlay.remove();
      }
    });
}


  function attachNewUser(){
    $("#btnNewUser")?.addEventListener("click", newUserModal);
  }

  // ========== RETE / MQTT (placeholder salva)
  async function loadNetwork(){
    try{
      const c = await apiGet("/api/sys/net");
      $("#net_host") && ($("#net_host").value = c.hostname || "");
      $("#net_dhcp") && ($("#net_dhcp").value = c.dhcp ? "1" : "0");
      const showStatic = (c.dhcp ? "1" : "0") === "0";
      const row = $("#net_static"); if (row) row.style.display = showStatic ? "flex" : "none";
      $("#net_ip")   && ($("#net_ip").value   = c.ip   || "");
      $("#net_gw")   && ($("#net_gw").value   = c.gw   || "");
      $("#net_mask") && ($("#net_mask").value = c.mask || "");
      $("#net_dns")  && ($("#net_dns").value  = c.dns  || "");
    }catch(e){ toast("Errore caricando rete: " + e.message, false); }
    $("#net_dhcp")?.addEventListener("change", (ev)=>{
      const row = $("#net_static");
      if (row) row.style.display = (ev.target.value === "0") ? "flex" : "none";
    });
    $("#btnNetSave")?.addEventListener("click", async ()=>{
      const body = {
        hostname: $("#net_host")?.value || "",
        dhcp: ($("#net_dhcp")?.value || "1") === "1",
        ip:   $("#net_ip")?.value || "",
        gw:   $("#net_gw")?.value || "",
        mask: $("#net_mask")?.value || "",
        dns:  $("#net_dns")?.value || "",
      };
      try{ await apiPost("/api/sys/net", body); toast("Rete salvata"); }
      catch(e){ toast("Errore salvataggio rete: " + e.message, false); }
    });
  }

  async function loadMqtt(){
    try{
      const c = await apiGet("/api/sys/mqtt");
      $("#mq_uri")  && ($("#mq_uri").value  = c.uri  || "");
      $("#mq_cid")  && ($("#mq_cid").value  = c.cid  || "");
      $("#mq_user") && ($("#mq_user").value = c.user || "");
      $("#mq_pass") && ($("#mq_pass").value = c.pass || "");
      $("#mq_keep") && ($("#mq_keep").value = (c.keepalive ?? 60));
    }catch(e){ toast("Errore caricando MQTT: " + e.message, false); }
    $("#btnMqttSave")?.addEventListener("click", async ()=>{
      const body = {
        uri:  $("#mq_uri")?.value  || "",
        cid:  $("#mq_cid")?.value  || "",
        user: $("#mq_user")?.value || "",
        pass: $("#mq_pass")?.value || "",
        keepalive: parseInt($("#mq_keep")?.value || "60", 10) || 60,
      };
      try{ await apiPost("/api/sys/mqtt", body); toast("MQTT salvato"); }
      catch(e){ toast("Errore salvataggio MQTT: " + e.message, false); }
    });
  }

  // ---- Wrapper come da tua init() originale
  async function setupNetMqttForms(){
    await Promise.all([loadNetwork(), loadMqtt()]);
  }

  function renderWebSecStatus(data){
    const box = $("#websecStatus");
    const fb = $("#websecFeedback");
    if (!box) return;
    if (!data){
      box.textContent = "Stato non disponibile";
      if (fb) fb.textContent = "";
      return;
    }
    const activeLabel = data.using_builtin ? "Certificato predefinito incorporato" : "Certificato personalizzato";
    let html = `<div><strong>Attivo:</strong> ${escapeHtml(activeLabel)}</div>`;
    if (data.active_subject) html += `<div class="muted">Soggetto: ${escapeHtml(data.active_subject)}</div>`;
    if (data.active_not_after) html += `<div class="muted">Valido fino al: ${escapeHtml(data.active_not_after)}</div>`;
    if (data.active_fingerprint) html += `<div class="muted">SHA-256: <code>${escapeHtml(data.active_fingerprint)}</code></div>`;
    if (data.custom_available){
      if (data.custom_valid){
        const subj = data.custom_subject ? escapeHtml(data.custom_subject) : "";
        const installed = data.custom_installed_iso ? ` (${escapeHtml(data.custom_installed_iso)})` : "";
        html += `<div class="muted" style="margin-top:.4rem">Ultimo certificato installato: ${subj}${installed}</div>`;
        if (data.custom_not_after) html += `<div class="muted">Scadenza personalizzato: ${escapeHtml(data.custom_not_after)}</div>`;
      } else {
        html += `<div class="muted" style="margin-top:.4rem">Il certificato personalizzato salvato non è valido.</div>`;
      }
    } else {
      html += `<div class="muted" style="margin-top:.4rem">Nessun certificato personalizzato installato.</div>`;
    }
    if (data.restart_pending){
      html += `<div class="muted" style="margin-top:.4rem">Riavvio HTTPS in corso…</div>`;
    }
    box.innerHTML = html;
    if (fb){
      if (data.last_error){
        fb.textContent = `Ultimo errore: ${data.last_error}`;
      } else if (data.restart_pending){
        fb.textContent = "Il server si riavvierà automaticamente per applicare il certificato.";
      } else {
        fb.textContent = "";
      }
    }
  }

  async function loadWebSecStatus(){
    try{
      const data = await apiGet("/api/sys/websec");
      renderWebSecStatus(data);
      return data;
    }catch(err){
      const box = $("#websecStatus");
      if (box) box.textContent = "Errore caricando stato: " + err.message;
      const fb = $("#websecFeedback");
      if (fb) fb.textContent = "";
      throw err;
    }
  }

  async function setupWebSecForm(){
    const btn = $("#btnWebsecUpload");
    if (btn){
      btn.addEventListener("click", async () => {
        const certInput = $("#websecCert");
        const keyInput = $("#websecKey");
        const certFile = certInput?.files?.[0];
        const keyFile = keyInput?.files?.[0];
        if (!certFile || !keyFile){ toast("Seleziona certificato e chiave", false); return; }
        if (certFile.size > WEB_TLS_MAX_PEM_LEN || keyFile.size > WEB_TLS_MAX_PEM_LEN){
          toast("File troppo grandi (max 4 KB)", false);
          return;
        }
        const prevText = btn.textContent;
        btn.disabled = true;
        btn.textContent = "Caricamento…";
        const fb = $("#websecFeedback");
        if (fb) fb.textContent = "Caricamento in corso…";
        try{
          const [certB64, keyB64] = await Promise.all([fileToBase64(certFile), fileToBase64(keyFile)]);
          await apiPost("/api/sys/websec", { cert_b64: certB64, key_b64: keyB64 });
          toast("Certificato aggiornato. Riavvio in corso…");
          if (fb) fb.textContent = "Aggiornamento completato, il server HTTPS si riavvierà automaticamente.";
          setTimeout(() => { loadWebSecStatus().catch(()=>{}); }, 1500);
        }catch(err){
          toast("Aggiornamento certificato: " + err.message, false);
          const fb2 = $("#websecFeedback");
          if (fb2) fb2.textContent = "Errore: " + err.message;
        }finally{
          btn.disabled = false;
          btn.textContent = prevText;
          if ($("#websecCert")) $("#websecCert").value = "";
          if ($("#websecKey")) $("#websecKey").value = "";
        }
      });
    }
    try { await loadWebSecStatus(); } catch {}
  }

  // ========== Logout (eventuale)
  $("#btnLogout")?.addEventListener("click", async () => {
    try{ await apiPost("/api/logout"); }catch{}
    needLogin();
  });

  document.addEventListener('DOMContentLoaded', () => {
    const y = document.getElementById('year');
    if (y) y.textContent = new Date().getFullYear();
  });

  // ========== Init
  (async function init(){
    const me = await apiGet("/api/me");
    currentUser = me.user || "";
    isAdmin = (typeof me.role === "number" ? me.role : parseInt(me.role, 10) || 0) >= 2;
    syncHeader();
    mountUserMenu();
    setupSidebar();
    const setupPromises = [setupNetMqttForms(), setupWebSecForm()];
    document.querySelector('[data-tab="home"]')?.addEventListener('click', (e) => {
      e.preventDefault();
      location.href = "/index.html";
    });
    if (!(await ensureAdmin())) return;     // ora è un no-op che sblocca la UI
    attachNewUser();
//    await Promise.all([loadUsers(), loadNetwork(), loadMqtt()]);
    await Promise.all([loadUsers(), ...setupPromises]);
  })();
})();
