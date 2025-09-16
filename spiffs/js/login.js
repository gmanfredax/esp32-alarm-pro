(() => {
  const $ = s=>document.querySelector(s);
  const msg = (t, ok=false)=>{
    const n=$("#lg_msg");
    n.textContent=t;
    n.classList.remove("hidden");
    n.style.color=ok?"#0a0":"#c00";
  };

  // Se già autenticato (cookie SID valido) vai direttamente alla home
  (async () => {
    try {
      const r = await fetch("/api/me", { credentials: "include" });
      if (r.ok) { location.replace("/"); }
    } catch {}
  })();

  $("#login_form").addEventListener("submit", async (ev)=>{
    ev.preventDefault();
    const user = $("#lg_user").value.trim();
    const pass = $("#lg_pass").value;
    try{
      const r = await fetch("/api/login", {
        credentials:"include",
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({ user, pass })
      });
      if(!r.ok){ msg("Credenziali non valide"); return; }
      const j = await r.json();
      sessionStorage.setItem("token", j.token);
      location.replace("/");
    } catch(e){ msg("Errore di rete"); }
  });
})();