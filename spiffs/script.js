let token='';
async function api(path, opt={}){
  opt.headers = Object.assign({'Content-Type':'application/json'}, opt.headers||{});
  if(token) opt.headers['X-Auth-Token']=token;
  const r = await fetch(path,opt);
  if(!r.ok) throw new Error(await r.text());
  const ct = r.headers.get('content-type')||'';
  return ct.includes('application/json')? r.json() : r.text();
}
async function login(){
  const user=document.getElementById('u').value, pass=document.getElementById('p').value, otp=document.getElementById('o').value;
  const r = await api('/api/login',{method:'POST',body:JSON.stringify({user,pass,otp})});
  token=r.token; document.getElementById('login').style.display='none'; document.getElementById('app').style.display='block'; refresh();
}
async function refresh(){
  const s = await api('/api/status'); document.getElementById('status').innerHTML=`<b>Stato:</b> ${s.state} | <b>Zones:</b> ${s.zones_count}`;
  const z = await api('/api/zones'); document.getElementById('zones').textContent=JSON.stringify(z,null,2);
  const l = await api('/api/logs'); document.getElementById('logs').textContent=JSON.stringify(l,null,2);
}
async function arm(mode){ await api('/api/arm',{method:'POST',body:JSON.stringify({mode})}); refresh(); }
async function disarm(){ await api('/api/disarm',{method:'POST'}); refresh(); }
async function setOutputs(){
  await api('/api/outputs',{method:'POST',body:JSON.stringify({relay:document.getElementById('relay').checked?1:0, led_state:document.getElementById('leds').checked?1:0, led_maint:document.getElementById('ledm').checked?1:0})});
}
