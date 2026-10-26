"""Self-contained dashboard assets; no CDN, analytics, maps or browser token storage."""

HTML = '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>AccuGPS · Fleet monitoring</title>
<style>
:root{font:15px system-ui;color:#172c43;background:#edf2f6}*{box-sizing:border-box}body{margin:0}
header{background:#102940;color:white;padding:26px max(24px,calc((100vw - 1280px)/2))}header p{color:#bfcedb;margin:8px 0}h1{font-size:28px;margin:4px 0}h2{font-size:19px}
main{max-width:1328px;margin:auto;padding:24px}button,a.button{font:inherit;border:1px solid #b8c9d5;background:white;border-radius:7px;padding:9px 13px;color:#173e5c;cursor:pointer}button:hover{background:#e4edf3}button:disabled{opacity:.5;cursor:wait}a{color:#185b93}
.bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:16px 0}.bar .push{margin-left:auto}.notice{padding:13px 17px;background:#fff6dc;border:1px solid #e7d7a3;border-radius:8px;line-height:1.6}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:20px 0}.card{background:white;border:1px solid #d9e3eb;border-radius:10px;padding:19px}.number{font-size:30px;font-weight:700;display:block}.muted,small{color:#53677a}#message{min-height:24px;color:#8a3d13}.tablebox{overflow:auto;background:white;border:1px solid #d9e3eb;border-radius:10px}table{border-collapse:collapse;width:100%;min-width:850px;text-align:left}th,td{padding:15px;border-bottom:1px solid #e2e9ef;vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.06em;background:#f8fafc}td small{display:block;margin-top:5px}.good{color:#13704b}.warn{color:#96620c}.bad{color:#a8372e}input{accent-color:#185b93}label{cursor:pointer}details{margin-top:20px}#detail{background:white;border-radius:10px;padding:22px;margin-top:20px;border:1px solid #d9e3eb;overflow-wrap:anywhere}#detail[hidden]{display:none}#detail li{margin:12px 0}footer{font-size:13px;line-height:1.7;color:#53677a;margin-top:24px}@media(max-width:650px){main{padding:16px}.cards{grid-template-columns:1fr}.bar .push{margin-left:0}header{padding:22px}}
</style></head><body><header><small style="color:#a7c7dc">ACCuGPS / OPERATIONS</small><h1>Fleet monitoring</h1><p>GPS freshness · Recorder connectivity · Evidence and follow-up</p></header>
<main><div class="notice">Pilot: new check cycles start at least 5 minutes apart while this page is open. Units are checked sequentially, so a cycle can take longer. Old GPS data can mean a parked or sleeping vehicle. API errors do not establish a hardware fault. Cameras and auxiliary placement require visual verification.</div>
<div class="bar"><strong id="state">Connecting…</strong><span id="expiry" class="muted"></span><button id="refresh" class="push">Check for updates</button><a href="/dashboard/start">Reconnect</a><button id="disconnect">Disconnect dashboard</button></div>
<div id="message" role="status" aria-live="polite"></div><div class="cards"><div class="card"><span class="muted">Approved units</span><span id="total" class="number">—</span></div><div class="card"><span class="muted">GPS observations older than 15 min</span><span id="stale" class="number">—</span></div><div class="card"><span class="muted">Latest checks that failed</span><span id="failed" class="number">—</span></div></div>
<div class="bar"><span class="muted">Mark units whose recorder status should be monitored. Hardware type is a team configuration, not inferred from the device name.</span><button id="save">Save camera selection</button></div>
<div class="tablebox"><table><thead><tr><th>Unit</th><th>GPS evidence</th><th>Recorder / ignition</th><th>Monitor recorder</th><th>Details</th></tr></thead><tbody id="units"></tbody></table></div>
<section id="detail" hidden aria-live="polite"></section><footer>All displayed times use your browser’s time zone. GPS source time and check time are shown separately. Recorder source timestamps are unavailable. Five- and fifteen-minute GPS age bands are triage settings, not contractual delay limits.<br>
No GPS coordinates, video, audio or playback links are displayed. Checks and the last 20 events per unit are held in server memory and disappear on restart. Sign-in lasts at most one hour. This pilot is not unattended monitoring or an availability guarantee. <a href="/connections">Manage connections</a></footer></main><script src="/dashboard/app.js" defer></script></body></html>'''

SCRIPT = r'''"use strict";
let data=null, loading=false, selected=new Set(), dirty=false, detailId=null;
const byId=id=>document.getElementById(id);
const node=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const stamp=s=>s?new Date(s).toLocaleString():"Unavailable";
function age(gps){const t=gps?.last_success?.reported_at_utc;return t?(Date.now()-Date.parse(t))/60000:null;}
function ageText(a){return a===null?"Source time unavailable":a<0?"Future timestamp; inspect clock":a<60?`${Math.floor(a)} min old`:`${(a/60).toFixed(1)} h old`;}
function render(){
 byId("message").textContent=data.collection_error||"";
 byId("state").textContent=data.collecting?"Checking units sequentially…":"Latest collected observations";
 byId("expiry").textContent=`Session ends ${stamp(data.expires_at_utc)}`;
 byId("total").textContent=data.device_count;
 byId("stale").textContent=data.rows.filter(r=>age(r.gps)>15).length;
 byId("failed").textContent=data.rows.reduce((n,r)=>n+[r.gps,r.recorder,r.recordings].filter(c=>c?.check_state==="request_failed").length,0);
 byId("save").disabled=!data.camera_consent||data.collecting;
 const body=byId("units");body.replaceChildren();
 for(const r of data.rows){
  const tr=node("tr"),name=node("td",r.alias);name.append(node("small",r.device_id));tr.append(name);
  const invalid=r.gps?.last_success?.valid_coordinate_bounds===false;
  const a=age(r.gps),gps=node("td",r.gps?.check_state==="request_failed"?"API check failed":!r.gps?"Awaiting check":ageText(a),r.gps?.check_state==="request_failed"?"bad":invalid||a===null||a>15||a<0?"warn":"good");
  gps.append(node("small",`GPS: ${stamp(r.gps?.last_success?.reported_at_utc)}`),node("small",`Last success: ${stamp(r.gps?.checked_at_utc)}`));
  if(r.gps?.attempted_at_utc)gps.append(node("small",`Last attempt: ${stamp(r.gps.attempted_at_utc)}`));
  if(r.gps?.last_success?.valid_coordinate_bounds===false)gps.append(node("small","Coordinates failed bounds validation"));tr.append(gps);
  const status=r.recorder?.last_success,rec=node("td",!data.camera_devices.includes(r.device_id)?"Not configured":r.recorder?.check_state==="request_failed"?"API check failed":status?`${status.recorder_status} / ignition ${status.ignition_status}`:"Awaiting check");
  if(r.recorder?.checked_at_utc)rec.append(node("small",`Last success: ${stamp(r.recorder.checked_at_utc)}`));
  if(r.recorder?.attempted_at_utc)rec.append(node("small",`Last attempt: ${stamp(r.recorder.attempted_at_utc)}`));tr.append(rec);
  const config=node("td"),label=node("label"),box=node("input");box.type="checkbox";box.checked=selected.has(r.device_id);box.disabled=!data.camera_consent;box.setAttribute("aria-label",`Monitor recorder for ${r.alias}`);
  box.addEventListener("change",()=>{box.checked?selected.add(r.device_id):selected.delete(r.device_id);dirty=true;});label.append(box,document.createTextNode(" Camera unit"));config.append(label);tr.append(config);
  const actions=node("td"),button=node("button","View evidence");button.addEventListener("click",()=>{detailId=r.device_id;renderDetail();});actions.append(button);tr.append(actions);body.append(tr);
 }
 if(!data.rows.length){const tr=node("tr"),td=node("td",data.collecting?"Collecting the first observations…":"No observations available. Check account access and retry later.");td.colSpan=5;tr.append(td);body.append(tr);}
 if(!data.camera_consent)byId("message").textContent="GPS-only access. Reconnect and opt in to camera metadata to enable recorder checks.";
 if(data.device_count>data.device_limit)byId("message").textContent=`Pilot limit: only the first ${data.device_limit} authorized units are checked. Reconnect with a smaller selection.`;
 renderDetail();
}
function renderDetail(){
 const panel=byId("detail"),r=data?.rows.find(x=>x.device_id===detailId);panel.hidden=!r;if(!r)return;panel.replaceChildren(node("h2",`${r.alias} · Evidence`));
 panel.append(node("p",`GPS timestamp change: ${r.gps?.last_success?.timestamp_change||"Not yet observed"}. This measures successive observations, not end-to-end delivery delay.`));
 const rec=r.recordings;panel.append(node("p",rec?`Cloud recording check: ${rec.check_state}. Checked/attempted: ${stamp(rec.checked_at_utc||rec.attempted_at_utc)}. Channels observed: ${(rec.observed_channels||[]).join(", ")||"None confirmed"}.`:"Recording metadata has not been checked."));
 if(rec?.check_state==="success")panel.append(node("p",`Window: ${stamp(rec.window_start_utc)} to ${stamp(rec.window_end_utc)}. Matching records: ${rec.matching_records??"Unavailable"}. Rejected rows: ${rec.rejected_records??"Unavailable"}. Metadata sample truncated: ${rec.truncated?"yes":"no"}.`));
 panel.append(node("p","Recording metadata cannot establish camera image quality, installed channel layout or auxiliary camera placement. No cloud clips does not establish a failed camera."));
 if(data.camera_devices.includes(r.device_id)){const b=node("button","Check last hour of cloud recording metadata");b.disabled=data.collecting;b.addEventListener("click",()=>action({action:"recordings",device_id:r.device_id}));panel.append(b);}
 panel.append(node("h2","Recent checks (temporary)"));const list=node("ul");for(const e of r.history||[])list.append(node("li",`${stamp(e.at_utc)} · ${e.check}: ${e.outcome}`));panel.append(list);
}
async function load(){if(loading||document.hidden)return;loading=true;try{const response=await fetch("/dashboard/data",{cache:"no-store",credentials:"same-origin"});const result=await response.json();if(!response.ok){byId("message").textContent=result.error;byId("state").textContent="Access unavailable";data=null;byId("units").replaceChildren();byId("detail").hidden=true;for(const id of ["total","stale","failed"])byId(id).textContent="—";return;}data=result;if(!dirty)selected=new Set(data.camera_devices);render();}catch{byId("message").textContent="Dashboard unavailable. Previously shown observations may be stale.";byId("state").textContent="Connection interrupted";}finally{loading=false;}}
async function action(values){if(!data)return;byId("message").textContent="";const form=new URLSearchParams({csrf:data.csrf});for(const [k,v] of Object.entries(values)){if(Array.isArray(v)){for(const item of v)form.append(k,item);}else form.set(k,v);}try{const response=await fetch("/dashboard/action",{method:"POST",body:form,credentials:"same-origin"});const result=await response.json();if(!response.ok){byId("message").textContent=result.error;return;}if(result.disconnected){location.assign("/dashboard");return;}if(result.configured)dirty=false;await load();}catch{byId("message").textContent="Request failed. Refresh to check its outcome.";}}
byId("save").addEventListener("click",()=>action({action:"configure",device:[...selected]}));
byId("refresh").addEventListener("click",load);
byId("disconnect").addEventListener("click",()=>action({action:"disconnect"}));
document.addEventListener("visibilitychange",()=>{if(!document.hidden)load();});
load();setInterval(load,30000);
'''
