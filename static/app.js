'use strict';
const $ = id => document.getElementById(id);
let current = null, busy = false, history = [], lastMode = null;
const fmt = (v, digits=0) => Number.isFinite(v) ? v.toLocaleString('ru-RU', {maximumFractionDigits:digits}) : '—';
const pct = (a,b) => Number.isFinite(a) && b > 0 ? Math.max(0,Math.min(100,a/b*100)) : null;
const bytes = v => Number.isFinite(v) ? (v >= 1024**4 ? fmt(v/1024**4,2)+' TiB' : fmt(v/1024**3,1)+' GiB') : '—';
const esc = s => String(s ?? '—').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function bar(id, value) { $(id).innerHTML = Array.from({length:24},(_,i)=>`<i class="${value!==null && i<Math.ceil(value/100*24)?'on':''}"></i>`).join(''); }
function badge(status) { const good=['running','online','available','OK'].includes(status); return `<span class="badge ${good?'':status==='stopped'?'off':'bad'}">${esc(status)}</span>`; }
function guests() {
  const rows=(current?.guests || []).filter(g=>$('guest-filter').value==='all'||g.status===$('guest-filter').value);
  $('guests').innerHTML=rows.map(g=>`<tr><td><span class="vm-id">${esc(g.vmid)}</span>${esc(g.name)}<small>${g.type==='qemu'?'Виртуальная машина':'Контейнер'}</small></td><td>${esc(g.type.toUpperCase())}<small>${esc(g.node)}</small></td><td>${badge(g.status)}</td><td>${g.status==='running'?fmt(g.cpu*100,1)+' %':'—'}</td><td>${bytes(g.mem)}<small>из ${bytes(g.maxmem)}</small></td></tr>`).join('') || '<tr><td colspan="5" class="empty">Машины не найдены</td></tr>';
}
function render(data) {
  current=data; document.body.classList.remove('stale');
  $('title').textContent=data.title;
  $('mode').textContent=data.mode==='demo'?'● DEMO MODE / ДЕМОНСТРАЦИОННЫЕ ДАННЫЕ':'● LIVE / PROXMOX API';
  $('config-mode').textContent=data.mode==='demo'?'демонстрационные данные':'живые данные Proxmox';
  $('updated').textContent='Обновлено '+new Date(data.updated_at*1000).toLocaleTimeString('ru-RU');
  const nodes=data.nodes, node=nodes[0];
  const cpu=node?.status==='online' && Number.isFinite(node.cpu) ? node.cpu*100:null, ram=node?.status==='online'?pct(node.mem,node.maxmem):null;
  $('host-name').textContent=node?.node||'Нет доступных узлов';
  $('host-status').textContent=node?.status?.toUpperCase()||'UNKNOWN';
  $('host-detail').textContent=`PROXMOX VE / ${nodes.length} узел · ${data.guests.length} VM / CT`;
  $('uptime').textContent=Number.isFinite(node?.uptime)?`${Math.floor(node.uptime/86400)} д ${Math.floor(node.uptime%86400/3600)} ч ${Math.floor(node.uptime%3600/60)} м`:'—';
  $('cpu').innerHTML=fmt(cpu,1)+'<small>%</small>'; $('ram').innerHTML=fmt(ram,1)+'<small>%</small>';
  $('cores').textContent=Number.isFinite(node?.maxcpu)?`${node.maxcpu} vCPU`:'—';
  $('ram-used').textContent=bytes(node?.mem)+' занято'; $('ram-total').textContent='из '+bytes(node?.maxmem);
  bar('cpu-bar',cpu); bar('ram-bar',ram);
  if(lastMode!==data.mode) history=[]; lastMode=data.mode;
  history.push([cpu,ram]); if(history.length>60) history.shift();
  for(const [id,index] of [['cpu-line',0],['ram-line',1]]) {
    $(id).setAttribute('points',history.map((h,i)=>h[index]===null?'':`${i*1000/59},${90-Math.max(0,Math.min(100,h[index]))*.8}`).join(' '));
  }
  $('guest-count').textContent=`${data.guests.filter(g=>g.status==='running').length} RUNNING / ${data.guests.length} TOTAL`; guests();
  $('disks').innerHTML=data.storage.map(s=>`<div class="disk"><div class="disk-heading"><span>${esc(s.storage)}</span><span>${fmt(pct(s.disk,s.maxdisk),1)} %</span></div><div class="disk-track"><span class="disk-fill" data-fill="${pct(s.disk,s.maxdisk)||0}"></span></div><div class="disk-foot"><span>${bytes(s.disk)} / ${bytes(s.maxdisk)}</span><span>${esc(s.node)} · ${esc(s.status||'unknown')}</span></div></div>`).join('')||'<p class="empty">Хранилища недоступны</p>';
  document.querySelectorAll('[data-fill]').forEach(el=>el.style.width=el.dataset.fill+'%');
  $('service-list').innerHTML=data.services.filter(s=>{try{return ['http:','https:'].includes(new URL(s.url).protocol);}catch{return false;}}).map(s=>`<a class="service" href="${esc(s.url)}" target="_blank" rel="noopener noreferrer"><b>${esc(s.name)} <span>↗</span></b><small>${esc(s.description||new URL(s.url).host)}</small></a>`).join('')||'<div class="panel empty">Добавьте ссылки на Proxmox, OpenWrt, AdGuard и другие сервисы в config.json.</div>';
  $('task-list').innerHTML=data.tasks.map(t=>`<tr><td>${esc(new Date(t.starttime*1000).toLocaleString('ru-RU'))}</td><td>${esc(t.type)}</td><td>${esc(t.id||'—')}</td><td>${t.endtime?badge(t.status||'unknown'):'<span class="badge off">В процессе</span>'}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">Нет доступных задач</td></tr>';
  $('error').hidden=!data.warnings.length; $('error').textContent=data.warnings.join(' · ');
}
async function refresh() {
  if(busy) return; busy=true; $('refresh').disabled=true;
  const controller=new AbortController(), timeout=setTimeout(()=>controller.abort(),18000);
  try {const response=await fetch('/api/status',{signal:controller.signal}); const data=await response.json(); if(!response.ok) throw Error(data.error||'Ошибка API'); render(data);}
  catch(error) {document.body.classList.add('stale'); $('mode').textContent='● СВЯЗЬ ПОТЕРЯНА'; $('error').hidden=false; $('error').textContent=(error.name==='AbortError'?'Превышено время ожидания':error.message)+(current?' · Показаны устаревшие данные.':'');}
  finally {clearTimeout(timeout);busy=false;$('refresh').disabled=false;}
}
try{$('theme').value=localStorage.getItem('nerv-theme')||'NERV';}catch{}
document.body.dataset.theme=$('theme').value;
$('theme').onchange=()=>{document.body.dataset.theme=$('theme').value;try{localStorage.setItem('nerv-theme',$('theme').value);}catch{}};
$('guest-filter').onchange=guests;
$('refresh').onclick=refresh;
$('settings').onclick=()=>$('config-dialog').showModal();
document.querySelectorAll('nav a').forEach(a=>a.onclick=()=>{document.querySelectorAll('nav a').forEach(n=>n.classList.toggle('active',n===a));});
function clock(){$('clock').textContent=new Date().toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'});}clock();setInterval(clock,1000);
refresh();setInterval(()=>{if(!document.hidden)refresh();},5000);
