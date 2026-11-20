'use strict';
const $ = id => document.getElementById(id);
let current = null, busy = false, history = [], lastMode = null;
const fmt = (v, digits=0) => Number.isFinite(v) ? v.toLocaleString('ru-RU', {maximumFractionDigits:digits}) : '—';
const pct = (a,b) => Number.isFinite(a) && b > 0 ? Math.max(0,Math.min(100,a/b*100)) : null;
const bytes = v => Number.isFinite(v) ? (v >= 1024**4 ? fmt(v/1024**4,2)+' TiB' : fmt(v/1024**3,1)+' GiB') : '—';
const esc = s => String(s ?? '—').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function bar(id, value) { $(id).innerHTML = Array.from({length:24},(_,i)=>`<i class="${value!==null && i<Math.ceil(value/100*24)?'on':''}"></i>`).join(''); }
function badge(status, label = status) { const good=['running','online','available','OK'].includes(status); return `<span class="badge ${good?'':status==='stopped'?'off':'bad'}">${esc(label)}</span>`; }
const powerLabels = {start:'Запустить', shutdown:'Выключить', reboot:'Перезагрузить'};
const guestStatuses = {running:'Запущена', stopped:'Выключена', paused:'Приостановлена'};
const pendingGuests = new Set();
let guestMarkup = '';

function guests() {
  const status = $('guest-filter').value, type = $('guest-type').value;
  const query = $('guest-search').value.trim().toLowerCase();
  const rows = (current?.guests || []).filter(g =>
    (status === 'all' || g.status === status) && (type === 'all' || g.type === type) &&
    [g.name, g.vmid, g.node].some(value => String(value ?? '').toLowerCase().includes(query))
  ).sort((a,b) => a.vmid - b.vmid);
  const markup = rows.map(g => {
    const allowed = current.managed_vmids?.includes(g.vmid) && !g.template;
    const actions = g.status === 'running' ? ['shutdown', 'reboot'] : g.status === 'stopped' ? ['start'] : [];
    const pending = pendingGuests.has(g.vmid);
    const disabled = pending || g.lock || document.body.classList.contains('stale');
    const buttons = allowed && actions.length ? actions.map(action =>
      `<button type="button" data-vmid="${esc(g.vmid)}" data-power="${action}" aria-label="${powerLabels[action]} ${esc(g.name || g.vmid)}" ${disabled?'disabled':''}>${powerLabels[action]}</button>`
    ).join('') : '—';
    return `<tr><td><span class="vm-id">${esc(g.vmid)}</span>${esc(g.name)}<small>${g.template?'Шаблон':g.type==='qemu'?'Виртуальная машина':'Контейнер'}</small></td>
      <td>${esc(g.type.toUpperCase())}<small>${esc(g.node)}</small></td>
      <td>${badge(g.status, guestStatuses[g.status])}${pending?'<small>Операция выполняется</small>':''}</td>
      <td>${g.status==='running'?fmt(g.cpu*100,1)+' %':'—'}</td><td>${bytes(g.mem)}<small>из ${bytes(g.maxmem)}</small></td>
      <td><div class="guest-actions">${buttons}</div></td></tr>`;
  }).join('') || '<tr><td colspan="6" class="empty">Машины не найдены</td></tr>';
  if (markup !== guestMarkup) {
    const focused = document.activeElement;
    $('guests').innerHTML = guestMarkup = markup;
    if (focused?.dataset.power) {
      const replacement = Array.from($('guests').querySelectorAll('button')).find(button =>
        button.dataset.vmid === focused.dataset.vmid && button.dataset.power === focused.dataset.power);
      replacement?.focus({preventScroll:true});
    }
  }
}

function powerFeedback(message, failure = false) {
  const notice = $('guest-feedback');
  notice.hidden = false;
  notice.classList.toggle('failure', failure);
  notice.textContent = message;
}

async function powerRequest(url, options) {
  const response = await fetch(url, {...options, signal:AbortSignal.timeout(15000)});
  const data = await response.json();
  if (!response.ok) throw Error(data.error || 'Ошибка запроса к панели.');
  return data;
}

async function runPower(guest, action) {
  const name = guest.name || guest.vmid;
  const dialog = $('power-dialog');
  $('power-title').textContent = powerLabels[action] + ' ' + name + '?';
  $('power-description').textContent = action === 'start' ? 'Proxmox запустит машину.' :
    'Подключения и службы этой машины будут прерваны. Proxmox выполнит штатную операцию.';
  dialog.returnValue = '';
  dialog.showModal();
  await new Promise(resolve => dialog.addEventListener('close', resolve, {once:true}));
  if (dialog.returnValue !== 'confirm' || document.body.classList.contains('stale') || pendingGuests.has(guest.vmid)) return;
  pendingGuests.add(guest.vmid);
  guests();
  powerFeedback(name + ' · отправка команды в Proxmox…');
  try {
    const {upid} = await powerRequest(`/api/guests/${guest.vmid}/${action}`, {
      method:'POST', headers:{'X-NERV-Action':'guest-power'}
    });
    powerFeedback(name + ' · задача принята Proxmox.');
    const deadline = Date.now() + 180000;
    while (Date.now() < deadline) {
      const task = await powerRequest('/api/power-tasks/' + encodeURIComponent(upid));
      if (task.status === 'stopped') {
        if (task.exitstatus !== 'OK') throw Error(task.exitstatus || 'Задача завершилась с ошибкой.');
        powerFeedback(name + ' · операция выполнена.');
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    throw Error('Задача ещё выполняется. Проверьте журнал Proxmox.');
  } catch (error) {
    powerFeedback(name + ' · ' + error.message, true);
  } finally {
    pendingGuests.delete(guest.vmid);
    await refresh();
    guests();
  }
}
function renderRouter(router = {state:'not_configured'}) {
  const states = {running:'Процесс запущен',stopped:'Процесс остановлен',unknown:'Нет данных',not_configured:'Не настроен',configured_down:'Настроен, не поднят',up:'Интерфейс поднят'};
  const connected = {connected:'SSH / CONNECTED',demo:'DEMO / ПРИМЕР',unavailable:'SSH / НЕТ СВЯЗИ',not_configured:'НЕ ПОДКЛЮЧЁН'};
  $('router-connection').textContent=connected[router.state]||'НЕТ ДАННЫХ';
  const notice = router.error || (router.state==='not_configured'?'Мониторинг OpenWrt не подключён. Настройте ограниченный SSH-ключ по инструкции в docs/openwrt.md.':'');
  $('router-notice').textContent=notice+(router.stale?' Показаны устаревшие данные служб.':'')+(router.checked_at?' Последний сбор: '+new Date(router.checked_at*1000).toLocaleTimeString('ru-RU'):'');
  $('router-notice').classList.toggle('warning',!!router.error);
  const cards=(router.services||[]).map(service=>({name:service.name,state:service.state,detail:'Состояние процесса на роутере'}));
  if(router.amneziawg) {
    const wg=router.amneziawg;
    cards.push({name:'AmneziaWG',state:wg.state,detail:wg.state==='up'?(Number.isFinite(wg.handshake_age)?'Последний handshake: '+fmt(wg.handshake_age)+' с назад':'Handshake пока не зарегистрирован'):'Конфигурация и интерфейс туннеля'});
  }
  $('router-cards').classList.toggle('router-stale',!!router.stale);
  $('router-cards').innerHTML=cards.map(c=>`<article class="panel router-card"><div class="panel-label">${esc(c.name)}</div><strong class="${c.state==='running'?'positive':''}">${esc(states[c.state]||'Нет данных')}</strong><small>${esc(c.detail)}</small></article>`).join('');
  const probes=[];
  if(router.wan) probes.push({name:'WAN',value:router.wan.up===true?'Интерфейс поднят':router.wan.up===false?'Интерфейс не поднят':'Нет данных',detail:(router.wan.addresses||[]).join(', '),ok:router.wan.up===true,stale:router.stale});
  if(router.probes) {
    probes.push({name:'DNS / UDP 53',value:router.probes.dns==='resolved'?'Имя разрешено':'Нет успешного ответа',detail:'example.com через роутер',ok:router.probes.dns==='resolved'});
    for(const [key,name] of [['adguard_tcp','AdGuard / TCP'],['telegram_tcp','Telegram / TCP']]) probes.push({name,value:router.probes[key]==='reachable'?'Порт доступен':'Порт недоступен',detail:'Соединение из контейнера панели',ok:router.probes[key]==='reachable'});
  }
  $('router-probes').innerHTML=probes.map(p=>`<div class="router-probe ${p.stale?'router-stale':''}"><small>${esc(p.name)}</small><span class="${p.ok&&!p.stale?'positive':''}">${esc(p.value)}</span><small>${esc(p.detail)}</small></div>`).join('');
}
function render(data) {
  current=data; renderRouter(data.router); document.body.classList.remove('stale');
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
  catch(error) {document.body.classList.add('stale'); guests(); $('mode').textContent='● СВЯЗЬ ПОТЕРЯНА'; $('error').hidden=false; $('error').textContent=(error.name==='AbortError'?'Превышено время ожидания':error.message)+(current?' · Показаны устаревшие данные.':'');}
  finally {clearTimeout(timeout);busy=false;$('refresh').disabled=false;}
}
try{$('theme').value=localStorage.getItem('nerv-theme')||'NERV';}catch{}
document.body.dataset.theme=$('theme').value;
$('theme').onchange=()=>{document.body.dataset.theme=$('theme').value;try{localStorage.setItem('nerv-theme',$('theme').value);}catch{}};
$('guest-filter').onchange = guests;
$('guest-type').onchange = guests;
$('guest-search').oninput = guests;
$('guests').onclick = event => {
  const button = event.target.closest('button[data-power]');
  if (!button || button.disabled) return;
  const guest = current.guests.find(g => String(g.vmid) === button.dataset.vmid);
  if (guest) runPower(guest, button.dataset.power);
};
$('refresh').onclick=refresh;
$('settings').onclick=()=>$('config-dialog').showModal();
document.querySelectorAll('nav a').forEach(a=>a.onclick=()=>{document.querySelectorAll('nav a').forEach(n=>n.classList.toggle('active',n===a));});
function clock(){$('clock').textContent=new Date().toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'});}clock();setInterval(clock,1000);
refresh();setInterval(()=>{if(!document.hidden)refresh();},5000);
