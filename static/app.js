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
let favorites = new Set();
try {
  const saved = JSON.parse(localStorage.getItem('nerv-guest-favorites'));
  if (Array.isArray(saved)) favorites = new Set(saved.filter(Number.isInteger));
} catch {}

function guests() {
  const status = $('guest-filter').value, type = $('guest-type').value;
  const query = $('guest-search').value.trim().toLowerCase();
  const favoritesOnly = $('guest-favorites').checked;
  const inventory = current?.guests || [];
  const rows = inventory.filter(g =>
    (!favoritesOnly || favorites.has(g.vmid)) &&
    (status === 'all' || g.status === status) && (type === 'all' || g.type === type) &&
    [g.name, g.vmid, g.node].some(value => String(value ?? '').toLowerCase().includes(query))
  ).sort((a,b) => Number(favorites.has(b.vmid)) - Number(favorites.has(a.vmid)) || a.vmid - b.vmid);
  $('guest-reset').hidden = !query && status === 'all' && type === 'all' && !favoritesOnly;
  const results = current ? `Показано ${rows.length} из ${inventory.length}` : '';
  if ($('guest-results').textContent !== results) $('guest-results').textContent = results;
  const markup = rows.map(g => {
    const allowed = current.managed_vmids?.includes(g.vmid) && !g.template;
    const actions = g.status === 'running' ? ['shutdown', 'reboot'] : g.status === 'stopped' ? ['start'] : [];
    const pending = pendingGuests.has(g.vmid);
    const disabled = pending || g.lock || document.body.classList.contains('stale');
    const buttons = allowed && actions.length ? actions.map(action =>
      `<button type="button" data-vmid="${esc(g.vmid)}" data-power="${action}" aria-label="${powerLabels[action]} ${esc(g.name || g.vmid)}" ${disabled?'disabled':''}>${powerLabels[action]}</button>`
    ).join('') : '—';
    const favorite = favorites.has(g.vmid);
    return `<tr role="row"><td role="cell" class="guest-name"><div class="guest-identity">
      <button type="button" class="favorite" data-favorite="${esc(g.vmid)}" aria-label="Избранное: ${esc(g.name || g.vmid)}" aria-pressed="${favorite}">${favorite?'★':'☆'}</button>
      <div><span class="vm-id">${esc(g.vmid)}</span><strong>${esc(g.name)}</strong></div></div></td>
      <td role="cell" class="guest-kind">${esc(g.type.toUpperCase())}<small>${esc(g.node)}</small></td>
      <td role="cell" class="guest-state">${badge(g.status, guestStatuses[g.status])}${pending?'<small>Операция выполняется</small>':''}</td>
      <td role="cell" class="guest-metric"><span class="mobile-metric">CPU</span>${g.status==='running'?fmt(g.cpu*100,1)+' %':'—'}</td>
      <td role="cell" class="guest-metric"><span class="mobile-metric">RAM</span>${bytes(g.mem)}<small>из ${bytes(g.maxmem)}</small></td>
      <td role="cell" class="guest-controls"><div class="guest-actions">${buttons}</div></td></tr>`;
  }).join('') || `<tr role="row"><td colspan="6" role="cell" class="empty guest-empty">${favoritesOnly && !favorites.size?'Нажмите ☆ рядом с машиной, чтобы добавить её в избранное.':'Машины не найдены'}</td></tr>`;
  if (markup !== guestMarkup) {
    const focused = document.activeElement;
    $('guests').innerHTML = guestMarkup = markup;
    if (focused?.dataset.power || focused?.dataset.favorite) {
      const replacement = Array.from($('guests').querySelectorAll('button')).find(button =>
        focused.dataset.favorite ? button.dataset.favorite === focused.dataset.favorite :
        button.dataset.vmid === focused.dataset.vmid && button.dataset.power === focused.dataset.power);
      (replacement && !replacement.disabled ? replacement : $('guest-search')).focus({preventScroll:true});
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
  $('guest-total').textContent = data.guests.length;
  $('guest-running').textContent = data.guests.filter(g => g.status === 'running').length;
  $('guest-stopped').textContent = data.guests.filter(g => g.status === 'stopped').length;
  guests();
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
$('guest-favorites').onchange = guests;
$('guest-reset').onclick = () => {
  $('guest-filter').value = $('guest-type').value = 'all';
  $('guest-search').value = '';
  $('guest-favorites').checked = false;
  guests();
  $('guest-search').focus();
};
$('guests').onclick = event => {
  const favorite = event.target.closest('button[data-favorite]');
  if (favorite) {
    const vmid = Number(favorite.dataset.favorite);
    if (favorites.has(vmid)) favorites.delete(vmid);
    else favorites.add(vmid);
    try { localStorage.setItem('nerv-guest-favorites', JSON.stringify([...favorites])); } catch {}
    guests();
    return;
  }
  const button = event.target.closest('button[data-power]');
  if (!button || button.disabled) return;
  const guest = current.guests.find(g => String(g.vmid) === button.dataset.vmid);
  if (guest) runPower(guest, button.dataset.power);
};
$('refresh').onclick=refresh;
$('settings').onclick=()=>$('config-dialog').showModal();
document.querySelectorAll('nav a').forEach(a=>a.onclick=()=>{document.querySelectorAll('nav a').forEach(n=>n.classList.toggle('active',n===a));});
let awgState=null, awgBusy=false;
function awgControls(disabled) {
  $('awg-refresh').disabled=awgBusy;
  for(const id of ['awg-domain','awg-add','awg-extra','awg-preset']) $(id).disabled=disabled;
  document.querySelectorAll('[data-awg-toggle],[data-awg-save],[data-awg-domains]').forEach(control=>control.disabled=disabled);
}
function renderAwg() {
  $('awg-list').innerHTML=awgState.rules.map(rule=>`<article class="awg-rule"><div><strong>${esc(rule.name)}</strong><p>${rule.enabled?'Через туннель AWG':'Обычный маршрут сети'}</p><details class="awg-domain-editor"><summary>Домены (${rule.domains.length})</summary><label>Домены и поддомены<textarea data-awg-domains="${esc(rule.id)}" rows="4" aria-label="Домены ${esc(rule.name)}">${esc(rule.domains.join('\n'))}</textarea></label><button type="button" data-awg-save="${esc(rule.id)}">Сохранить домены</button></details></div><button class="awg-switch" type="button" role="switch" aria-checked="${rule.enabled}" data-awg-toggle="${esc(rule.id)}" aria-label="AWG для ${esc(rule.name)}"><span aria-hidden="true"></span>${rule.enabled?'Вкл':'Выкл'}</button></article>`).join('')||'<p class="empty">Сайтов в списке пока нет.</p>';
  const selected=$('awg-preset').value;
  $('awg-preset').innerHTML='<option value="">Свой сайт</option>'+(awgState.presets||[]).map(preset=>`<option value="${esc(preset.domain)}">${esc(preset.name)}</option>`).join('');
  $('awg-preset').value=selected;
}
async function awgRequest(payload) {
  if(awgBusy) return;
  awgBusy=true; awgControls(true);
  $('awg-feedback').classList.remove('failure');
  $('awg-feedback').textContent=payload?'Применяем изменения на роутере…':'Загрузка списка…';
  const controller=new AbortController(), timeout=setTimeout(()=>controller.abort(),160000);
  try {
    const options={signal:controller.signal};
    if(payload) Object.assign(options,{method:'POST',headers:{'Content-Type':'application/json','X-NERV-Action':'awg-routing'},body:JSON.stringify({...payload,revision:awgState.revision})});
    const response=await fetch('/api/router/awg-sites',options), data=await response.json();
    if(!response.ok) throw Error(data.error||'Не удалось получить настройки AWG.');
    awgState=data; renderAwg();
    if(payload?.action==='add') {$('awg-domain').value='';$('awg-extra').value='';$('awg-preset').value='';}
    $('awg-feedback').textContent=payload?'Изменения применены для всей сети. Переподключитесь к сайту, чтобы открыть новое соединение.':'Список получен с OpenWrt.';
  } catch(error) {
    awgState=null;
    $('awg-feedback').classList.add('failure');
    $('awg-feedback').textContent=error.name==='AbortError'?'Ответ не получен. Обновите список перед повтором: изменение могло примениться.':error.message;
  } finally {clearTimeout(timeout);awgBusy=false;awgControls(!awgState);}
}
function splitDomains(value) {return value.split(/[\s,;]+/).filter(Boolean);}
$('awg-preset').onchange=()=>{
  const preset=awgState?.presets?.find(item=>item.domain===$('awg-preset').value);
  $('awg-domain').value=preset?.domain||'';
  $('awg-extra').value=preset?.domains.slice(1).join('\n')||'';
};
$('awg-form').onsubmit=event=>{event.preventDefault();if(awgState&&!awgBusy)awgRequest({action:'add',domain:$('awg-domain').value.trim(),extra_domains:splitDomains($('awg-extra').value)});};
$('awg-refresh').onclick=()=>awgRequest();
$('awg-list').onclick=event=>{
  const button=event.target.closest('[data-awg-toggle],[data-awg-save]');
  if(!button||button.disabled||!awgState||awgBusy)return;
  if(button.dataset.awgToggle) {
    const rule=awgState.rules.find(item=>item.id===button.dataset.awgToggle);
    if(rule)awgRequest({action:'set_enabled',id:rule.id,enabled:!rule.enabled});
  } else {
    const editor=[...document.querySelectorAll('[data-awg-domains]')].find(item=>item.dataset.awgDomains===button.dataset.awgSave);
    if(editor)awgRequest({action:'update_domains',id:button.dataset.awgSave,domains:splitDomains(editor.value)});
  }
};
awgRequest();
function clock(){$('clock').textContent=new Date().toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'});}clock();setInterval(clock,1000);
refresh();setInterval(()=>{if(!document.hidden)refresh();},5000);
