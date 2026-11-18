'use strict';

const dpiLabels = {
  queued: 'В очереди', running: 'В работе', done: 'Завершено', timeout: 'Истекло время ожидания',
  cancelled: 'Отменено', infrastructure: 'Сбой сети, DNS или стенда', failed: 'Ошибка',
  incompatible: 'Стенд и роутер несовместимы', checking: 'Проверка из LAN',
  applied: 'Применено', rolled_back: 'Откат выполнен', expired: 'Операция просрочена',
  search: 'Подбор', manual: 'Ручная ревизия', revision: 'Ревизия', check: 'Проверка',
  direct: 'Доступен без обработки', stale: 'Конфигурация изменилась, нужна перепроверка',
  verified: 'Есть подтверждённые кандидаты', no_candidate: 'Проверенных кандидатов нет', checked: 'Замеры сохранены',
};
const dpiReasons = {
  dns: 'DNS', connect: 'Не удалось подключиться', tls: 'Ошибка TLS', timeout: 'Таймаут',
  body: 'Неполная загрузка', http: 'Неуспешный HTTP-ответ', redirect: 'Отклонённый редирект',
  media: 'Видеоданные недоступны', internal: 'Ошибка зонда', drift: 'Конфигурация изменилась',
  syntax: 'Проверка синтаксиса не пройдена', service: 'Служба не запустилась',
  probe: 'Контрольный запрос из LAN не прошёл', storage: 'Ошибка сохранения',
};
const dpiTime = stamp => stamp ? new Date(stamp * 1000).toLocaleString('ru-RU') : '—';
let dpiLoading = false;
let dpiRendered = '';

function dpiButton(text, action, id = '', disabled = false) {
  return `<button type="button" data-dpi-action="${esc(action)}" data-id="${esc(id)}" ${disabled ? 'disabled' : ''}>${esc(text)}</button>`;
}

function dpiRule(rule) {
  if (!rule) return '<span>—</span>';
  return `<small class="dpi-domains">${esc(rule.domains.join(', '))}</small><code>${esc(rule.args.join(' '))}</code>`;
}

function dpiOperation(data) {
  const result = data.operation || data.last_operation;
  const action = result?.action === 'rollback' ? 'Откат' : 'Активация';
  const message = result ? `<span>${action} · ${esc(result.profile)} ·
    ${esc(dpiLabels[result.phase] || result.phase)}
    ${result.reason ? ' · ' + esc(dpiReasons[result.reason] || result.reason) : ''}</span>` : '';
  const previous = data.router?.previous;
  $('dpi-operation').innerHTML = message + (previous ? dpiButton('Откатить ' + previous, 'rollback', '',
    !data.router_online || Boolean(data.operation)) : '');
}

function dpiProfiles(data) {
  const html = Object.entries(data.profiles).sort(([a], [b]) => a.localeCompare(b)).map(([name, profile]) => {
    const backups = data.versions.filter(version => version.profile === name).map(version => {
      const canApply = version.delivered && version.eligible && data.router_online && data.lan_online && !data.operation;
      const delivery = !version.eligible ? 'Нужна перепроверка' : version.delivered ?
        'Доставлен ' + dpiTime(version.delivered) : 'Ожидает доставки';
      return `<div class="dpi-variant">
        <div><strong>Запасной · ${esc(delivery)}</strong><small>Подтверждение до ${esc(dpiTime(version.expires))} · медиана ${esc(version.median_ms)} мс</small></div>
        ${dpiRule(version.rule)}
        ${dpiButton('Применить на OpenWrt', 'apply', version.id, !canApply)}
      </div>`;
    }).join('');
    const activeScore = profile.active_score ? ` · загрузки ${profile.active_score.join('/')}` : '';
    const auto = profile.automatic ? 'Отключить автопереключение' : 'Включить автопереключение';
    return `<article class="panel dpi-profile">
      <div class="dpi-profile-header">
        <h4>${esc(name)}</h4>
        ${profile.drift ? '<span class="badge bad">Конфигурация изменилась</span>' : ''}
        <div class="dpi-actions">
          ${dpiButton('Перепроверить и подобрать заново', 'revision', name)}
          ${dpiButton(auto, profile.automatic ? 'auto-off' : 'auto-on', name)}
        </div>
      </div>
      <div class="dpi-variant"><strong>${profile.active ? 'Активный на OpenWrt' : 'Ожидает первой активации'}${esc(activeScore)}</strong>
        ${dpiRule(profile.active)}
        <small>Последняя проверка ${esc(dpiTime(profile.last_check))} · следующая ревизия
          ${profile.active ? esc(dpiTime(profile.next_revision)) : 'после активации'}</small>
      </div>
      ${backups}
    </article>`;
  }).join('');
  $('dpi-profiles').innerHTML = html || '<p class="empty">Профили появятся после синхронизации роутера или запуска подбора.</p>';
}

function dpiProbeRows(title, rows) {
  const entries = rows?.flatMap((row, i) => Object.entries(row).map(([name, probe]) => `<tr>
    <td>${esc(title)} · ${i + 1}<small>${esc(dpiTime(probe?.at))}</small></td><td>${esc(name)}</td>
    <td>${esc(!probe ? 'Не проверено' : probe.error ? dpiReasons[probe.error] || probe.error : 'Завершено')}</td>
    <td>${esc(probe?.ips.join(', '))}</td><td>${esc(probe?.bytes)}</td><td>${esc(probe?.ms)}</td>
  </tr>`)).join('') || '';
  return entries;
}

function dpiReport(report) {
  if (!report) return '';
  const outcomes = {completed: 'Выполнен', timeout: 'Таймаут', failed: 'Ошибка', not_requested: 'Не запускался'};
  const options = report.candidates?.map((candidate, i) =>
    `<li>Вариант ${i + 1} · ${candidate.accepted ? 'Подтверждён' : 'Не допущен'} ·
      синтаксис ${candidate.syntax ? 'проверен' : 'отклонён'} ${dpiRule(candidate.rule)}</li>`).join('');
  const rows = dpiProbeRows('Без стратегии', report.baseline) + dpiProbeRows('Активный', report.active) +
    dpiProbeRows('Контроль', report.control?.map(probe => ({DNS_HTTPS: probe}))) +
    (report.candidates?.map((candidate, i) => dpiProbeRows('Вариант ' + (i + 1), candidate.attempts) +
      dpiProbeRows('Соседние · ' + (i + 1), candidate.neighbors)).join('') || '');
  return `<div class="dpi-report">
    ${report.outcome ? `<p>${esc(dpiLabels[report.outcome])} · Подбор: ${esc(outcomes[report.selection])} · IPv6 и QUIC не проверялись</p>` : ''}
    ${report.series ? `<small>Серии · ${esc(report.series.map(dpiTime).join(' / '))}</small>` : ''}
    ${options ? `<ul>${options}</ul>` : ''}
    ${rows ? `<div class="table-scroll"><table><thead><tr><th>Попытка</th><th>Проверка</th><th>Результат</th>
      <th>Адреса</th><th>Байт</th><th>мс</th></tr></thead><tbody>${rows}</tbody></table></div>` : ''}
  </div>`;
}

function dpiJobs(data) {
  const expanded = new Set([...$('dpi-jobs').querySelectorAll('[open]')].map(item => item.dataset.job));
  $('dpi-jobs').innerHTML = data.jobs.slice().reverse().map(job => `<details data-job="${esc(job.id)}"
      ${expanded.has(job.id) ? 'open' : ''}>
    <summary>${esc(dpiTime(job.created))} · ${esc(job.profile)} · ${esc(dpiLabels[job.kind])} ·
      ${esc(job.cancel_requested && job.state === 'running' ? 'Отмена выполняется' : dpiLabels[job.state])}</summary>
    ${dpiReport(job.report)}
    ${['queued', 'running'].includes(job.state) && !job.cancel_requested ? dpiButton('Отменить', 'cancel', job.id) : ''}
    </details>`).join('') || '<p class="empty">Заданий пока нет.</p>';
}

async function dpiRefresh() {
  if (dpiLoading) return;
  dpiLoading = true;
  try {
    const response = await fetch('/api/dpi', {signal: AbortSignal.timeout(8000)});
    if (!response.ok) throw Error();
    const data = await response.json();
    $('dpi').hidden = !data.enabled;
    $('dpi-link').hidden = !data.enabled;
    if (!data.enabled) return;
    $('dpi-connection').textContent = `OpenWrt ${data.router_online ? 'на связи' : 'недоступен'} · LAN-зонд ${data.lan_online ? 'на связи' : 'недоступен'}`;
    const serialized = JSON.stringify([data.operation, data.last_operation, data.router?.previous, data.profiles,
      data.versions, data.jobs, data.router_online, data.lan_online]);
    if (serialized !== dpiRendered) {
      dpiOperation(data);
      dpiProfiles(data);
      dpiJobs(data);
      dpiRendered = serialized;
    }
  } catch {
    $('dpi-connection').textContent = 'Нет связи с API';
  } finally {
    dpiLoading = false;
  }
}

async function dpiPost(action, payload) {
  const message = $('dpi-message');
  message.hidden = false;
  message.textContent = 'Отправка…';
  try {
    const response = await fetch('/api/dpi/admin/' + action, {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-NERV-Request': 'dpi'},
      body: JSON.stringify(payload), signal: AbortSignal.timeout(8000),
    });
    const data = await response.json();
    if (!response.ok) throw Error(data.error || 'Запрос отклонён.');
    message.textContent = action === 'auto' ? 'Настройка сохранена.' : 'Запрос принят.';
    await dpiRefresh();
    return true;
  } catch (error) {
    message.textContent = error.message;
    return false;
  }
}

$('dpi-search').addEventListener('submit', async event => {
  event.preventDefault();
  if (await dpiPost('add', {url: $('dpi-address').value.trim()})) $('dpi-search').reset();
});

$('dpi').addEventListener('click', async event => {
  const button = event.target.closest('[data-dpi-action]');
  if (!button) return;
  const {dpiAction: action, id} = button.dataset;
  button.disabled = true;
  try {
    if (action.startsWith('auto-')) await dpiPost('auto', {profile: id, enabled: action === 'auto-on'});
    else if (action === 'revision') await dpiPost(action, {profile: id});
    else await dpiPost(action, {id});
  } finally {
    button.disabled = false;
  }
});

dpiRefresh();
setInterval(() => { if (!document.hidden) dpiRefresh(); }, 5000);
