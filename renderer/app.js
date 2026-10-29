'use strict';

/* global api */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const CARRIERS = [
  ['beeline_msk', 'Билайн (Москва)'],
  ['yota_msk', 'Yota (Москва)'],
  ['tele2_msk', 'Tele2 (Москва)'],
  ['tele2_krasnoyarsk', 'Tele2 (Красноярск)'],
  ['tattelecom', 'Таттелеком / Летай'],
  ['megafon_regions', 'Мегафон (регионы)'],
  ['tmobile_us', 'Т-Мобайл (Москва и область)'],
];

const COMMANDS = [
  { id: 'add', cmd: 'add', title: 'Добавить клиента', desc: 'Создать одного или нескольких клиентов, опционально со сроком, PSK и индивидуальными маршрутами.', danger: false },
  { id: 'remove', cmd: 'remove', title: 'Удалить клиента', desc: 'Удалить одного или нескольких клиентов и применить конфиг без перезапуска.', danger: true },
  { id: 'list', cmd: 'list', title: 'Список клиентов', desc: 'Показать клиентов, IP, статус и срок действия. Машиночитаемый JSON.', danger: false },
  { id: 'stats', cmd: 'stats', title: 'Статистика трафика', desc: 'Получено/отправлено, последний handshake и статус по каждому клиенту.', danger: false },
  { id: 'regen', cmd: 'regen', title: 'Перегенерировать файлы', desc: 'Пересоздать .conf, QR и vpn:// для всех или указанных клиентов.', danger: false },
  { id: 'modify', cmd: 'modify', title: 'Изменить параметр', desc: 'DNS, Endpoint, AllowedIPs или PersistentKeepalive конкретного клиента.', danger: false },
  { id: 'check', cmd: 'check', title: 'Проверить сервер', desc: 'Сервис, интерфейс, порт, модуль, клиенты, UFW и поколение протокола.', danger: false },
  { id: 'show', cmd: 'show', title: 'awg show', desc: 'Живой статус интерфейса AmneziaWG: пиры, handshake, трафик.', danger: false },
  { id: 'diagnose', cmd: 'diagnose', title: 'Диагностика', desc: 'Модуль ядра, sysctl, UFW и сравнение параметров с профилем оператора.', danger: false },
  { id: 'backup', cmd: 'backup', title: 'Создать бэкап', desc: 'Архив конфигов, ключей, данных expiry и cron в /root/awg/backups.', danger: false },
  { id: 'restore', cmd: 'restore', title: 'Восстановить из бэкапа', desc: 'Заменить конфиги и ключи из выбранного архива. Опасная операция.', danger: true },
  { id: 'restart', cmd: 'restart', title: 'Перезапустить сервис', desc: 'systemctl restart awg-quick@awg0. Кратковременный разрыв туннелей.', danger: true },
  { id: 'repair-module', cmd: 'repair-module', title: 'Починить модуль ядра', desc: 'DKMS-пересборка и загрузка модуля после обновления ядра. До 5 минут.', danger: true },
  { id: 'help', cmd: 'help', title: 'Справка manage', desc: 'Показать встроенную справку manage_amneziawg.sh.', danger: false },
  { id: 'raw', cmd: 'ssh', title: 'Произвольная команда', desc: 'Открыть SSH-консоль и выполнить любую команду на сервере.', danger: true },
];

const state = {
  info: null,
  profiles: [],
  profileId: null,
  status: null,
  check: null,
  clients: [],
  stats: [],
  server: null,
  serverReveal: false,
  logs: [],
  backups: [],
  selectedLog: '',
  serverLogText: '',
  appLog: [],
  consoleBuffer: '',
  consoleHistory: [],
  consoleIndex: -1,
  tab: 'overview',
  busy: 0,
  diagRunning: false,
  maintenance: { logInfo: null, backups: [], selected: '', loaded: false, loading: false },
  update: null,
};

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function esc(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function fmtUnix(ts) {
  const n = Number(ts);
  if (!n || !Number.isFinite(n)) return '—';
  try {
    return new Date(n * 1000).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
  } catch (_) {
    return String(ts);
  }
}

function fmtBytes(n) {
  const num = Number(n) || 0;
  if (num < 1024) return `${num} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = num / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}

function fmtDuration(ms) {
  const n = Number(ms) || 0;
  if (n < 1000) return `${n} мс`;
  return `${(n / 1000).toFixed(n < 10000 ? 1 : 0)} с`;
}

function shortFp(fp) {
  if (!fp) return '—';
  return fp.length > 26 ? `${fp.slice(0, 18)}…${fp.slice(-8)}` : fp;
}

function parseClientNames(value, { optional = false } = {}) {
  const list = String(value || '').split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  if (!list.length) {
    if (optional) return [];
    throw new Error('Укажите хотя бы одно имя клиента.');
  }
  for (const n of list) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(n)) {
      throw new Error(`Недопустимое имя «${n}»: только латиница, цифры, _ и -, до 64 символов.`);
    }
  }
  return list;
}

function statusInfo(code, fallbackText) {
  const map = {
    active: ['good', 'Активен'],
    recent: ['warn', 'Недавно'],
    no_handshake: ['', 'Нет handshake'],
    key_error: ['bad', 'Ошибка ключа'],
    inactive: ['', 'Неактивен'],
    error: ['bad', 'Ошибка'],
  };
  if (map[code]) return map[code];
  return ['', fallbackText || code || '—'];
}

function toast(text, type = 'info', timeout = 4200) {
  const root = $('#toasts');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = text;
  root.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(4px)';
    el.style.transition = 'opacity .2s, transform .2s';
    setTimeout(() => el.remove(), 220);
  }, timeout);
}

function showBusy(text = 'Выполняется…') {
  state.busy += 1;
  if (state.busy > 1) return;
  const el = document.createElement('div');
  el.className = 'busy-overlay';
  el.id = 'busyOverlay';
  el.innerHTML = `<div class="busy-box"><span class="spinner"></span><span>${esc(text)}</span></div>`;
  document.body.appendChild(el);
}

function hideBusy() {
  state.busy = Math.max(0, state.busy - 1);
  if (state.busy === 0) {
    const el = $('#busyOverlay');
    if (el) el.remove();
  }
}

function openModal(opts) {
  const root = $('#modalRoot');
  const wrap = document.createElement('div');
  wrap.className = 'modal-backdrop';
  wrap.innerHTML = `
    <div class="modal ${opts.wide ? 'wide' : ''} ${opts.slim ? 'slim' : ''}" role="dialog" aria-modal="true">
      <div class="modal-head">
        <div>
          <h3>${esc(opts.title || '')}</h3>
          ${opts.subtitle ? `<p>${esc(opts.subtitle)}</p>` : ''}
        </div>
        <button class="modal-close" type="button" aria-label="Закрыть">×</button>
      </div>
      <div class="modal-body">${opts.body || ''}</div>
      ${opts.footer ? `<div class="modal-foot">${opts.footer}</div>` : ''}
    </div>`;
  root.appendChild(wrap);

  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    wrap.remove();
    if (opts.onClose) opts.onClose();
  };
  wrap.querySelector('.modal-close').addEventListener('click', close);
  if (opts.dismissible !== false) {
    wrap.addEventListener('mousedown', (e) => { if (e.target === wrap) close(); });
  }
  const handle = { wrap, el: wrap.querySelector('.modal'), close };
  if (opts.onMount) opts.onMount(handle);
  return handle;
}

function confirmDialog(opts) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const id = `cf${Date.now()}${Math.floor(Math.random() * 1000)}`;
    const requireText = opts.requireText || '';
    const modal = openModal({
      title: opts.title || 'Подтверждение',
      subtitle: opts.subtitle || '',
      slim: true,
      body: `
        <div class="form-error" id="${id}err"></div>
        <p style="margin:0 0 12px;color:var(--muted);line-height:1.55">${opts.text || ''}</p>
        ${requireText ? `<div class="field"><label>Для подтверждения введите <code>${esc(requireText)}</code></label><input class="input mono" id="${id}input" autocomplete="off" /></div>` : ''}`,
      footer: `
        <button class="btn btn-ghost" id="${id}cancel" type="button">Отмена</button>
        <button class="btn ${opts.danger === false ? 'btn-primary' : 'btn-danger'}" id="${id}ok" type="button" ${requireText ? 'disabled' : ''}>${esc(opts.confirmLabel || 'Подтвердить')}</button>`,
      onClose: () => finish(false),
      onMount: ({ wrap, close }) => {
        const input = wrap.querySelector(`#${id}input`);
        const ok = wrap.querySelector(`#${id}ok`);
        if (input) {
          input.addEventListener('input', () => { ok.disabled = input.value.trim() !== requireText; });
          setTimeout(() => input.focus(), 30);
        }
        wrap.querySelector(`#${id}cancel`).addEventListener('click', () => { finish(false); close(); });
        ok.addEventListener('click', () => { finish(true); close(); });
      },
    });
    return modal;
  });
}

function promptSecret(opts) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => { if (!settled) { settled = true; resolve(value); } };
    const id = `ps${Date.now()}${Math.floor(Math.random() * 1000)}`;
    openModal({
      title: opts.title || 'Секрет',
      subtitle: opts.subtitle || '',
      slim: true,
      body: `
        <div class="form-error" id="${id}err"></div>
        <div class="field">
          <label>${esc(opts.label || 'Значение')}</label>
          <input class="input" id="${id}input" type="password" autocomplete="off" />
          ${opts.hint ? `<div class="hint">${esc(opts.hint)}</div>` : ''}
        </div>
        ${opts.saveLabel ? `<label class="check"><input type="checkbox" id="${id}save" /> ${esc(opts.saveLabel)}</label>` : ''}`,
      footer: `
        <button class="btn btn-ghost" id="${id}cancel" type="button">Отмена</button>
        <button class="btn btn-primary" id="${id}ok" type="button">Продолжить</button>`,
      onClose: () => finish(null),
      onMount: ({ wrap, close }) => {
        const input = wrap.querySelector(`#${id}input`);
        const err = wrap.querySelector(`#${id}err`);
        const submit = () => {
          const value = input.value;
          if (!value) {
            err.textContent = 'Значение не может быть пустым.';
            err.classList.add('visible');
            return;
          }
          const save = wrap.querySelector(`#${id}save`);
          finish({ value, save: save ? save.checked : false });
          close();
        };
        wrap.querySelector(`#${id}cancel`).addEventListener('click', () => { finish(null); close(); });
        wrap.querySelector(`#${id}ok`).addEventListener('click', submit);
        input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
        setTimeout(() => input.focus(), 30);
      },
    });
  });
}

function formModal(opts) {
  const id = `fm${Date.now()}${Math.floor(Math.random() * 1000)}`;
  const fields = opts.fields || [];
  const body = fields.map((f) => {
    if (f.type === 'static') return f.html || '';
    const val = f.value == null ? '' : f.value;
    let control = '';
    if (f.type === 'select') {
      control = `<select class="input" name="${esc(f.name)}" id="${id}_${esc(f.name)}">${(f.options || []).map((o) => `<option value="${esc(o.value)}" ${String(o.value) === String(val) ? 'selected' : ''}>${esc(o.label)}</option>`).join('')}</select>`;
    } else if (f.type === 'textarea') {
      control = `<textarea class="input" name="${esc(f.name)}" id="${id}_${esc(f.name)}" rows="${f.rows || 4}" placeholder="${esc(f.placeholder || '')}">${esc(val)}</textarea>`;
    } else if (f.type === 'checkbox') {
      return `<div class="field"><label class="check" style="font-size:12.5px"><input type="checkbox" name="${esc(f.name)}" id="${id}_${esc(f.name)}" ${f.checked ? 'checked' : ''} /> ${esc(f.label)}</label>${f.hint ? `<div class="hint">${esc(f.hint)}</div>` : ''}</div>`;
    } else {
      control = `<input class="input" name="${esc(f.name)}" id="${id}_${esc(f.name)}" type="${esc(f.type || 'text')}" value="${esc(val)}" placeholder="${esc(f.placeholder || '')}" ${f.autocomplete === false ? 'autocomplete="off"' : ''} />`;
    }
    return `<div class="field">
      <label for="${id}_${esc(f.name)}">${esc(f.label)}${f.required ? ' *' : ''}</label>
      ${control}
      ${f.hint ? `<div class="hint">${esc(f.hint)}</div>` : ''}
    </div>`;
  }).join('');

  return openModal({
    title: opts.title,
    subtitle: opts.subtitle,
    wide: opts.wide,
    body: `<div class="form-error" id="${id}err"></div>${body}`,
    footer: `<button class="btn btn-ghost" id="${id}cancel" type="button">Отмена</button><button class="btn ${opts.danger ? 'btn-danger' : 'btn-primary'}" id="${id}ok" type="button">${esc(opts.submitLabel || 'Выполнить')}</button>`,
    onMount: ({ wrap, close }) => {
      const err = wrap.querySelector(`#${id}err`);
      const ok = wrap.querySelector(`#${id}ok`);
      wrap.querySelector(`#${id}cancel`).addEventListener('click', close);
      const submit = async () => {
        const values = {};
        for (const f of fields) {
          if (f.type === 'static') continue;
          const el = wrap.querySelector(`[name="${f.name}"]`);
          if (!el) continue;
          values[f.name] = f.type === 'checkbox' ? el.checked : el.value.trim();
        }
        err.classList.remove('visible');
        ok.disabled = true;
        const old = ok.textContent;
        ok.innerHTML = '<span class="spinner"></span>';
        try {
          await opts.onSubmit(values, { wrap, close, err });
        } catch (e) {
          err.textContent = e.message || String(e);
          err.classList.add('visible');
        } finally {
          ok.disabled = false;
          ok.textContent = old;
        }
      };
      ok.addEventListener('click', submit);
      if (opts.onMount) opts.onMount({ wrap, close, id, fields });
    },
  });
}

/* ------------------------------------------------------------------ */
/* Rendering: profiles / connection                                    */
/* ------------------------------------------------------------------ */

function selectedProfile() {
  return state.profiles.find((p) => p.id === state.profileId) || null;
}

function renderProfiles() {
  const root = $('#profileList');
  if (!state.profiles.length) {
    root.innerHTML = `<div class="empty" style="padding:18px 8px"><strong>Нет профилей</strong>Добавьте сервер, чтобы начать.</div>`;
    return;
  }
  root.innerHTML = state.profiles.map((p) => {
    const online = Boolean(state.status && state.status.connected && state.status.profileId === p.id);
    return `
    <div class="profile-item ${p.id === state.profileId ? 'selected' : ''}" data-id="${esc(p.id)}">
      <div class="p-name"><span>${esc(p.name)}</span>${online ? '<span class="badge good">online</span>' : ''}</div>
      <div class="p-host">${esc(p.user)}@${esc(p.host)}:${esc(p.port)}</div>
      <div class="p-actions">
        <button class="btn btn-ghost btn-sm" data-act="${online ? 'disconnect' : 'connect'}" data-id="${esc(p.id)}" type="button">${online ? 'Отключить' : 'Подключить'}</button>
        <button class="btn btn-ghost btn-sm" data-act="edit" data-id="${esc(p.id)}" type="button">Изменить</button>
      </div>
    </div>`;
  }).join('');
}

function updateConnCard() {
  const st = state.status;
  const p = selectedProfile();
  const dot = $('#connDot');
  const title = $('#connTitle');
  const meta = $('#connMeta');
  const btn = $('#btnConnToggle');
  const chip = $('#serverChip');

  if (st && st.connected) {
    dot.className = 'dot dot-on';
    title.textContent = st.profileName || 'Подключено';
    const role = st.isRoot ? 'root' : (st.sudoReady ? 'sudo готов' : 'sudo не проверен');
    meta.textContent = `${st.user}@${st.host}:${st.port} · ${role}${st.server && st.server.os ? ` · ${st.server.os}` : ''}`;
    btn.textContent = 'Отключить';
    btn.classList.remove('btn-primary');
    btn.classList.add('btn-danger');
    chip.textContent = `${st.host}:${st.port}`;
    chip.classList.add('online');
  } else {
    dot.className = 'dot dot-off';
    title.textContent = 'Не подключено';
    meta.textContent = p ? `${p.user}@${p.host}:${p.port}` : 'Выберите профиль сервера';
    btn.textContent = 'Подключить';
    btn.classList.add('btn-primary');
    btn.classList.remove('btn-danger');
    chip.textContent = 'offline';
    chip.classList.remove('online');
  }
}

/* ------------------------------------------------------------------ */
/* Connection flow                                                     */
/* ------------------------------------------------------------------ */

async function connectSelected(secrets = {}, retried = false) {
  const p = selectedProfile();
  if (!p) { openProfileModal(); return; }

  if (p.authType === 'password' && !p.hasPassword && !secrets.password) {
    const r = await promptSecret({
      title: 'Пароль SSH',
      subtitle: `${p.user}@${p.host}:${p.port}`,
      label: 'Пароль SSH',
      saveLabel: 'Сохранить в профиле (шифруется Windows DPAPI)',
    });
    if (!r) return;
    secrets = { ...secrets, password: r.value };
    if (r.save) {
      try {
        await api.saveProfile({ ...p, password: r.value });
        await reloadProfiles();
      } catch (e) { toast(e.message, 'warn'); }
    }
  }

  if (state.status && state.status.connected) {
    try { await api.disconnect(); } catch (_) { /* ignore */ }
    state.status = null;
    updateConnCard();
  }

  showBusy(`Подключение к ${p.host}:${p.port}…`);
  let res;
  try {
    res = await api.connect(p.id, secrets);
  } finally {
    hideBusy();
  }

  if (!res.ok) {
    if (res.code === 'HOSTKEY_MISMATCH') {
      openHostKeyModal(res.hostKey);
      return;
    }
    const msg = res.message || 'Не удалось подключиться.';
    if (!retried && /passphrase|encrypted|decrypt/i.test(msg) && p.authType === 'key') {
      const r = await promptSecret({
        title: 'Пароль SSH-ключа',
        subtitle: 'Ключ зашифрован. Введите passphrase.',
        label: 'Passphrase',
        saveLabel: 'Сохранить в профиле',
      });
      if (r) {
        if (r.save) {
          try { await api.saveProfile({ ...p, passphrase: r.value }); await reloadProfiles(); } catch (_) { /* ignore */ }
        }
        return connectSelected({ ...secrets, passphrase: r.value }, true);
      }
    }
    toast(msg, 'error', 8000);
    return;
  }

  state.status = res.status;
  localStorage.setItem('awg.profileId', p.id);
  updateConnCard();
  renderProfiles();
  toast(`Подключено: ${p.name}`, 'success');

  if (!res.status.isRoot && !res.status.sudoReady) {
    if (p.authType === 'password' && p.sudoSameAsSsh && secrets.password) {
      try {
        const sr = await api.setSudoPassword(secrets.password);
        if (sr.ok) state.status = sr.status;
      } catch (_) { /* fall through to prompt */ }
    }
    if (!state.status.sudoReady) {
      openSudoModal();
      return;
    }
  }

  await refreshAll();
}

async function disconnectSession({ quiet = false } = {}) {
  try { await api.disconnect(); } catch (_) { /* ignore */ }
  state.status = null;
  state.check = null;
  state.clients = [];
  state.stats = [];
  state.server = null;
  state.serverReveal = false;
  state.maintenance = { logInfo: null, backups: [], selected: '', loaded: false, loading: false };
  updateConnCard();
  renderProfiles();
  renderOverview();
  renderClients();
  if (state.tab === 'maintenance') renderMaintenance();
  if (!quiet) toast('Соединение закрыто');
}

function openHostKeyModal(hk) {
  if (!hk) { toast('Отпечаток SSH-ключа не получен.', 'error'); return; }
  openModal({
    title: 'SSH-ключ сервера изменился',
    subtitle: `${hk.host}:${hk.port}`,
    slim: true,
    body: `
      <div class="form-error visible">Это может быть подмена сервера (MITM) или переустановка ОС. Не подтверждайте, если не уверены.</div>
      <div class="field"><label>Сохранённый отпечаток</label><div class="code-block wrap">${esc(hk.known || '—')}</div></div>
      <div class="field"><label>Новый отпечаток</label><div class="code-block wrap">${esc(hk.fingerprint)}</div></div>
      <div class="field"><label>Алгоритм</label><div class="mono">${esc(hk.algorithm || '—')}</div></div>`,
    footer: `<button class="btn btn-ghost" id="hkCancel" type="button">Отменить</button><button class="btn btn-danger" id="hkTrust" type="button">Доверять новому ключу</button>`,
    onMount: ({ wrap, close }) => {
      wrap.querySelector('#hkCancel').addEventListener('click', close);
      wrap.querySelector('#hkTrust').addEventListener('click', async () => {
        try {
          await api.trustHost({ host: hk.host, port: hk.port, fingerprint: hk.fingerprint, algorithm: hk.algorithm });
          close();
          connectSelected();
        } catch (e) {
          toast(e.message, 'error');
        }
      });
    },
  });
}

function openSudoModal() {
  openModal({
    title: 'Пароль sudo',
    subtitle: 'Пользователь не root. Для чтения конфигов и управления нужен sudo.',
    slim: true,
    body: `
      <div class="form-error" id="sudoErr"></div>
      <div class="field">
        <label>Пароль sudo</label>
        <input class="input" id="sudoPass" type="password" autocomplete="off" />
        <div class="hint">Пароль хранится только в памяти до отключения. В профиль он не записывается.</div>
      </div>`,
    footer: `<button class="btn btn-ghost" id="sudoSkip" type="button">Пропустить</button><button class="btn btn-primary" id="sudoOk" type="button">Применить</button>`,
    onMount: ({ wrap, close }) => {
      const input = wrap.querySelector('#sudoPass');
      const err = wrap.querySelector('#sudoErr');
      const submit = async () => {
        err.classList.remove('visible');
        try {
          const r = await api.setSudoPassword(input.value);
          if (!r.ok) throw new Error(r.message || 'sudo отклонил пароль.');
          state.status = r.status;
          updateConnCard();
          close();
          toast('sudo готов', 'success');
          await refreshAll();
        } catch (e) {
          err.textContent = e.message;
          err.classList.add('visible');
        }
      };
      wrap.querySelector('#sudoOk').addEventListener('click', submit);
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
      wrap.querySelector('#sudoSkip').addEventListener('click', () => {
        close();
        toast('sudo не настроен: команды управления могут не выполняться.', 'warn', 6000);
      });
      setTimeout(() => input.focus(), 30);
    },
  });
}

/* ------------------------------------------------------------------ */
/* Data refresh                                                        */
/* ------------------------------------------------------------------ */

function newRequestId() {
  if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
  return `r${Date.now()}${Math.floor(Math.random() * 100000)}`;
}

async function silentExec(action, params) {
  if (!state.status || !state.status.connected) return null;
  const rid = newRequestId();
  silentRequests.add(rid);
  const unregister = registerRun(rid, () => {});
  try {
    return await api.exec(action, params, rid);
  } catch (e) {
    return { ok: false, error: e.message };
  } finally {
    unregister();
    silentRequests.delete(rid);
  }
}

async function refreshCheck(manual = false) {
  if (!state.status || !state.status.connected) return null;
  const res = await silentExec('check', {});
  if (res && res.parsed) {
    state.check = res.parsed;
  } else if (manual && res) {
    toast(res.error || res.stderr || 'check не вернул JSON', 'error', 7000);
  }
  if (state.tab === 'overview') renderOverview();
  if (state.tab === 'server' && state.server) renderServer();
  return res;
}

async function refreshClients(manual = false) {
  if (!state.status || !state.status.connected) return null;
  const [listRes, statsRes] = await Promise.all([
    silentExec('list', { verbose: true }),
    silentExec('stats', {}),
  ]);
  if (listRes && Array.isArray(listRes.parsed)) state.clients = listRes.parsed;
  if (statsRes && Array.isArray(statsRes.parsed)) state.stats = statsRes.parsed;
  if (manual && (!listRes || !Array.isArray(listRes.parsed))) {
    toast(listRes && (listRes.error || listRes.stderr) || 'Не удалось получить список клиентов.', 'error', 7000);
  }
  renderClients();
  if (state.tab === 'overview') renderOverview();
  return { listRes, statsRes };
}

async function refreshAll(manual = false) {
  if (!state.status || !state.status.connected) {
    if (manual) toast('Сначала подключитесь к серверу.', 'warn');
    return;
  }
  showBusy('Обновление данных сервера…');
  try {
    await Promise.all([refreshCheck(manual), refreshClients(manual)]);
    if (state.tab === 'server' || state.server) await loadServer(state.serverReveal, true);
  } finally {
    hideBusy();
  }
  renderOverview();
  if (state.tab === 'maintenance') await loadMaintenance();
}

/* ------------------------------------------------------------------ */
/* Overview                                                            */
/* ------------------------------------------------------------------ */

function renderOverview() {
  const root = $('#overviewContent');
  if (!state.status || !state.status.connected) {
    root.innerHTML = `
      <div class="hero">
        <div class="hero-top">
          <div>
            <h2>AmneziaWG GUI</h2>
            <div class="host">Портативный пульт для сервера bivlked/amneziawg-installer</div>
          </div>
          <div class="hero-actions">
            <button class="btn btn-primary" id="ovCreateProfile" type="button">Создать профиль</button>
            <button class="btn btn-ghost" id="ovConnect" type="button" ${state.profiles.length ? '' : 'disabled'}>Подключиться</button>
          </div>
        </div>
        <div class="hero-meta">
          <div class="item"><div class="k">Управление</div><div class="v">add · remove · list · stats</div></div>
          <div class="item"><div class="k">Обслуживание</div><div class="v">check · backup · restore</div></div>
          <div class="item"><div class="k">Диагностика</div><div class="v">diagnose · show · логи</div></div>
          <div class="item"><div class="k">Импорт</div><div class="v">QR · .conf · vpn://</div></div>
        </div>
      </div>
      <div class="panel">
        <h3 class="panel-title">Как начать</h3>
        <div class="muted" style="line-height:1.7;font-size:12.8px">
          1. Создайте профиль: IP сервера, порт SSH, пользователь и приватный ключ.<br/>
          2. Нажмите «Подключиться». Пароль sudo запрашивается только если вы не root.<br/>
          3. Управляйте клиентами, смотрите QR-коды, конфиги и состояние сервера.<br/><br/>
          Профили хранятся в зашифрованном виде средствами Windows DPAPI в папке данных приложения.
        </div>
      </div>`;
    $('#ovCreateProfile')?.addEventListener('click', () => openProfileModal());
    $('#ovConnect')?.addEventListener('click', () => connectSelected());
    return;
  }

  if (!state.check) {
    root.innerHTML = `<div class="panel"><div class="empty"><span class="spinner"></span> Загрузка состояния сервера…</div></div>`;
    return;
  }

  const c = state.check;
  const st = state.status;
  const svc = c.service && c.service.active;
  const port = c.port || {};
  const fw = c.firewall || {};
  const moduleOk = c.module && c.module.loaded;
  const clientsTotal = (c.clients && c.clients.total) || state.clients.length || 0;
  const fp = st.hostKey ? st.hostKey.fingerprint : '';

  const rows = state.clients.slice(0, 6).map((cl) => {
    const stat = state.stats.find((s) => s.name === cl.name) || {};
    const [cls, label] = statusInfo(stat.status_code || cl.status_code, stat.status || cl.status);
    return `<tr>
      <td><div class="cell-name">${esc(cl.name)}</div><div class="cell-sub">${esc(cl.ip || '')}${cl.client_ipv6 ? ` · ${esc(cl.client_ipv6)}` : ''}</div></td>
      <td><span class="badge ${cls}">${esc(label)}</span></td>
      <td class="mono">${stat.rx != null ? `↓ ${fmtBytes(stat.rx)}` : '—'}</td>
      <td class="mono">${stat.tx != null ? `↑ ${fmtBytes(stat.tx)}` : '—'}</td>
    </tr>`;
  }).join('');

  const activity = state.appLog.slice(-8).reverse().map((l) => `
    <div class="log-row">
      <div class="log-time">${esc(new Date(l.ts || Date.now()).toLocaleTimeString('ru-RU'))}</div>
      <div class="log-level ${esc(l.level || 'info')}">${esc(l.level || 'info')}</div>
      <div class="log-text">${esc(l.text)}</div>
    </div>`).join('');

  root.innerHTML = `
    <div class="hero">
      <div class="hero-top">
        <div>
          <h2>${esc(st.profileName || 'Сервер')}</h2>
          <div class="host">${esc(st.user)}@${esc(st.host)}:${esc(st.port)}${st.server && st.server.os ? ` · ${esc(st.server.os)}` : ''}</div>
        </div>
        <div class="hero-actions">
          <button class="btn btn-primary" id="ovAddClient" type="button">+ Клиент</button>
          <button class="btn btn-ghost" id="ovBackup" type="button">Бэкап</button>
          <button class="btn btn-ghost" id="ovDiag" type="button">Диагностика</button>
        </div>
      </div>
      <div class="hero-meta">
        <div class="item"><div class="k">Доступ</div><div class="v">${st.isRoot ? 'root' : (st.sudoReady ? 'sudo готов' : 'sudo не проверен')}</div></div>
        <div class="item"><div class="k">Ядро</div><div class="v">${esc(st.server && st.server.kernel || '—')}</div></div>
        <div class="item"><div class="k">Поколение</div><div class="v">${esc(c.protocol || '—')}</div></div>
        <div class="item"><div class="k">SSH fingerprint</div><div class="v mono" style="font-size:11.5px" title="${esc(fp)}">${esc(shortFp(fp))}</div></div>
      </div>
    </div>

    <div class="stat-grid">
      <div class="stat-card ${svc ? 'good' : 'bad'}">
        <div class="label">Сервис</div>
        <div class="value">${svc ? 'active' : 'down'}</div>
        <div class="hint">awg-quick@awg0</div>
      </div>
      <div class="stat-card ${port.listening ? 'good' : 'warn'}">
        <div class="label">Порт</div>
        <div class="value">${port.number || '—'}/udp</div>
        <div class="hint">${port.listening ? 'слушает' : 'не подтверждён'}</div>
      </div>
      <div class="stat-card ${moduleOk ? 'good' : 'warn'}">
        <div class="label">Модуль ядра</div>
        <div class="value">${moduleOk ? 'loaded' : 'n/a'}</div>
        <div class="hint">${esc(c.module && c.module.version || 'userspace или нет модуля')}</div>
      </div>
      <div class="stat-card ${clientsTotal ? '' : 'warn'}">
        <div class="label">Клиенты</div>
        <div class="value">${clientsTotal}</div>
        <div class="hint">${fw.ufw_active ? 'UFW активен' : 'UFW не активен'}${fw.port_allowed ? ' · порт открыт' : ''}</div>
      </div>
    </div>

    <div class="grid-2">
      <div class="panel" style="padding:0;overflow:hidden">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:13px 15px;border-bottom:1px solid var(--border)">
          <div class="panel-title" style="margin:0">Клиенты <span class="sub">${state.clients.length}</span></div>
          <button class="btn btn-ghost btn-sm" id="ovAllClients" type="button">Все клиенты</button>
        </div>
        ${rows ? `<div class="table-scroll"><table><thead><tr><th>Клиент</th><th>Статус</th><th>Получено</th><th>Отправлено</th></tr></thead><tbody>${rows}</tbody></table></div>` : '<div class="empty">Клиентов пока нет.</div>'}
      </div>
      <div class="panel" style="padding:0;overflow:hidden">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:13px 15px;border-bottom:1px solid var(--border)">
          <div class="panel-title" style="margin:0">Активность</div>
          <button class="btn btn-ghost btn-sm" id="ovJournal" type="button">Журнал</button>
        </div>
        ${activity || '<div class="empty">Событий пока нет.</div>'}
      </div>
    </div>`;

  $('#ovAddClient')?.addEventListener('click', () => openAddClient());
  $('#ovBackup')?.addEventListener('click', () => runWithOutput({ action: 'backup', params: {}, title: 'Создание резервной копии' }));
  $('#ovDiag')?.addEventListener('click', () => { switchTab('diagnostics'); });
  $('#ovAllClients')?.addEventListener('click', () => switchTab('clients'));
  $('#ovJournal')?.addEventListener('click', () => switchTab('journal'));
}

/* ------------------------------------------------------------------ */
/* Clients                                                             */
/* ------------------------------------------------------------------ */

function mergedClients() {
  return state.clients.map((c) => ({
    ...c,
    stat: state.stats.find((s) => s.name === c.name) || null,
  }));
}

function renderClients() {
  const root = $('#clientsTableWrap');
  if (!state.status || !state.status.connected) {
    root.innerHTML = `<div class="empty">Подключитесь к серверу, чтобы увидеть клиентов.</div>`;
    return;
  }
  const q = ($('#clientSearch').value || '').trim().toLowerCase();
  const list = mergedClients().filter((c) => {
    if (!q) return true;
    return String(c.name).toLowerCase().includes(q) || String(c.ip || '').toLowerCase().includes(q);
  });

  if (!list.length) {
    root.innerHTML = `<div class="empty"><strong>${state.clients.length ? 'Ничего не найдено' : 'Клиентов пока нет'}</strong>${state.clients.length ? 'Измените поисковый запрос.' : 'Добавьте первого клиента — QR-код и конфиг создадутся автоматически.'}</div>`;
    return;
  }

  const rows = list.map((c) => {
    const st = c.stat || {};
    const [cls, label] = statusInfo(st.status_code || c.status_code, st.status || c.status);
    const exp = c.expires_at ? fmtUnix(c.expires_at) : (c.expires_at_error ? 'не читается' : 'бессрочно');
    const traffic = st.rx != null || st.tx != null
      ? `↓ ${fmtBytes(st.rx)} · ↑ ${fmtBytes(st.tx)}`
      : '—';
    const hs = st.last_handshake ? fmtUnix(st.last_handshake) : '—';
    return `<tr>
      <td>
        <div class="cell-name">${esc(c.name)}</div>
        <div class="cell-sub">${esc(c.ip || '—')}${c.client_ipv6 ? ` · ${esc(c.client_ipv6)}` : ''}</div>
      </td>
      <td><span class="badge ${cls}">${esc(label)}</span></td>
      <td>${esc(exp)}</td>
      <td class="mono" style="font-size:11.5px">${esc(traffic)}</td>
      <td class="mono" style="font-size:11.5px">${esc(hs)}</td>
      <td>
        <div class="row-actions">
          <button class="btn btn-ghost btn-sm" data-cact="qr" data-name="${esc(c.name)}" type="button">QR</button>
          <button class="btn btn-ghost btn-sm" data-cact="edit" data-name="${esc(c.name)}" type="button">Изменить</button>
          <button class="btn btn-ghost btn-sm" data-cact="regen" data-name="${esc(c.name)}" type="button">Regen</button>
          <button class="btn btn-danger btn-sm" data-cact="remove" data-name="${esc(c.name)}" type="button">Удалить</button>
        </div>
      </td>
    </tr>`;
  }).join('');

  root.innerHTML = `<div class="table-scroll"><table>
    <thead><tr><th>Клиент</th><th>Статус</th><th>Срок</th><th>Трафик</th><th>Handshake</th><th></th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

function openAddClient() {
  if (!requireConnection()) return;
  formModal({
    title: 'Новый клиент',
    subtitle: 'Имя — латиница, цифры, _ и -. Можно создать несколько через запятую.',
    fields: [
      { name: 'names', label: 'Имя клиента', placeholder: 'my_phone, my_laptop', required: true, hint: 'Несколько имён: через запятую или пробел. До 50 за раз.' },
      { name: 'expires', label: 'Срок действия', type: 'select', value: '', options: [
        { value: '', label: 'Бессрочно' },
        { value: '1h', label: '1 час' },
        { value: '12h', label: '12 часов' },
        { value: '1d', label: '1 день' },
        { value: '7d', label: '7 дней' },
        { value: '30d', label: '30 дней' },
        { value: '4w', label: '4 недели' },
      ] },
      { name: 'psk', label: 'PresharedKey (--psk)', type: 'checkbox', checked: false, hint: 'Дополнительный симметричный ключ. Нужен не всем клиентам.' },
      { name: 'allowedIps', label: 'Индивидуальные AllowedIPs', placeholder: '10.0.0.0/8, 192.168.0.0/16', hint: 'Пусто — глобальный режим маршрутизации сервера.' },
    ],
    submitLabel: 'Создать',
    onSubmit: async (values, { close }) => {
      parseClientNames(values.names);
      close();
      await runWithOutput({
        action: 'add',
        params: { names: values.names, expires: values.expires, psk: values.psk, allowedIps: values.allowedIps },
        title: 'Создание клиента',
        onDone: async (res) => { if (res.ok) await refreshClients(true); },
      });
    },
  });
}

function openEditClient(name) {
  if (!requireConnection()) return;
  formModal({
    title: `Изменить клиента ${name}`,
    subtitle: 'Параметр записывается в клиентский .conf; QR и vpn:// перегенерируются.',
    fields: [
      { name: 'param', label: 'Параметр', type: 'select', value: 'DNS', options: [
        { value: 'DNS', label: 'DNS' },
        { value: 'Endpoint', label: 'Endpoint' },
        { value: 'AllowedIPs', label: 'AllowedIPs' },
        { value: 'PersistentKeepalive', label: 'PersistentKeepalive' },
      ] },
      { name: 'value', label: 'Новое значение', placeholder: '8.8.8.8, 1.0.0.1', required: true },
    ],
    submitLabel: 'Изменить',
    onSubmit: async (values, { close }) => {
      close();
      await runWithOutput({
        action: 'modify',
        params: { name, param: values.param, value: values.value },
        title: `Изменение ${values.param} у ${name}`,
        onDone: async (res) => { if (res.ok) await refreshClients(true); },
      });
    },
  });
}

function openRemoveClient(name) {
  if (!requireConnection()) return;
  runWithOutput({
    action: 'remove',
    params: { names: name },
    title: `Удаление клиента ${name}`,
    confirm: {
      title: 'Удалить клиента?',
      text: `Клиент <b>${esc(name)}</b> будет удалён из серверного конфига, его ключи и файлы — удалены. Это действие нельзя отменить без резервной копии.`,
      requireText: name,
      confirmLabel: 'Удалить',
    },
    onDone: async (res) => { if (res.ok) await refreshClients(true); },
  });
}

function openRegenClient(name) {
  if (!requireConnection()) return;
  runWithOutput({
    action: 'regen',
    params: { names: name },
    title: `Перегенерация файлов ${name}`,
    onDone: async (res) => { if (res.ok) await refreshClients(true); },
  });
}

function openQr(name, initialTab = 'conf') {
  if (!requireConnection()) return;
  let currentTab = initialTab;
  let reveal = false;
  let art = null;

  const modal = openModal({
    title: `Клиент ${name}`,
    subtitle: 'QR-код, .conf и vpn:// для импорта в клиент.',
    wide: true,
    body: `
      <div class="qr-layout">
        <div>
          <div class="qr-box" id="qrBox"><div class="qr-empty"><span class="spinner"></span><br/>Чтение файлов…</div></div>
          <div class="qr-actions">
            <button class="btn btn-ghost btn-sm" id="qrDlPng" type="button" disabled>Скачать PNG</button>
            <button class="btn btn-ghost btn-sm" id="qrReveal" type="button">Показать секреты</button>
          </div>
        </div>
        <div class="qr-side">
          <div class="tabs-inline">
            <button type="button" data-qrtab="conf" class="active">Конфиг .conf</button>
            <button type="button" data-qrtab="uri">vpn:// для Amnezia VPN</button>
          </div>
          <div id="qrTextWrap"><pre class="code-block wrap conf-view" id="qrText">Загрузка…</pre></div>
          <div class="qr-actions">
            <button class="btn btn-ghost btn-sm" id="qrCopy" type="button">Копировать текст</button>
            <button class="btn btn-ghost btn-sm" id="qrDlConf" type="button">Скачать .conf</button>
            <button class="btn btn-ghost btn-sm" id="qrDlUri" type="button">Скачать .vpnuri</button>
            <button class="btn btn-primary btn-sm" id="qrDone" type="button">Готово</button>
          </div>
          <div class="qr-note">QR-код .conf импортируется в AmneziaWG / WG Tunnel. QR-код vpn:// — в Amnezia VPN. Файлы читаются с сервера; если PNG отсутствует, он строится локально из конфига.</div>
        </div>
      </div>`,
    onMount: ({ wrap, close }) => {
      const qrBox = wrap.querySelector('#qrBox');
      const text = wrap.querySelector('#qrText');
      const btnPng = wrap.querySelector('#qrDlPng');
      const btnConf = wrap.querySelector('#qrDlConf');
      const btnUri = wrap.querySelector('#qrDlUri');
      const btnCopy = wrap.querySelector('#qrCopy');
      const btnReveal = wrap.querySelector('#qrReveal');
      const done = wrap.querySelector('#qrDone');
      done.addEventListener('click', close);

      const paint = () => {
        if (!art || !art.ok) {
          qrBox.innerHTML = `<div class="qr-empty">${esc(art ? art.error : 'Не удалось прочитать данные клиента')}</div>`;
          text.textContent = art ? art.error : '';
          return;
        }
        const img = currentTab === 'conf' ? art.qrConf : art.qrUri;
        qrBox.innerHTML = img
          ? `<img src="${img}" alt="QR ${esc(name)}" />`
          : `<div class="qr-empty">QR-код для этого типа не создан.<br/>Попробуйте regen клиента.</div>`;
        if (currentTab === 'conf') {
          text.textContent = art.conf || 'Файл .conf не найден.';
          btnPng.disabled = !art.qrConf;
          btnConf.disabled = !art.files.conf;
          btnUri.disabled = !art.files.vpnuri;
        } else {
          text.textContent = art.vpnuriShown || 'Файл .vpnuri не найден.';
          btnPng.disabled = !art.qrUri;
          btnConf.disabled = !art.files.conf;
          btnUri.disabled = !art.files.vpnuri;
        }
        btnReveal.textContent = reveal ? 'Скрыть секреты' : 'Показать секреты';
      };

      const load = async (withReveal) => {
        reveal = withReveal;
        art = await api.artifacts(name, reveal);
        paint();
      };

      wrap.querySelectorAll('[data-qrtab]').forEach((b) => {
        b.addEventListener('click', () => {
          currentTab = b.dataset.qrtab;
          wrap.querySelectorAll('[data-qrtab]').forEach((x) => x.classList.toggle('active', x === b));
          paint();
        });
      });

      btnReveal.addEventListener('click', async () => {
        if (!reveal) {
          const ok = await confirmDialog({
            title: 'Показать приватные ключи?',
            text: 'В конфиге клиента содержатся <b>PrivateKey</b> и, возможно, <b>PresharedKey</b>. Убедитесь, что рядом нет посторонних.',
            confirmLabel: 'Показать',
          });
          if (!ok) return;
        }
        await load(!reveal);
      });

      btnPng.addEventListener('click', async () => {
        const r = await api.downloadClient(name, currentTab === 'conf' ? 'png' : 'vpnuriPng');
        if (r.ok) toast('Файл сохранён', 'success');
        else if (!r.canceled) toast(r.error, 'error');
      });
      btnConf.addEventListener('click', async () => {
        const r = await api.downloadClient(name, 'conf');
        if (r.ok) toast('Конфиг сохранён', 'success');
        else if (!r.canceled) toast(r.error, 'error');
      });
      btnUri.addEventListener('click', async () => {
        const r = await api.downloadClient(name, 'vpnuri');
        if (r.ok) toast('vpn:// сохранён', 'success');
        else if (!r.canceled) toast(r.error, 'error');
      });
      btnCopy.addEventListener('click', async () => {
        await api.copy(text.textContent || '');
        toast('Скопировано', 'success');
      });

      load(false);
    },
  });
  return modal;
}

/* ------------------------------------------------------------------ */
/* Server                                                              */
/* ------------------------------------------------------------------ */

function checkValue(check, path, fallback = '—') {
  let cur = check;
  for (const key of path.split('.')) {
    if (cur == null) return fallback;
    cur = cur[key];
  }
  return cur == null ? fallback : cur;
}

async function loadServer(reveal = false, quiet = false) {
  if (!state.status || !state.status.connected) return;
  if (!quiet) showBusy('Чтение настроек и состояния сервера…');
  try {
    const [res, logs, backups] = await Promise.all([
      api.serverSettings(reveal),
      api.logs().catch((e) => ({ ok: false, error: e.message })),
      api.backups().catch((e) => ({ ok: false, error: e.message })),
    ]);
    if (!res.ok) {
      if (!quiet) toast(res.error || 'Не удалось прочитать настройки', 'error', 8000);
      return;
    }
    state.server = res;
    state.serverReveal = reveal;
    state.logs = logs.ok ? logs.logs : [];
    state.backups = backups.ok ? backups.backups : [];
    if (state.logs.length && !state.selectedLog) state.selectedLog = state.logs[0].name;
    renderServer();
  } finally {
    if (!quiet) hideBusy();
  }
}

function renderServer() {
  const root = $('#serverContent');
  const s = state.server;
  if (!s) {
    root.innerHTML = `<div class="empty">Подключитесь к серверу, чтобы увидеть настройки.</div>`;
    return;
  }
  const c = s.check;
  if (!c) {
    root.innerHTML = `<div class="panel"><div class="form-error visible">${esc(s.checkError || 'check не вернул JSON')}</div><div class="muted">Команда check недоступна. Проверьте путь к manage_amneziawg.sh и sudo.</div></div>`;
    return;
  }

  const svc = c.service && c.service.active;
  const port = c.port || {};
  const fw = c.firewall || {};
  const mod = c.module || {};
  const iface = c.interface || {};
  const proto = c.protocol || '—';
  const addr = Array.isArray(iface.addresses) ? iface.addresses.join(', ') : '—';

  const logsOptions = state.logs.map((l) => `<option value="${esc(l.name)}" ${state.selectedLog === l.name ? 'selected' : ''}>${esc(l.name)} (${fmtBytes(l.size)})</option>`).join('');
  const backupsRows = state.backups.length ? state.backups.map((b) => `
    <tr>
      <td class="mono" style="font-size:11.5px">${esc(b.name)}</td>
      <td>${esc(b.date || '—')}</td>
      <td class="mono">${fmtBytes(b.size)}</td>
      <td><div class="row-actions"><button class="btn btn-danger btn-sm" data-srv="restore" data-file="${esc(b.name)}" type="button">Восстановить</button></div></td>
    </tr>`).join('') : '';

  root.innerHTML = `
    <div class="stat-grid">
      <div class="stat-card ${svc ? 'good' : 'bad'}"><div class="label">Сервис</div><div class="value">${svc ? 'active' : 'down'}</div><div class="hint">awg-quick@awg0</div></div>
      <div class="stat-card ${port.listening ? 'good' : 'warn'}"><div class="label">Порт</div><div class="value">${esc(port.number || '—')}/udp</div><div class="hint">${port.listening ? 'слушает' : 'не подтверждён'}</div></div>
      <div class="stat-card ${mod.loaded ? 'good' : 'warn'}"><div class="label">Модуль</div><div class="value">${mod.loaded ? 'loaded' : 'n/a'}</div><div class="hint">${esc(mod.version || '—')}</div></div>
      <div class="stat-card ${proto === '3.1' ? 'good' : ''}"><div class="label">Протокол</div><div class="value">${esc(proto)}</div><div class="hint">${esc(c.protocol_error || 'маркер установки')}</div></div>
    </div>

    <div class="panel">
      <h3 class="panel-title">Состояние <span class="sub">check --json</span></h3>
      <div class="kv-grid">
        <div class="kv"><div class="k">Интерфейс</div><div class="v">${esc(iface.name || 'awg0')} · ${iface.present ? 'present' : 'missing'}</div></div>
        <div class="kv"><div class="k">MTU</div><div class="v">${esc(iface.mtu || '—')}</div></div>
        <div class="kv"><div class="k">Адреса</div><div class="v mono" style="font-size:11.5px">${esc(addr)}</div></div>
        <div class="kv"><div class="k">Клиенты</div><div class="v">${esc(checkValue(c, 'clients.total'))}</div></div>
        <div class="kv"><div class="k">UFW</div><div class="v">${fw.ufw_active ? 'активен' : 'не активен'}${fw.port_allowed ? ' · порт открыт' : ''}</div></div>
        <div class="kv"><div class="k">Порт</div><div class="v mono">${esc(port.number || '—')}/${esc(port.proto || 'udp')} · ${port.listening ? 'listen' : 'unknown'}</div></div>
      </div>
    </div>

    <div class="section-block panel">
      <h3>awg0.conf <span class="right">
        <button class="btn btn-ghost btn-sm" data-srv="copy-conf" type="button">Копировать</button>
        <button class="btn btn-ghost btn-sm" data-srv="download-conf" type="button">Скачать</button>
        <button class="btn btn-ghost btn-sm" data-srv="reveal" type="button">${state.serverReveal ? 'Скрыть секреты' : 'Показать секреты'}</button>
      </span></h3>
      ${s.serverConfMasked ? '<div class="hint" style="margin-bottom:8px">PrivateKey / PresharedKey / HeaderProtectionKey скрыты. Для просмотра нажмите «Показать секреты».</div>' : '<div class="hint" style="margin-bottom:8px;color:var(--warn)">Секреты видны. Не оставляйте экран без присмотра.</div>'}
      <pre class="code-block wrap">${esc(s.serverConf || '')}</pre>
    </div>

    <div class="section-block panel">
      <h3>awgsetup_cfg.init <span class="right">
        <button class="btn btn-ghost btn-sm" data-srv="copy-init" type="button">Копировать</button>
        <button class="btn btn-ghost btn-sm" data-srv="download-init" type="button">Скачать</button>
      </span></h3>
      <pre class="code-block wrap">${esc(s.init || '')}</pre>
    </div>

    <div class="section-block panel">
      <h3>Система <span class="right"><button class="btn btn-ghost btn-sm" data-srv="refresh" type="button">Обновить</button></span></h3>
      <pre class="code-block wrap">${esc(s.snapshot || '')}</pre>
    </div>

    <div class="section-block grid-2">
      <div class="panel" style="padding:0;overflow:hidden;margin-top:0">
        <div style="padding:13px 15px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:10px">
          <div class="panel-title" style="margin:0">Журналы <span class="sub">${state.logs.length}</span></div>
          <div style="display:flex;gap:6px">
            <select class="input" id="serverLogSelect" style="width:190px;padding:5px 9px;font-size:11.5px">${logsOptions || '<option value="">нет .log</option>'}</select>
            <button class="btn btn-ghost btn-sm" data-srv="tail-log" type="button">Показать</button>
          </div>
        </div>
        <pre class="code-block" id="serverLogOutput" style="border:0;border-radius:0;max-height:300px;min-height:160px;margin:0">${esc(state.serverLogText || 'Выберите журнал и нажмите «Показать».')}</pre>
      </div>

      <div class="panel" style="padding:0;overflow:hidden;margin-top:0">
        <div style="padding:13px 15px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:10px">
          <div class="panel-title" style="margin:0">Резервные копии <span class="sub">${state.backups.length}</span></div>
          <button class="btn btn-ghost btn-sm" data-srv="backup" type="button">Создать</button>
        </div>
        ${backupsRows ? `<div class="table-scroll"><table><thead><tr><th>Файл</th><th>Дата</th><th>Размер</th><th></th></tr></thead><tbody>${backupsRows}</tbody></table></div>` : '<div class="empty">Резервных копий нет.</div>'}
      </div>
    </div>`;
}

function onServerClick(e) {
  const btn = e.target.closest('[data-srv]');
  if (!btn) return;
  const act = btn.dataset.srv;
  const s = state.server;
  if (!s) return;

  if (act === 'refresh') { loadServer(state.serverReveal); return; }
  if (act === 'reveal') {
    const next = !state.serverReveal;
    if (next) {
      confirmDialog({
        title: 'Показать секреты сервера?',
        text: 'В awg0.conf содержатся <b>PrivateKey</b>, <b>PresharedKey</b> и <b>HeaderProtectionKey</b>. Они будут показаны на экране и доступны для копирования.',
        confirmLabel: 'Показать',
      }).then((ok) => { if (ok) loadServer(true); });
    } else {
      loadServer(false);
    }
    return;
  }
  if (act === 'copy-conf') {
    api.copy(s.serverConf || '').then(() => toast('Конфиг скопирован', 'success'));
    return;
  }
  if (act === 'download-conf') {
    if (!state.serverReveal) {
      toast('Сначала нажмите «Показать секреты»: иначе будет скачан конфиг со скрытыми ключами.', 'warn', 6000);
      return;
    }
    api.saveFile({ text: s.serverConf || '', defaultName: 'awg0.conf', filters: [{ name: 'Config', extensions: ['conf'] }] })
      .then((r) => { if (r.ok) toast('Файл сохранён', 'success'); else if (r.error) toast(r.error, 'error'); });
    return;
  }
  if (act === 'copy-init') {
    api.copy(s.init || '').then(() => toast('awgsetup_cfg.init скопирован', 'success'));
    return;
  }
  if (act === 'download-init') {
    api.saveFile({ text: s.init || '', defaultName: 'awgsetup_cfg.init', filters: [{ name: 'Config', extensions: ['init', 'conf', 'txt'] }] })
      .then((r) => { if (r.ok) toast('Файл сохранён', 'success'); else if (r.error) toast(r.error, 'error'); });
    return;
  }
  if (act === 'tail-log') {
    const sel = $('#serverLogSelect');
    const name = sel ? sel.value : '';
    if (!name) return;
    state.selectedLog = name;
    api.tailLog(name, 300).then((r) => {
      if (!r.ok) { toast(r.error, 'error'); return; }
      state.serverLogText = r.text;
      const pre = $('#serverLogOutput');
      if (pre) pre.textContent = r.text;
    });
    return;
  }
  if (act === 'backup') {
    runWithOutput({
      action: 'backup',
      params: {},
      title: 'Создание резервной копии',
      onDone: async (res) => { if (res.ok) await loadServer(state.serverReveal, true); },
    });
    return;
  }
  if (act === 'restore') {
    const file = btn.dataset.file;
    runWithOutput({
      action: 'restore',
      params: { file },
      title: `Восстановление из ${file}`,
      confirm: {
        title: 'Восстановить из бэкапа?',
        text: `Конфиги и ключи будут заменены данными из <b>${esc(file)}</b>. Текущее состояние сохранится в автоматический бэкап, но клиенты могут потребовать перевыпуска.`,
        requireText: 'RESTORE',
        confirmLabel: 'Восстановить',
      },
      onDone: async (res) => {
        if (res.ok) {
          await refreshClients(true);
          await loadServer(state.serverReveal, true);
        }
      },
    });
  }
}

/* ------------------------------------------------------------------ */
/* Diagnostics                                                         */
/* ------------------------------------------------------------------ */

function appendDiag(text) {
  const pre = $('#diagOutput');
  if (!pre) return;
  pre.textContent += text;
  if (pre.textContent.length > 500000) pre.textContent = pre.textContent.slice(-400000);
  pre.scrollTop = pre.scrollHeight;
}

async function runDiag(action, params, label) {
  if (!requireConnection()) return;
  if (state.diagRunning) return;
  state.diagRunning = true;
  $('#diagStatus').textContent = `${label}: выполняется…`;
  $('#diagMeta').textContent = '';
  $('#diagOutput').textContent = '';
  const rid = newRequestId();
  const started = Date.now();
  let finished = false;
  let streamedText = '';
  const onChunk = (chunk) => {
    if (finished) return;
    streamedText += chunk;
    appendDiag(chunk);
  };
  const unregister = registerRun(rid, onChunk);
  try {
    const pv = await api.preview(action, params);
    if (!pv.ok) throw new Error(pv.error);
    appendDiag(`$ ${pv.command}\n\n`);
    const res = await api.exec(action, params, rid);
    finished = true;
    if (res.error) appendDiag(`\n${res.error}\n`);
    if (res.parsed) {
      $('#diagOutput').textContent = `${JSON.stringify(res.parsed, null, 2)}\n`;
    } else {
      const full = `${res.stdout || ''}${res.stderr ? `\n${res.stderr}` : ''}`;
      if (full.startsWith(streamedText)) {
        const missing = full.slice(streamedText.length);
        if (missing) appendDiag(missing);
      } else if (!res.ok && res.stderr && !streamedText.includes(res.stderr.slice(0, 80))) {
        appendDiag(`\n${res.stderr}`);
      }
    }
    $('#diagStatus').textContent = res.ok ? 'Готово' : `Ошибка (код ${res.code})`;
    $('#diagMeta').textContent = `${fmtDuration(res.duration || (Date.now() - started))}`;
  } catch (e) {
    appendDiag(`\n${e.message}\n`);
    $('#diagStatus').textContent = 'Ошибка';
  } finally {
    finished = true;
    unregister();
    state.diagRunning = false;
  }
}

/* ------------------------------------------------------------------ */
/* Command forms                                                       */
/* ------------------------------------------------------------------ */

function openCommandForm(id) {
  if (!requireConnection()) return;
  switch (id) {
    case 'add': openAddClient(); return;
    case 'remove':
      formModal({
        title: 'Удалить клиентов',
        subtitle: 'Имена через запятую или пробел.',
        fields: [{ name: 'names', label: 'Имена клиентов', placeholder: 'guest, old_phone', required: true }],
        submitLabel: 'Удалить',
        danger: true,
        onSubmit: async (values, { close }) => {
          parseClientNames(values.names);
          close();
          await runWithOutput({
            action: 'remove',
            params: { names: values.names },
            title: 'Удаление клиентов',
            confirm: { title: 'Удалить клиентов?', text: `Будут удалены: <b>${esc(values.names)}</b>. Действие необратимо без бэкапа.`, requireText: 'УДАЛИТЬ', confirmLabel: 'Удалить' },
            onDone: async (res) => { if (res.ok) await refreshClients(true); },
          });
        },
      });
      return;
    case 'regen':
      formModal({
        title: 'Перегенерация файлов',
        subtitle: 'Пустое поле — все клиенты.',
        fields: [
          { name: 'names', label: 'Имена клиентов', placeholder: 'оставьте пустым для всех' },
          { name: 'resetRoutes', label: 'Сбросить AllowedIPs на глобальный режим (--reset-routes)', type: 'checkbox', checked: false, hint: 'Используйте после смены режима маршрутизации переустановкой.' },
        ],
        submitLabel: 'Перегенерировать',
        onSubmit: async (values, { close }) => {
          parseClientNames(values.names, { optional: true });
          close();
          await runWithOutput({
            action: 'regen',
            params: { names: values.names, resetRoutes: values.resetRoutes },
            title: values.names ? `Перегенерация ${values.names}` : 'Перегенерация всех клиентов',
            onDone: async (res) => { if (res.ok) await refreshClients(true); },
          });
        },
      });
      return;
    case 'modify':
      formModal({
        title: 'Изменить параметр клиента',
        fields: [
          { name: 'name', label: 'Клиент', placeholder: 'my_phone', required: true },
          { name: 'param', label: 'Параметр', type: 'select', value: 'DNS', options: [
            { value: 'DNS', label: 'DNS' },
            { value: 'Endpoint', label: 'Endpoint' },
            { value: 'AllowedIPs', label: 'AllowedIPs' },
            { value: 'PersistentKeepalive', label: 'PersistentKeepalive' },
          ] },
          { name: 'value', label: 'Значение', required: true },
        ],
        submitLabel: 'Изменить',
        onSubmit: async (values, { close }) => {
          close();
          await runWithOutput({
            action: 'modify',
            params: values,
            title: `modify ${values.name} ${values.param}`,
            onDone: async (res) => { if (res.ok) await refreshClients(true); },
          });
        },
      });
      return;
    case 'diagnose':
      formModal({
        title: 'Диагностика',
        subtitle: 'Без оператора — базовые проверки. С оператором — сравнение параметров обфускации.',
        fields: [
          { name: 'carrier', label: 'Профиль оператора', type: 'select', value: '', options: [{ value: '', label: 'Без сравнения' }, ...CARRIERS.map(([v, l]) => ({ value: v, label: l }))] },
        ],
        submitLabel: 'Запустить',
        onSubmit: async (values, { close }) => {
          close();
          switchTab('diagnostics');
          $('#carrierSelect').value = values.carrier;
          await runDiag('diagnose', { carrier: values.carrier }, 'diagnose');
        },
      });
      return;
    case 'restore': openRestoreForm(); return;
    case 'raw': switchTab('console'); return;
    default: {
      const meta = COMMANDS.find((c) => c.id === id);
      const danger = meta && meta.danger;
      runWithOutput({
        action: id,
        params: {},
        title: meta ? meta.title : id,
        confirm: danger ? {
          title: meta.title,
          text: `Команда <code>${esc(meta.cmd)}</code> изменит состояние сервера. Продолжить?`,
          requireText: 'ПОДТВЕРЖДАЮ',
          confirmLabel: 'Выполнить',
        } : null,
        onDone: async (res) => {
          if (!res.ok) return;
          if (id === 'check') state.check = res.parsed || state.check;
          if (['restart', 'repair-module'].includes(id)) await refreshCheck(true);
          if (['backup', 'restore'].includes(id)) await loadServer(state.serverReveal, true);
        },
      });
    }
  }
}

async function openRestoreForm() {
  showBusy('Чтение списка бэкапов…');
  let backups = [];
  try {
    const r = await api.backups();
    if (r.ok) backups = r.backups;
  } finally {
    hideBusy();
  }
  if (!backups.length) {
    toast('Резервных копий нет. Сначала создайте бэкап.', 'warn', 6000);
    return;
  }
  formModal({
    title: 'Восстановление из бэкапа',
    subtitle: 'Текущие конфиги и ключи будут заменены. Перед восстановлением создаётся автоматический бэкап.',
    fields: [
      { name: 'file', label: 'Файл', type: 'select', value: backups[0].name, options: backups.map((b) => ({ value: b.name, label: `${b.name} · ${b.date || ''} · ${fmtBytes(b.size)}` })) },
    ],
    submitLabel: 'Восстановить',
    danger: true,
    onSubmit: async (values, { close }) => {
      close();
      await runWithOutput({
        action: 'restore',
        params: { file: values.file },
        title: `Восстановление из ${values.file}`,
        confirm: {
          title: 'Восстановить из бэкапа?',
          text: `Конфиги и ключи будут заменены данными из <b>${esc(values.file)}</b>.`,
          requireText: 'RESTORE',
          confirmLabel: 'Восстановить',
        },
        onDone: async (res) => {
          if (res.ok) {
            await refreshClients(true);
            await loadServer(state.serverReveal, true);
          }
        },
      });
    },
  });
}

/* ------------------------------------------------------------------ */
/* Run with output modal                                               */
/* ------------------------------------------------------------------ */

const activeRuns = new Map();
const silentRequests = new Set();
function registerRun(requestId, handler) {
  activeRuns.set(requestId, handler);
  return () => activeRuns.delete(requestId);
}

function humanSummary(parsed) {
  if (Array.isArray(parsed)) return `Получено записей: ${parsed.length}`;
  if (!parsed || typeof parsed !== 'object') return '';
  if (parsed.command === 'add') return `Создано: ${parsed.added || 0}, ошибок: ${parsed.failed || 0}${parsed.applied ? ', применено' : ''}`;
  if (parsed.command === 'remove') return `Удалено: ${parsed.removed || 0}, ошибок: ${parsed.failed || 0}`;
  if (parsed.command === 'regen') return `Перегенерировано: ${parsed.regenerated || 0}, ошибок: ${parsed.failed || 0}`;
  if (parsed.command === 'backup') return `Бэкап: ${parsed.path || '—'} (${fmtBytes(parsed.size_bytes)})`;
  if (parsed.command === 'restore') return `Восстановлено клиентов: ${(parsed.restored && parsed.restored.clients) || 0}`;
  if (parsed.command === 'check') return `Сервис: ${parsed.service && parsed.service.active ? 'active' : 'down'} · порт: ${parsed.port && parsed.port.number} · протокол: ${parsed.protocol || '—'}`;
  if (parsed.command === 'restart') return `Сервис: ${parsed.active ? 'active' : 'не активен'}`;
  if (parsed.command === 'repair-module') return `Модуль: ${parsed.module_loaded ? 'loaded' : 'нет'} · сервис: ${parsed.service_active ? 'active' : 'down'}`;
  if (parsed.ok === false) return parsed.error || 'Команда завершилась с ошибкой';
  return parsed.ok === true ? 'Успешно' : '';
}

async function runWithOutput(opts) {
  if (!requireConnection()) return null;
  const pv = await api.preview(opts.action, opts.params || {});
  if (!pv.ok) {
    toast(pv.error, 'error', 7000);
    return null;
  }

  if (opts.confirm) {
    const ok = await confirmDialog(opts.confirm);
    if (!ok) return null;
  }

  const rid = newRequestId();
  const id = `run${Date.now()}${Math.floor(Math.random() * 1000)}`;
  let closed = false;
  const modal = openModal({
    title: opts.title || 'Выполнение команды',
    subtitle: 'Вывод команды в реальном времени.',
    wide: true,
    dismissible: false,
    body: `
      <div class="field">
        <label>Команда</label>
        <pre class="code-block wrap" style="max-height:120px">${esc(pv.command)}</pre>
      </div>
      <div id="${id}summary"></div>
      <div class="output-panel" style="margin-top:0">
        <div class="output-head"><span id="${id}status"><span class="spinner"></span> Выполняется…</span><span class="mono" id="${id}meta"></span></div>
        <pre class="terminal tall" id="${id}out"></pre>
      </div>`,
    footer: `<button class="btn btn-ghost" id="${id}copy" type="button">Копировать вывод</button><button class="btn btn-primary" id="${id}close" type="button" disabled>Закрыть</button>`,
    onClose: () => { closed = true; },
    onMount: ({ wrap, close }) => {
      wrap.querySelector(`#${id}copy`).addEventListener('click', async () => {
        await api.copy(wrap.querySelector(`#${id}out`).textContent || '');
        toast('Вывод скопирован', 'success');
      });
      wrap.querySelector(`#${id}close`).addEventListener('click', close);
      wrap.__runClose = close;
    },
  });

  const out = modal.wrap.querySelector(`#${id}out`);
  const status = modal.wrap.querySelector(`#${id}status`);
  const meta = modal.wrap.querySelector(`#${id}meta`);
  const summary = modal.wrap.querySelector(`#${id}summary`);
  const closeBtn = modal.wrap.querySelector(`#${id}close`);
  let streamed = false;
  let finished = false;
  const onChunk = (chunk) => {
    if (closed || finished) return;
    streamed = true;
    out.textContent += chunk;
    if (out.textContent.length > 800000) out.textContent = out.textContent.slice(-600000);
    out.scrollTop = out.scrollHeight;
  };
  const unregister = registerRun(rid, onChunk);
  const started = Date.now();

  try {
    const res = await api.exec(opts.action, opts.params || {}, rid);
    finished = true;
    if (!closed) {
      const full = `${res.stdout || ''}${res.stderr ? `\n${res.stderr}` : ''}`;
      if (!streamed) {
        out.textContent = full;
      } else if (full.startsWith(out.textContent)) {
        const missing = full.slice(out.textContent.length);
        if (missing) out.textContent += missing;
      } else if (res.stderr && !out.textContent.includes(res.stderr.slice(0, 80))) {
        out.textContent += `\n${res.stderr}`;
      }
      if (res.error) out.textContent += `\n${res.error}`;
      out.scrollTop = out.scrollHeight;

      const ok = Boolean(res.ok);
      status.innerHTML = ok
        ? `<span style="color:var(--accent)">Готово</span> · код ${res.code}`
        : `<span style="color:var(--danger)">Ошибка</span> · код ${res.code}`;
      meta.textContent = fmtDuration(res.duration || (Date.now() - started));

      const human = humanSummary(res.parsed);
      if (human || res.parsed) {
        summary.innerHTML = `
          ${human ? `<div class="badge ${ok ? 'good' : 'bad'}" style="margin-bottom:10px">${esc(human)}</div>` : ''}
          ${res.parsed ? `<details><summary style="cursor:pointer;color:var(--muted);font-size:12px;margin-bottom:7px">JSON-ответ</summary><pre class="code-block wrap" style="max-height:260px">${esc(JSON.stringify(res.parsed, null, 2))}</pre></details>` : ''}`;
      }
      closeBtn.disabled = false;
      if (opts.onDone) await opts.onDone(res);
    }
    return res;
  } catch (e) {
    if (!closed) {
      out.textContent += `\n${e.message}`;
      status.innerHTML = `<span style="color:var(--danger)">Ошибка</span>`;
      closeBtn.disabled = false;
    }
    return { ok: false, error: e.message };
  } finally {
    finished = true;
    unregister();
  }
}

/* ------------------------------------------------------------------ */
/* Command cards / console                                             */
/* ------------------------------------------------------------------ */

function renderCommandCards() {
  const root = $('#commandCards');
  root.innerHTML = COMMANDS.map((c) => `
    <div class="command-card ${c.danger ? 'danger' : ''}" data-cmd="${esc(c.id)}">
      <div class="cmd-top"><span class="cmd-name">${esc(c.title)}</span><span class="cmd-code">${esc(c.cmd)}</span></div>
      <div class="cmd-desc">${esc(c.desc)}</div>
    </div>`).join('');
}

function appendConsole(text) {
  state.consoleBuffer += text;
  if (state.consoleBuffer.length > 400000) state.consoleBuffer = state.consoleBuffer.slice(-300000);
  if (state.tab === 'console') {
    const pre = $('#consoleOutput');
    if (pre) {
      pre.textContent = state.consoleBuffer;
      pre.scrollTop = pre.scrollHeight;
    }
  }
}

async function runConsole() {
  if (!requireConnection()) return;
  const input = $('#consoleInput');
  const cmd = input.value.trim();
  if (!cmd) return;
  if (cmd === 'clear') { state.consoleBuffer = ''; $('#consoleOutput').textContent = ''; input.value = ''; return; }
  state.consoleHistory.push(cmd);
  if (state.consoleHistory.length > 100) state.consoleHistory.shift();
  state.consoleIndex = state.consoleHistory.length;
  input.value = '';
  const rid = newRequestId();
  const unregister = registerRun(rid, (chunk) => appendConsole(chunk));
  try {
    const res = await api.exec('raw', { command: cmd, useSudo: $('#consoleSudo').checked }, rid);
    if (res.error) appendConsole(`${res.error}\n`);
    appendConsole(`\n[код ${res.code}, ${fmtDuration(res.duration)}]\n`);
  } catch (e) {
    appendConsole(`${e.message}\n`);
  } finally {
    unregister();
  }
}

/* ------------------------------------------------------------------ */
/* Journal / settings / profile modal                                  */
/* ------------------------------------------------------------------ */

function renderJournal() {
  const root = $('#journalList');
  const items = state.appLog.slice().reverse();
  if (!items.length) {
    root.innerHTML = '<div class="empty">Событий пока нет.</div>';
    return;
  }
  root.innerHTML = items.map((l) => `
    <div class="log-row">
      <div class="log-time">${esc(new Date(l.ts || Date.now()).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'medium' }))}</div>
      <div class="log-level ${esc(l.level || 'info')}">${esc(l.level || 'info')}</div>
      <div class="log-text">${esc(l.text)}</div>
    </div>`).join('');
}

async function openSettings() {
  const info = await api.info();
  const hosts = await api.listKnownHosts();
  const hostRows = hosts.length ? hosts.map((h) => `
    <tr>
      <td class="mono" style="font-size:11.5px">${esc(h.key)}</td>
      <td class="mono" style="font-size:10.8px;overflow-wrap:anywhere">${esc(h.fingerprint)}</td>
      <td><button class="btn btn-ghost btn-sm" data-forget="${esc(h.key)}" type="button">Забыть</button></td>
    </tr>`).join('') : '';

  openModal({
    title: 'Настройки и безопасность',
    wide: true,
    body: `
      <div class="section-block">
        <h3>Приложение</h3>
        <div class="kv-grid">
          <div class="kv"><div class="k">Версия</div><div class="v">${esc(info.version)}</div></div>
          <div class="kv"><div class="k">Electron / Node</div><div class="v mono" style="font-size:11.5px">${esc(info.electron)} / ${esc(info.node)}</div></div>
          <div class="kv"><div class="k">Профили</div><div class="v">${info.encryptedProfiles ? 'зашифрованы DPAPI' : 'без шифрования'}</div></div>
          <div class="kv"><div class="k">Папка данных</div><div class="v mono" style="font-size:11px">${esc(info.dataDir)}</div></div>
        </div>
        <div class="qr-actions" style="margin-top:10px">
          <button class="btn btn-ghost btn-sm" id="setOpenData" type="button">Открыть папку данных</button>
        </div>
      </div>
      <div class="section-block">
        <h3>Доверенные SSH-ключи <span class="sub">${hosts.length}</span></h3>
        ${hostRows ? `<div class="table-scroll"><table><thead><tr><th>Сервер</th><th>SHA256 fingerprint</th><th></th></tr></thead><tbody>${hostRows}</tbody></table></div>` : '<div class="empty">Пока нет сохранённых отпечатков.</div>'}
        <div class="hint" style="margin-top:8px">При первом подключении отпечаток сохраняется (TOFU). Если он изменился, приложение блокирует подключение до подтверждения.</div>
      </div>
      <div class="section-block">
        <h3>Безопасность</h3>
        <div class="muted" style="font-size:12.3px;line-height:1.65">
          • Приватные ключи и пароли профилей шифруются средствами Windows DPAPI и привязаны к учётной записи Windows.<br/>
          • Пароль sudo хранится только в памяти до отключения.<br/>
          • Приватные ключи клиентов показываются только после подтверждения.<br/>
          • Журнал приложения не содержит приватных ключей и паролей.
        </div>
      </div>`,
    footer: `<button class="btn btn-primary" id="setClose" type="button">Закрыть</button>`,
    onMount: ({ wrap, close }) => {
      wrap.querySelector('#setClose').addEventListener('click', close);
      wrap.querySelector('#setOpenData').addEventListener('click', () => api.openDataDir());
      wrap.querySelectorAll('[data-forget]').forEach((b) => {
        b.addEventListener('click', async () => {
          const key = b.dataset.forget;
          const [host, port] = key.split(':');
          const ok = await confirmDialog({ title: 'Забыть отпечаток?', text: `При следующем подключении к <b>${esc(key)}</b> ключ будет принят заново.`, confirmLabel: 'Забыть' });
          if (!ok) return;
          await api.forgetHost({ host, port: Number(port) || 22 });
          b.closest('tr').remove();
          toast('Отпечаток удалён', 'success');
        });
      });
    },
  });
}

function openProfileModal(profile = null) {
  const p = profile || null;
  const isEdit = Boolean(p);
  const id = `pf${Date.now()}`;
  const auth = p ? p.authType : 'key';

  openModal({
    title: isEdit ? `Профиль: ${p.name}` : 'Новый профиль сервера',
    subtitle: 'SSH-доступ к серверу с amneziawg-installer.',
    wide: true,
    body: `
      <div class="form-error" id="${id}err"></div>
      <div class="field-row-3">
        <div class="field"><label>Название</label><input class="input" id="${id}name" value="${esc(p ? p.name : '')}" placeholder="Мой VPS" /></div>
        <div class="field"><label>IP / host</label><input class="input mono" id="${id}host" value="${esc(p ? p.host : '')}" /></div>
        <div class="field"><label>Порт SSH</label><input class="input mono" id="${id}port" type="number" min="1" max="65535" value="${esc(p ? p.port : 22)}" /></div>
      </div>
      <div class="field-row">
        <div class="field"><label>Пользователь</label><input class="input mono" id="${id}user" value="${esc(p ? p.user : 'root')}" placeholder="root" /></div>
        <div class="field"><label>Аутентификация</label>
          <select class="input" id="${id}auth">
            <option value="key" ${auth === 'key' ? 'selected' : ''}>Приватный ключ</option>
            <option value="password" ${auth === 'password' ? 'selected' : ''}>Пароль</option>
          </select>
        </div>
      </div>

      <div id="${id}keyBlock">
        <div class="field">
          <label>Файл приватного ключа</label>
          <div class="input-with-btn">
            <input class="input mono" id="${id}keyPath" value="${esc(p ? p.keyPath : '')}" placeholder="C:\\Users\\...\\id_ed25519" />
            <button class="btn btn-ghost" id="${id}browse" type="button">Выбрать…</button>
          </div>
          <div class="hint">OpenSSH / PEM. PuTTY .ppk не поддерживается — конвертируйте в PuTTYgen (Conversions → Export OpenSSH key).</div>
        </div>
        <div class="field">
          <label>Или вставить ключ</label>
          <textarea class="input" id="${id}privateKey" rows="4" placeholder="${p && p.hasPrivateKey ? 'Ключ уже сохранён. Оставьте пустым, чтобы не менять.' : '-----BEGIN OPENSSH PRIVATE KEY-----'}"></textarea>
          <div class="hint">${p && p.hasPrivateKey ? 'Сохранённый ключ не показывается. Вставьте новый, чтобы заменить.' : 'Ключ будет сохранён в зашифрованном профиле.'}</div>
        </div>
        <div class="field">
          <label>Passphrase ключа</label>
          <input class="input" id="${id}passphrase" type="password" autocomplete="off" placeholder="${p && p.hasPassphrase ? 'сохранён, оставьте пустым' : 'если ключ зашифрован'}" />
        </div>
      </div>

      <div id="${id}pwBlock" class="${auth === 'password' ? '' : 'hidden'}">
        <div class="field">
          <label>Пароль SSH</label>
          <input class="input" id="${id}password" type="password" autocomplete="off" placeholder="${p && p.hasPassword ? 'сохранён, оставьте пустым' : ''}" />
          <div class="hint">Сохраняется в зашифрованном профиле (DPAPI).</div>
        </div>
        <label class="check"><input type="checkbox" id="${id}sudoSame" ${p && p.sudoSameAsSsh === false ? '' : 'checked'} /> использовать этот пароль для sudo (если пользователь не root)</label>
      </div>

      <details style="margin-top:14px">
        <summary style="cursor:pointer;color:var(--muted);font-size:12px">Дополнительно</summary>
        <div class="field" style="margin-top:12px"><label>Путь к manage_amneziawg.sh</label><input class="input mono" id="${id}managePath" value="${esc(p ? p.managePath : '/root/awg/manage_amneziawg.sh')}" /></div>
        <div class="field"><label>Каталог AWG</label><input class="input mono" id="${id}awgDir" value="${esc(p ? p.awgDir : '/root/awg')}" /></div>
      </details>`,
    footer: `
      ${isEdit ? `<button class="btn btn-danger" id="${id}delete" type="button" style="margin-right:auto">Удалить профиль</button>` : ''}
      <button class="btn btn-ghost" id="${id}cancel" type="button">Отмена</button>
      <button class="btn btn-ghost" id="${id}save" type="button">Сохранить</button>
      <button class="btn btn-primary" id="${id}saveConnect" type="button">Сохранить и подключиться</button>`,
    onMount: ({ wrap, close }) => {
      const err = wrap.querySelector(`#${id}err`);
      const authSel = wrap.querySelector(`#${id}auth`);
      const keyBlock = wrap.querySelector(`#${id}keyBlock`);
      const pwBlock = wrap.querySelector(`#${id}pwBlock`);
      const syncAuth = () => {
        keyBlock.classList.toggle('hidden', authSel.value !== 'key');
        pwBlock.classList.toggle('hidden', authSel.value !== 'password');
      };
      authSel.addEventListener('change', syncAuth);
      syncAuth();

      wrap.querySelector(`#${id}browse`).addEventListener('click', async () => {
        const path = await api.openKeyDialog();
        if (path) wrap.querySelector(`#${id}keyPath`).value = path;
      });
      wrap.querySelector(`#${id}cancel`).addEventListener('click', close);

      const collect = () => {
        const payload = {
          id: p ? p.id : undefined,
          name: wrap.querySelector(`#${id}name`).value.trim(),
          host: wrap.querySelector(`#${id}host`).value.trim(),
          port: Number(wrap.querySelector(`#${id}port`).value),
          user: wrap.querySelector(`#${id}user`).value.trim(),
          authType: authSel.value,
          keyPath: wrap.querySelector(`#${id}keyPath`).value.trim(),
          managePath: wrap.querySelector(`#${id}managePath`).value.trim(),
          awgDir: wrap.querySelector(`#${id}awgDir`).value.trim(),
          sudoSameAsSsh: wrap.querySelector(`#${id}sudoSame`).checked,
        };
        const pk = wrap.querySelector(`#${id}privateKey`).value.trim();
        const pp = wrap.querySelector(`#${id}passphrase`).value;
        const pw = wrap.querySelector(`#${id}password`).value;
        if (pk) payload.privateKey = pk;
        else if (!isEdit) payload.privateKey = '';
        if (pp) payload.passphrase = pp;
        else if (!isEdit) payload.passphrase = '';
        if (pw) payload.password = pw;
        else if (!isEdit) payload.password = '';
        return payload;
      };

      const validate = (payload) => {
        if (!payload.host) throw new Error('Укажите IP или host сервера.');
        if (!payload.user) throw new Error('Укажите пользователя SSH.');
        if (!payload.port || payload.port < 1 || payload.port > 65535) throw new Error('Порт SSH должен быть 1–65535.');
        if (payload.authType === 'key' && !payload.keyPath && !payload.privateKey && !(p && p.hasPrivateKey)) {
          throw new Error('Укажите файл ключа или вставьте приватный ключ.');
        }
        if (payload.authType === 'password' && !payload.password && !(p && p.hasPassword)) {
          throw new Error('Укажите пароль SSH.');
        }
      };

      const save = async (connectAfter) => {
        err.classList.remove('visible');
        try {
          const payload = collect();
          validate(payload);
          const saved = await api.saveProfile(payload);
          await reloadProfiles();
          state.profileId = saved.id;
          localStorage.setItem('awg.profileId', saved.id);
          renderProfiles();
          updateConnCard();
          close();
          toast('Профиль сохранён', 'success');
          if (connectAfter) {
            await new Promise((r) => setTimeout(r, 100));
            await connectSelected();
          }
        } catch (e) {
          err.textContent = e.message;
          err.classList.add('visible');
        }
      };

      wrap.querySelector(`#${id}save`).addEventListener('click', () => save(false));
      wrap.querySelector(`#${id}saveConnect`).addEventListener('click', () => save(true));

      const del = wrap.querySelector(`#${id}delete`);
      if (del) {
        del.addEventListener('click', async () => {
          const ok = await confirmDialog({ title: 'Удалить профиль?', text: `Профиль <b>${esc(p.name)}</b> и сохранённые секреты будут удалены.`, confirmLabel: 'Удалить' });
          if (!ok) return;
          await api.deleteProfile(p.id);
          await reloadProfiles();
          if (state.profileId === p.id) {
            state.profileId = state.profiles[0] ? state.profiles[0].id : null;
            localStorage.setItem('awg.profileId', state.profileId || '');
          }
          renderProfiles();
          updateConnCard();
          close();
          toast('Профиль удалён', 'success');
        });
      }
    },
  });
}

async function reloadProfiles() {
  const data = await api.listProfiles();
  state.profiles = data.profiles || [];
  if (state.profileId && !state.profiles.some((p) => p.id === state.profileId)) {
    state.profileId = state.profiles[0] ? state.profiles[0].id : null;
  }
  renderProfiles();
}

function requireConnection() {
  if (!state.status || !state.status.connected) {
    toast('Сначала подключитесь к серверу.', 'warn');
    return false;
  }
  return true;
}

/* ------------------------------------------------------------------ */
/* Maintenance                                                         */
/* ------------------------------------------------------------------ */

function renderMaintenance() {
  const connected = Boolean(state.status && state.status.connected);
  const logMeta = $('#maintLogMeta');
  const sel = $('#backupSelect');
  const meta = $('#backupMeta');
  const btnClear = $('#btnClearManageLog');
  const btnDown = $('#btnDownloadBackup');
  const btnRefresh = $('#btnRefreshBackups');
  const btnUpload = $('#btnUploadBackup');
  const uploadTarget = $('#uploadTarget');
  if (!logMeta || !sel) return;

  if (!connected) {
    logMeta.textContent = 'Подключитесь к серверу.';
    sel.innerHTML = '<option value="">—</option>';
    sel.disabled = true;
    btnClear.disabled = true;
    btnDown.disabled = true;
    btnRefresh.disabled = true;
    if (btnUpload) btnUpload.disabled = true;
    if (uploadTarget) uploadTarget.textContent = '—';
    meta.textContent = 'Подключитесь к серверу, чтобы увидеть архивы.';
    return;
  }

  btnRefresh.disabled = false;
  sel.disabled = false;
  if (btnUpload) btnUpload.disabled = false;
  if (uploadTarget) uploadTarget.textContent = 'каталог backups рядом с manage_amneziawg.sh';

  const li = state.maintenance.logInfo;
  if (li) {
    logMeta.textContent = `${li.name} · ${fmtBytes(li.size)}${li.size ? '' : ' · пуст'}`;
    btnClear.disabled = !li.size;
  } else if (!state.maintenance.loaded) {
    logMeta.textContent = 'Загрузка…';
    btnClear.disabled = true;
  } else {
    logMeta.textContent = 'manage_amneziawg.log не найден';
    btnClear.disabled = true;
  }

  const backups = state.maintenance.backups || [];
  if (!backups.length) {
    sel.innerHTML = `<option value="">${state.maintenance.loaded ? 'Бэкапов нет' : 'Загрузка…'}</option>`;
    btnDown.disabled = true;
    meta.textContent = state.maintenance.loaded
      ? 'Создайте бэкап в разделе «Сервер» или «Команды».'
      : 'Чтение списка архивов…';
    if (!state.maintenance.loaded) loadMaintenance();
    return;
  }
  sel.innerHTML = backups.map((b) => `<option value="${esc(b.name)}">${esc(b.name)} — ${fmtBytes(b.size)}${b.date ? ` · ${esc(b.date)}` : ''}</option>`).join('');
  if (state.maintenance.selected && backups.some((b) => b.name === state.maintenance.selected)) {
    sel.value = state.maintenance.selected;
  } else {
    state.maintenance.selected = backups[0].name;
    sel.value = backups[0].name;
  }
  const cur = backups.find((b) => b.name === sel.value) || backups[0];
  meta.textContent = `${cur.name} · ${fmtBytes(cur.size)}${cur.date ? ` · ${cur.date}` : ''}`;
  btnDown.disabled = false;
}

async function loadMaintenance() {
  if (!state.status || !state.status.connected) { renderMaintenance(); return; }
  if (state.maintenance.loading) return;
  state.maintenance.loading = true;
  let failed = null;
  try {
    const [logsRes, backupsRes] = await Promise.allSettled([api.logs(), api.backups()]);
    if (logsRes.status === 'fulfilled' && logsRes.value && logsRes.value.ok) {
      state.maintenance.logInfo = (logsRes.value.logs || []).find((l) => l.name === 'manage_amneziawg.log') || null;
    } else {
      failed = (logsRes.status === 'fulfilled' && logsRes.value && logsRes.value.error)
        || 'Не удалось прочитать список журналов.';
    }
    if (backupsRes.status === 'fulfilled' && backupsRes.value && backupsRes.value.ok) {
      state.maintenance.backups = backupsRes.value.backups || [];
      if (!state.maintenance.backups.some((b) => b.name === state.maintenance.selected)) {
        state.maintenance.selected = state.maintenance.backups.length ? state.maintenance.backups[0].name : '';
      }
    } else if (!failed) {
      failed = (backupsRes.status === 'fulfilled' && backupsRes.value && backupsRes.value.error)
        || 'Не удалось прочитать список резервных копий.';
    }
    state.maintenance.loaded = true;
  } finally {
    state.maintenance.loading = false;
  }
  renderMaintenance();
  if (failed) toast(failed, 'error', 8000);
}

async function clearManageLog() {
  if (!requireConnection()) return;
  const ok = await confirmDialog({
    title: 'Очистить журнал управления?',
    text: 'Содержимое <code>manage_amneziawg.log</code> будет удалено безвозвратно. Сервер, клиенты, ключи и конфигурация не затрагиваются.',
    confirmLabel: 'Очистить',
  });
  if (!ok) return;
  showBusy('Очистка журнала…');
  let res;
  try {
    res = await api.clearManageLog();
  } finally {
    hideBusy();
  }
  if (!res || !res.ok) {
    toast((res && res.error) || 'Не удалось очистить журнал.', 'error', 8000);
    return;
  }
  toast(`Журнал очищен. Освобождено ${fmtBytes(res.beforeSize)}.`, 'success', 6000);
  await loadMaintenance();
}

async function downloadBackup() {
  if (!requireConnection()) return;
  const name = $('#backupSelect') ? $('#backupSelect').value : '';
  if (!name) { toast('Выберите архив.', 'warn'); return; }
  const bar = $('#backupProgressBar');
  const wrap = $('#backupProgress');
  if (wrap) wrap.classList.remove('hidden');
  if (bar) bar.style.width = '0%';
  showBusy(`Скачивание ${name}…`);
  let res;
  try {
    res = await api.downloadBackup(name);
  } finally {
    hideBusy();
    if (wrap) wrap.classList.add('hidden');
  }
  if (res && res.canceled) return;
  if (!res || !res.ok) {
    toast((res && res.error) || 'Не удалось скачать бэкап.', 'error', 9000);
    return;
  }
  toast(`Бэкап сохранён: ${res.path} (${fmtBytes(res.size)})`, 'success', 10000);
}

async function uploadBackup() {
  if (!requireConnection()) return;
  const ok = await confirmDialog({
    title: 'Загрузить бэкап на сервер?',
    text: 'Архив <code>.tar.gz</code> будет отправлен в каталог <code>backups</code> на сервере. Существующие файлы не перезаписываются. Сервер, клиенты и конфигурация не меняются.',
    confirmLabel: 'Выбрать файл',
  });
  if (!ok) return;
  const bar = $('#uploadProgressBar');
  const wrap = $('#uploadProgress');
  const meta = $('#uploadMeta');
  if (wrap) wrap.classList.remove('hidden');
  if (bar) bar.style.width = '0%';
  showBusy('Загрузка архива на сервер…');
  let res;
  try {
    res = await api.uploadBackup();
  } finally {
    hideBusy();
    if (wrap) wrap.classList.add('hidden');
  }
  if (res && res.canceled) {
    if (meta) meta.textContent = 'Архив не выбран.';
    return;
  }
  if (!res || !res.ok) {
    if (meta) meta.textContent = 'Загрузка не выполнена.';
    toast((res && res.error) || 'Не удалось загрузить бэкап.', 'error', 9000);
    return;
  }
  if (meta) meta.textContent = `${res.name} · ${fmtBytes(res.size)} · загружен`;
  toast(`Архив загружен на сервер: ${res.name} (${fmtBytes(res.size)})`, 'success', 10000);
  await loadMaintenance();
}

/* ------------------------------------------------------------------ */
/* About                                                               */
/* ------------------------------------------------------------------ */

function renderAbout() {
  const info = state.info || {};
  const set = (sel, value) => {
    const el = $(sel);
    if (el) el.textContent = value || '—';
  };
  set('#aboutVersion', info.version ? `v${info.version}` : 'v1.1.0');
  set('#aboutVersion2', info.version || '1.1.0');
  set('#aboutElectron', info.electron);
  set('#aboutNode', info.node);
  set('#aboutDataDir', info.dataDir);
  set('#updateCurrent', info.version ? `v${info.version}` : '—');
  const u = state.update;
  if (u) {
    set('#updateLatest', u.latest ? `v${u.latest}` : '—');
    const meta = $('#updateMeta');
    const btn = $('#btnDownloadUpdate');
    if (u.ok) {
      if (u.newer) {
        if (meta) meta.textContent = `Доступна новая версия v${u.latest}. Скачайте portable-файл и замените текущий.`;
        if (btn) btn.classList.remove('hidden');
      } else {
        if (meta) meta.textContent = `Установлена последняя версия (${u.current}).`;
        if (btn) btn.classList.add('hidden');
      }
    } else {
      if (meta) meta.textContent = `Не удалось проверить обновления: ${u.error || 'нет связи с GitHub'}.`;
      if (btn) btn.classList.add('hidden');
    }
  }
}

async function downloadUpdate() {
  const u = state.update;
  if (!u || !u.ok) { toast('Сначала проверьте обновления.', 'warn'); return; }
  if (!u.assetUrl || !u.assetName) {
    api.openExternal(u.url).then((ok) => { if (!ok) toast('Ссылка заблокирована.', 'warn'); });
    return;
  }
  const wrap = $('#updateProgress');
  const bar = $('#updateProgressBar');
  const meta = $('#updateMeta');
  const btn = $('#btnDownloadUpdate');
  if (wrap) wrap.classList.remove('hidden');
  if (bar) bar.style.width = '0%';
  if (btn) btn.disabled = true;
  showBusy(`Скачивание ${u.assetName}…`);
  let res;
  try {
    res = await api.downloadUpdate({ url: u.assetUrl, name: u.assetName });
  } finally {
    hideBusy();
    if (wrap) wrap.classList.add('hidden');
    if (btn) btn.disabled = false;
  }
  if (!res || !res.ok) {
    toast((res && res.error) || 'Не удалось скачать обновление.', 'error', 9000);
    return;
  }
  if (meta) meta.textContent = `Файл сохранён: ${res.path}. Закройте приложение и замените старый exe новым.`;
  toast(`Обновление скачано: ${res.path}`, 'success', 12000);
}

async function checkUpdates({ quiet = false } = {}) {
  const btn = $('#btnCheckUpdates');
  if (btn) { btn.disabled = true; btn.textContent = 'Проверка…'; }
  let res;
  try {
    res = await api.checkUpdates();
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Проверить обновления'; }
  }
  state.update = res || { ok: false, error: 'нет ответа' };
  renderAbout();
  if (!res || !res.ok) {
    if (!quiet) toast(`Не удалось проверить обновления: ${(res && res.error) || 'нет связи'}.`, 'warn', 8000);
    return;
  }
  if (res.newer) toast(`Доступна новая версия v${res.latest}.`, 'info', 9000);
  else if (!quiet) toast('Установлена последняя версия.', 'success', 5000);
}


/* ------------------------------------------------------------------ */
/* Tabs / events / init                                                */
/* ------------------------------------------------------------------ */

function switchTab(tab) {
  state.tab = tab;
  $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === tab));
  $$('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${tab}`));
  if (tab === 'overview') {
    renderOverview();
    if (state.status && state.status.connected && !state.check) refreshAll();
  }
  if (tab === 'clients') {
    renderClients();
    if (state.status && state.status.connected && !state.clients.length) refreshClients();
  }
  if (tab === 'server') {
    if (state.status && state.status.connected && !state.server) loadServer(state.serverReveal);
    else if (state.server) renderServer();
  }
  if (tab === 'commands') renderCommandCards();
  if (tab === 'maintenance') {
    renderMaintenance();
    if (state.status && state.status.connected) loadMaintenance();
  }
  if (tab === 'about') renderAbout();
  if (tab === 'journal') renderJournal();
  if (tab === 'console') {
    const pre = $('#consoleOutput');
    if (pre) { pre.textContent = state.consoleBuffer; pre.scrollTop = pre.scrollHeight; }
    setTimeout(() => $('#consoleInput')?.focus(), 50);
  }
}

function bindEvents() {
  $('#tabs').addEventListener('click', (e) => {
    const t = e.target.closest('.tab');
    if (t) switchTab(t.dataset.tab);
  });

  $('#btnConnToggle').addEventListener('click', () => {
    if (state.status && state.status.connected) disconnectSession();
    else connectSelected();
  });
  $('#btnNewProfile').addEventListener('click', () => openProfileModal());
  $('#btnSettings').addEventListener('click', () => openSettings());
  $('#btnRefreshAll').addEventListener('click', () => refreshAll(true));

  $('#profileList').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-act]');
    const item = e.target.closest('.profile-item');
    if (btn) {
      e.stopPropagation();
      const id = btn.dataset.id;
      state.profileId = id;
      localStorage.setItem('awg.profileId', id);
      renderProfiles();
      updateConnCard();
      if (btn.dataset.act === 'connect') connectSelected();
      if (btn.dataset.act === 'disconnect') disconnectSession();
      if (btn.dataset.act === 'edit') openProfileModal(state.profiles.find((p) => p.id === id));
      return;
    }
    if (item) {
      state.profileId = item.dataset.id;
      localStorage.setItem('awg.profileId', state.profileId);
      renderProfiles();
      updateConnCard();
    }
  });

  $('#btnClientsRefresh').addEventListener('click', () => refreshClients(true));
  $('#btnAddClient').addEventListener('click', () => openAddClient());
  $('#clientSearch').addEventListener('input', () => renderClients());
  $('#clientsVerbose').addEventListener('change', () => refreshClients(true));
  $('#clientsTableWrap').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-cact]');
    if (!btn) return;
    const name = btn.dataset.name;
    if (btn.dataset.cact === 'qr') openQr(name, 'conf');
    if (btn.dataset.cact === 'edit') openEditClient(name);
    if (btn.dataset.cact === 'regen') openRegenClient(name);
    if (btn.dataset.cact === 'remove') openRemoveClient(name);
  });

  $('#btnServerRefresh').addEventListener('click', () => loadServer(state.serverReveal));
  $('#btnRevealServer').addEventListener('click', () => {
    if (!state.server) return;
    if (!state.serverReveal) {
      confirmDialog({
        title: 'Показать секреты сервера?',
        text: 'Будут показаны PrivateKey, PresharedKey и HeaderProtectionKey из awg0.conf.',
        confirmLabel: 'Показать',
      }).then((ok) => { if (ok) loadServer(true); });
    } else {
      loadServer(false);
    }
  });
  $('#serverContent').addEventListener('click', onServerClick);

  $('#btnRunCheck').addEventListener('click', () => runDiag('check', {}, 'check'));
  $('#btnRunShow').addEventListener('click', () => runDiag('show', {}, 'awg show'));
  $('#btnRunDiagnose').addEventListener('click', () => runDiag('diagnose', { carrier: $('#carrierSelect').value }, 'diagnose'));
  $('#btnClearDiag').addEventListener('click', () => { $('#diagOutput').textContent = ''; $('#diagStatus').textContent = 'Готово'; $('#diagMeta').textContent = ''; });

  $('#commandCards').addEventListener('click', (e) => {
    const card = e.target.closest('[data-cmd]');
    if (card) openCommandForm(card.dataset.cmd);
  });

  $('#btnConsoleRun').addEventListener('click', runConsole);
  $('#consoleInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); runConsole(); return; }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (!state.consoleHistory.length) return;
      state.consoleIndex = Math.max(0, Math.min(state.consoleHistory.length - 1, state.consoleIndex - 1));
      $('#consoleInput').value = state.consoleHistory[state.consoleIndex] || '';
      return;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      state.consoleIndex = Math.min(state.consoleHistory.length, state.consoleIndex + 1);
      $('#consoleInput').value = state.consoleHistory[state.consoleIndex] || '';
    }
  });
  $('#btnConsoleClear').addEventListener('click', () => {
    state.consoleBuffer = '';
    $('#consoleOutput').textContent = '';
  });

  $('#btnJournalClear').addEventListener('click', () => { state.appLog = []; renderJournal(); });
  $('#btnOpenData').addEventListener('click', () => api.openDataDir());

  $('#btnMaintRefresh').addEventListener('click', () => loadMaintenance());
  $('#btnRefreshBackups').addEventListener('click', () => loadMaintenance());
  $('#btnClearManageLog').addEventListener('click', clearManageLog);
  $('#btnDownloadBackup').addEventListener('click', downloadBackup);
  $('#btnUploadBackup').addEventListener('click', uploadBackup);
  $('#btnCheckUpdates').addEventListener('click', () => checkUpdates());
  $('#btnDownloadUpdate').addEventListener('click', () => downloadUpdate());
  $('#backupSelect').addEventListener('change', () => {
    state.maintenance.selected = $('#backupSelect').value;
    renderMaintenance();
  });
  $('#view-about').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-ext]');
    if (!btn) return;
    e.preventDefault();
    api.openExternal(btn.dataset.ext).then((ok) => {
      if (!ok) toast('Ссылка заблокирована.', 'warn');
    });
  });

  api.onBackupProgress(({ transferred, total }) => {
    if (!total) return;
    const pct = Math.max(0, Math.min(100, Math.round((transferred / total) * 100)));
    const bar = $('#backupProgressBar');
    if (bar) bar.style.width = `${pct}%`;
  });

  api.onUploadProgress(({ transferred, total }) => {
    if (!total) return;
    const pct = Math.max(0, Math.min(100, Math.round((transferred / total) * 100)));
    const bar = $('#uploadProgressBar');
    if (bar) bar.style.width = `${pct}%`;
  });

  api.onUpdateProgress(({ transferred, total }) => {
    if (!total) return;
    const pct = Math.max(0, Math.min(100, Math.round((transferred / total) * 100)));
    const bar = $('#updateProgressBar');
    if (bar) bar.style.width = `${pct}%`;
  });

  api.onOutput(({ requestId, stream, chunk }) => {
    const h = activeRuns.get(requestId);
    if (h) h(chunk, stream);
    else appendConsole(chunk);
  });

  api.onStatus((status) => {
    const was = state.status && state.status.connected;
    state.status = status;
    updateConnCard();
    renderProfiles();
    if (was && status && !status.connected) {
      toast('SSH-соединение закрыто.', 'warn', 6000);
      state.check = null;
      state.clients = [];
      state.stats = [];
      state.server = null;
      renderOverview();
      renderClients();
    }
  });

  api.onLog((entry) => {
    state.appLog.push(entry);
    if (state.appLog.length > 800) state.appLog = state.appLog.slice(-600);
    if (state.tab === 'journal') renderJournal();
  });

  api.onCommandStart((p) => {
    if (p && p.command && !silentRequests.has(p.requestId)) appendConsole(`\n$ ${p.command}\n`);
  });
}

function renderCarrierSelect() {
  const sel = $('#carrierSelect');
  if (!sel) return;
  sel.innerHTML = '<option value="">без сравнения</option>' + CARRIERS.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join('');
}

async function init() {
  try {
    state.info = await api.info();
  } catch (_) { /* ignore */ }
  renderCarrierSelect();
  renderCommandCards();
  renderAbout();
  bindEvents();

  setTimeout(() => { checkUpdates({ quiet: true }); }, 4000);

  try {
    const data = await api.listProfiles();
    state.profiles = data.profiles || [];
    if (data.error) toast(data.error, 'error', 10000);
  } catch (e) {
    toast(`Не удалось загрузить профили: ${e.message}`, 'error', 8000);
  }

  const last = localStorage.getItem('awg.profileId');
  state.profileId = (state.profiles.find((p) => p.id === last) || state.profiles[0] || {}).id || null;
  renderProfiles();
  updateConnCard();
  renderOverview();
  renderClients();

  try {
    const st = await api.status();
    if (st && st.connected) {
      state.status = st;
      updateConnCard();
      renderProfiles();
      await refreshAll();
    }
  } catch (_) { /* ignore */ }

  if (!state.profiles.length) {
    setTimeout(() => openProfileModal(), 350);
  }
}

document.addEventListener('DOMContentLoaded', init);
