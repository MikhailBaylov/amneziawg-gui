'use strict';

const {
  shq,
  validateClientName,
  validateExpires,
  validateAllowedIps,
  validateBackupName,
  CARRIERS,
} = require('./util');

const MODIFY_PARAMS = ['DNS', 'Endpoint', 'AllowedIPs', 'PersistentKeepalive'];
const CARRIER_IDS = new Set(CARRIERS.map(([id]) => id));

function manageBase(profile) {
  return `bash ${shq(profile.managePath)}`;
}

function names(params) {
  const raw = Array.isArray(params.names) ? params.names : String(params.names || '').split(/[\s,]+/);
  const list = raw.map((x) => String(x).trim()).filter(Boolean);
  if (!list.length) throw new Error('Укажите хотя бы одно имя клиента.');
  if (list.length > 50) throw new Error('Слишком много имён за один раз (максимум 50).');
  return list.map(validateClientName);
}

function validateModifyValue(param, value) {
  const v = String(value == null ? '' : value).trim();
  if (!v) throw new Error('Укажите новое значение параметра.');
  if (v.length > 2000) throw new Error('Значение слишком длинное.');
  switch (param) {
    case 'DNS':
      if (!/^[0-9a-fA-F:., ]+$/.test(v)) throw new Error('DNS: ожидается список IPv4/IPv6 через запятую.');
      break;
    case 'Endpoint':
      if (!/^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9_.-]+):[0-9]{1,5}$/.test(v)) {
        throw new Error('Endpoint: ожидается host:port или [IPv6]:port.');
      }
      break;
    case 'AllowedIPs':
      validateAllowedIps(v);
      break;
    case 'PersistentKeepalive': {
      const n = Number(v);
      if (!Number.isInteger(n) || n < 0 || n > 65535) throw new Error('PersistentKeepalive: целое число 0–65535.');
      break;
    }
    default:
      throw new Error('Этот параметр нельзя изменить через modify.');
  }
  return v;
}

/**
 * Build a manage command. Returns { command, json, timeout, title, danger }.
 * All user-controlled values are validated and shell-quoted.
 */
function buildAction(action, params, profile) {
  const base = manageBase(profile);
  const p = params || {};

  switch (action) {
    case 'add': {
      const list = names(p);
      let cmd = `${base} add ${list.map(shq).join(' ')}`;
      const exp = validateExpires(p.expires);
      if (exp) cmd += ` --expires=${shq(exp)}`;
      if (p.psk) cmd += ' --psk';
      const aip = validateAllowedIps(p.allowedIps);
      if (aip) cmd += ` --allowed-ips=${shq(aip)}`;
      cmd += ' --json';
      return { command: cmd, json: true, timeout: 180000, title: `Добавление клиента: ${list.join(', ')}`, danger: false };
    }
    case 'remove': {
      const list = names(p);
      return {
        command: `${base} remove ${list.map(shq).join(' ')} --json --yes`,
        json: true,
        timeout: 180000,
        title: `Удаление клиента: ${list.join(', ')}`,
        danger: true,
      };
    }
    case 'list':
      return {
        command: `${base} list ${p.verbose ? '-v ' : ''}--json`,
        json: true,
        timeout: 60000,
        title: 'Список клиентов',
        danger: false,
      };
    case 'stats':
      return { command: `${base} stats --json`, json: true, timeout: 60000, title: 'Статистика клиентов', danger: false };
    case 'regen': {
      let list = [];
      if (p.names && String(p.names).trim()) list = names(p);
      let cmd = `${base} regen`;
      if (list.length) cmd += ` ${list.map(shq).join(' ')}`;
      if (p.resetRoutes) cmd += ' --reset-routes';
      cmd += ' --json';
      return {
        command: cmd,
        json: true,
        timeout: 180000,
        title: list.length ? `Перегенерация: ${list.join(', ')}` : 'Перегенерация всех клиентов',
        danger: false,
      };
    }
    case 'modify': {
      const name = validateClientName(p.name);
      const param = String(p.param || '');
      if (!MODIFY_PARAMS.includes(param)) throw new Error('Недопустимый параметр modify.');
      const value = validateModifyValue(param, p.value);
      return {
        command: `${base} modify ${shq(name)} ${shq(param)} ${shq(value)} --json`,
        json: true,
        timeout: 90000,
        title: `Изменение ${param} у ${name}`,
        danger: false,
      };
    }
    case 'backup':
      return { command: `${base} backup --json`, json: true, timeout: 180000, title: 'Резервная копия', danger: false };
    case 'restore': {
      const file = validateBackupName(p.file);
      const full = `${profile.awgDir.replace(/\/+$/, '')}/backups/${file}`;
      return {
        command: `${base} restore ${shq(full)} --json --yes`,
        json: true,
        timeout: 300000,
        title: `Восстановление из ${file}`,
        danger: true,
      };
    }
    case 'check':
      return { command: `${base} check --json`, json: true, timeout: 90000, title: 'Проверка состояния', danger: false };
    case 'diagnose': {
      const carrier = String(p.carrier || '').trim();
      if (carrier && !CARRIER_IDS.has(carrier)) throw new Error('Неизвестный профиль оператора.');
      const cmd = carrier ? `${base} diagnose --carrier=${shq(carrier)}` : `${base} diagnose`;
      return { command: cmd, json: false, timeout: 240000, title: 'Диагностика', danger: false };
    }
    case 'show':
      return { command: `${base} show`, json: false, timeout: 60000, title: 'awg show', danger: false };
    case 'restart':
      return {
        command: `${base} restart --json --yes`,
        json: true,
        timeout: 120000,
        title: 'Перезапуск сервиса AmneziaWG',
        danger: true,
      };
    case 'repair-module':
      return {
        command: `${base} repair-module --json --yes`,
        json: true,
        timeout: 900000,
        title: 'Пересборка модуля ядра (DKMS)',
        danger: true,
      };
    case 'help':
      return { command: `${base} help`, json: false, timeout: 60000, title: 'Справка manage_amneziawg.sh', danger: false };
    case 'raw': {
      const cmd = String(p.command || '').trim();
      if (!cmd) throw new Error('Пустая команда.');
      if (cmd.length > 8000) throw new Error('Слишком длинная команда.');
      return { command: cmd, json: false, timeout: Number(p.timeout) || 120000, title: 'Произвольная команда', danger: true, raw: true };
    }
    default:
      throw new Error(`Неизвестное действие: ${action}`);
  }
}

module.exports = { buildAction, MODIFY_PARAMS, CARRIERS };
