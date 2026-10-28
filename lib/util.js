'use strict';

const ANSI_RE = /\u001b\[[0-9;?]*[ -/]*[@-~]|\u001b\][^\u0007]*(?:\u0007|\u001b\\)/g;

function stripAnsi(s) {
  return String(s == null ? '' : s).replace(ANSI_RE, '');
}

/** POSIX shell single-quote. Safe for arbitrary text without NUL/newline. */
function shq(value) {
  const s = String(value);
  if (s.includes('\0') || s.includes('\n') || s.includes('\r')) {
    throw new Error('Недопустимый символ перевода строки в аргументе команды');
  }
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function clampText(s, max) {
  const str = String(s == null ? '' : s);
  if (str.length <= max) return { text: str, truncated: false };
  return {
    text: str.slice(0, max) + `\n\n… вывод обрезан (${str.length} символов, показано ${max})`,
    truncated: true,
  };
}

function parseJsonLoose(text) {
  if (text == null) return null;
  const s = stripAnsi(text).trim();
  if (!s) return null;
  try { return JSON.parse(s); } catch (_) { /* continue */ }
  // Contract promises exactly one document on stdout, but be tolerant to
  // accidental leading/trailing lines.
  const firstObj = s.indexOf('{');
  const firstArr = s.indexOf('[');
  let start = -1;
  if (firstObj === -1) start = firstArr;
  else if (firstArr === -1) start = firstObj;
  else start = Math.min(firstObj, firstArr);
  if (start < 0) return null;
  const lastObj = s.lastIndexOf('}');
  const lastArr = s.lastIndexOf(']');
  const end = Math.max(lastObj, lastArr);
  if (end <= start) return null;
  try { return JSON.parse(s.slice(start, end + 1)); } catch (_) { return null; }
}

function humanBytes(n) {
  const num = Number(n) || 0;
  if (num < 1024) return `${num} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = num / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}

const CLIENT_NAME_RE = /^[A-Za-z0-9_-]{1,64}$/;
const CARRIERS = [
  ['beeline_msk', 'Билайн (Москва)'],
  ['yota_msk', 'Yota (Москва)'],
  ['tele2_msk', 'Tele2 (Москва)'],
  ['tele2_krasnoyarsk', 'Tele2 (Красноярск)'],
  ['tattelecom', 'Таттелеком / Летай'],
  ['megafon_regions', 'Мегафон (регионы)'],
  ['tmobile_us', 'Т-Мобайл (Москва и область)'],
];

function validateClientName(name) {
  if (!CLIENT_NAME_RE.test(String(name || ''))) {
    throw new Error(`Недопустимое имя клиента «${name}». Разрешены латиница, цифры, _ и -, до 64 символов.`);
  }
  return String(name);
}

function validateExpires(value) {
  if (!value) return '';
  const v = String(value).trim();
  if (!/^[1-9][0-9]{0,5}[hdw]$/.test(v)) {
    throw new Error('Срок задаётся как 1h, 12h, 1d, 7d, 30d или 4w.');
  }
  return v;
}

function validateAllowedIps(value) {
  const v = String(value || '').trim();
  if (!v) return '';
  if (v.length > 2000 || !/^[0-9a-fA-F:./, ]+$/.test(v)) {
    throw new Error('AllowedIPs: ожидается список CIDR IPv4/IPv6 через запятую.');
  }
  const parts = v.split(',').map((x) => x.trim()).filter(Boolean);
  for (const p of parts) {
    if (!/^[0-9a-fA-F:.]+(\/[0-9]{1,3})?$/.test(p)) {
      throw new Error(`AllowedIPs: некорректный элемент «${p}».`);
    }
  }
  return parts.join(', ');
}

function validateBackupName(value) {
  const v = String(value || '').trim();
  if (!/^awg_backup_[A-Za-z0-9._-]+\.tar\.gz$/.test(v)) {
    throw new Error('Некорректное имя файла резервной копии.');
  }
  return v;
}

module.exports = {
  stripAnsi,
  shq,
  clampText,
  parseJsonLoose,
  humanBytes,
  validateClientName,
  validateExpires,
  validateAllowedIps,
  validateBackupName,
  CLIENT_NAME_RE,
  CARRIERS,
};
