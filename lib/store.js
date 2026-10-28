'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { safeStorage } = require('electron');

const SECRET_FIELDS = ['privateKey', 'passphrase', 'password'];

class Store {
  constructor(dir) {
    this.dir = dir;
    this.profilesPath = path.join(dir, 'profiles.json');
    this.knownHostsPath = path.join(dir, 'known_hosts.json');
    this.settingsPath = path.join(dir, 'settings.json');
    this.logPath = path.join(dir, 'awg-gui.log');
    this.profiles = [];
    this.knownHosts = {};
    this.settings = {};
    this.encrypted = false;
  }

  init() {
    fs.mkdirSync(this.dir, { recursive: true });
    try { this.encrypted = safeStorage.isEncryptionAvailable(); } catch (_) { /* ignore */ }
    this.profiles = this._readProfiles();
    this.knownHosts = this._readJson(this.knownHostsPath, {});
    this.settings = this._readJson(this.settingsPath, {});
    this._rotateLog();
    return this;
  }

  _readJson(file, fallback) {
    try {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (_) {
      return fallback;
    }
  }

  _writeJson(file, data) {
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, file);
  }

  _readProfiles() {
    const raw = this._readJson(this.profilesPath, null);
    if (!raw) return [];
    if (raw.enc === true && typeof raw.data === 'string') {
      try {
        if (!safeStorage.isEncryptionAvailable()) throw new Error('safeStorage недоступен');
        const json = safeStorage.decryptString(Buffer.from(raw.data, 'base64'));
        this.encrypted = true;
        const parsed = JSON.parse(json);
        return Array.isArray(parsed) ? parsed : [];
      } catch (e) {
        this.lastProfileError = `Не удалось расшифровать профили: ${e.message}`;
        return [];
      }
    }
    if (Array.isArray(raw.profiles)) {
      this.encrypted = false;
      return raw.profiles;
    }
    return [];
  }

  saveProfiles() {
    if (!safeStorage.isEncryptionAvailable()) {
      throw new Error('Windows DPAPI недоступен: сохранение профилей остановлено, чтобы не хранить ключи в открытом виде.');
    }
    const json = JSON.stringify(this.profiles);
    const enc = safeStorage.encryptString(json).toString('base64');
    this._writeJson(this.profilesPath, { v: 1, enc: true, data: enc });
    this.encrypted = true;
  }

  listProfiles() {
    return this.profiles.map(sanitizeProfile);
  }

  getProfile(id) {
    return this.profiles.find((p) => p.id === id) || null;
  }

  getProfileRaw(id) {
    return this.profiles.find((p) => p.id === id) || null;
  }

  saveProfile(input) {
    const now = new Date().toISOString();
    const clean = normalizeProfileInput(input);
    let existing = input.id ? this.getProfile(input.id) : null;
    if (existing) {
      for (const f of SECRET_FIELDS) {
        if (input[f] === undefined || input[f] === null) clean[f] = existing[f] || '';
      }
      Object.assign(existing, clean, { updatedAt: now });
      this.saveProfiles();
      return sanitizeProfile(existing);
    }
    const profile = {
      id: crypto.randomUUID(),
      ...clean,
      createdAt: now,
      updatedAt: now,
    };
    this.profiles.push(profile);
    this.saveProfiles();
    return sanitizeProfile(profile);
  }

  deleteProfile(id) {
    const before = this.profiles.length;
    this.profiles = this.profiles.filter((p) => p.id !== id);
    if (this.profiles.length !== before) this.saveProfiles();
    return this.profiles.length !== before;
  }

  knownHostKey(host, port) {
    return `${String(host).toLowerCase()}:${Number(port) || 22}`;
  }

  getKnownHost(host, port) {
    return this.knownHosts[this.knownHostKey(host, port)] || null;
  }

  trustHost(host, port, fingerprint, algorithm) {
    this.knownHosts[this.knownHostKey(host, port)] = {
      fingerprint,
      algorithm: algorithm || '',
      trustedAt: new Date().toISOString(),
    };
    this._writeJson(this.knownHostsPath, this.knownHosts);
  }

  forgetHost(host, port) {
    delete this.knownHosts[this.knownHostKey(host, port)];
    this._writeJson(this.knownHostsPath, this.knownHosts);
  }

  listKnownHosts() {
    return Object.entries(this.knownHosts).map(([key, v]) => ({ key, ...v }));
  }

  getSetting(key, fallback) {
    return Object.prototype.hasOwnProperty.call(this.settings, key) ? this.settings[key] : fallback;
  }

  setSetting(key, value) {
    this.settings[key] = value;
    this._writeJson(this.settingsPath, this.settings);
  }

  _rotateLog() {
    try {
      const st = fs.statSync(this.logPath);
      if (st.size > 2 * 1024 * 1024) {
        fs.renameSync(this.logPath, `${this.logPath}.1`);
      }
    } catch (_) { /* no log yet */ }
  }

  log(level, text) {
    const line = `${new Date().toISOString()} [${level}] ${String(text).replace(/\r?\n/g, ' | ')}\n`;
    try { fs.appendFileSync(this.logPath, line, { mode: 0o600 }); } catch (_) { /* ignore */ }
  }
}

function normalizeProfileInput(input) {
  const host = String(input.host || '').trim();
  if (!host || !/^[A-Za-z0-9_.:\-\[\]]{1,255}$/.test(host)) {
    throw new Error('Некорректный адрес сервера.');
  }
  const port = Number(input.port || 22);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Порт SSH должен быть 1–65535.');
  }
  const user = String(input.user || 'root').trim();
  if (!/^[A-Za-z0-9_.\-]{1,64}$/.test(user)) {
    throw new Error('Некорректное имя пользователя SSH.');
  }
  const authType = input.authType === 'password' ? 'password' : 'key';
  const managePath = String(input.managePath || '/root/awg/manage_amneziawg.sh').trim();
  const awgDir = String(input.awgDir || '/root/awg').trim();
  if (!managePath.startsWith('/') || !/^[A-Za-z0-9_./-]+$/.test(managePath)) {
    throw new Error('Путь к manage_amneziawg.sh должен быть абсолютным и без спецсимволов.');
  }
  if (!awgDir.startsWith('/') || !/^[A-Za-z0-9_./-]+$/.test(awgDir)) {
    throw new Error('Каталог AWG должен быть абсолютным и без спецсимволов.');
  }
  return {
    name: String(input.name || host).trim().slice(0, 80) || host,
    host,
    port,
    user,
    authType,
    keyPath: String(input.keyPath || '').trim(),
    privateKey: typeof input.privateKey === 'string' ? input.privateKey : '',
    passphrase: typeof input.passphrase === 'string' ? input.passphrase : '',
    password: typeof input.password === 'string' ? input.password : '',
    managePath,
    awgDir,
    sudoSameAsSsh: input.sudoSameAsSsh !== false,
  };
}

function sanitizeProfile(p) {
  const out = {
    id: p.id,
    name: p.name,
    host: p.host,
    port: p.port,
    user: p.user,
    authType: p.authType,
    keyPath: p.keyPath || '',
    managePath: p.managePath,
    awgDir: p.awgDir,
    sudoSameAsSsh: p.sudoSameAsSsh !== false,
    hasPrivateKey: Boolean(p.privateKey),
    hasPassphrase: Boolean(p.passphrase),
    hasPassword: Boolean(p.password),
    createdAt: p.createdAt,
    updatedAt: p.updatedAt,
  };
  return out;
}

module.exports = { Store, sanitizeProfile };
