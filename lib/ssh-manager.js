'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Client } = require('ssh2');
const { shq, stripAnsi, clampText, parseJsonLoose } = require('./util');

const MAX_OUTPUT = 8 * 1024 * 1024;

function fingerprint(key) {
  return 'SHA256:' + crypto.createHash('sha256').update(key).digest('base64').replace(/=+$/, '');
}

function keyAlgorithm(key) {
  try {
    const len = key.readUInt32BE(0);
    return key.slice(4, 4 + len).toString('ascii');
  } catch (_) {
    return '';
  }
}

class SshManager {
  constructor(store, emit) {
    this.store = store;
    this.emit = emit;
    this.client = null;
    this.profile = null;
    this.connected = false;
    this.isRoot = false;
    this.sudoReady = false;
    this.sudoPassword = null;
    this.queue = Promise.resolve();
    this.hostKey = null;
    this.pendingHostKey = null;
    this.server = null;
    this._closing = false;
  }

  status() {
    return {
      connected: this.connected,
      profileId: this.profile ? this.profile.id : null,
      profileName: this.profile ? this.profile.name : null,
      host: this.profile ? this.profile.host : null,
      port: this.profile ? this.profile.port : null,
      user: this.profile ? this.profile.user : null,
      isRoot: this.isRoot,
      sudoReady: this.sudoReady,
      hostKey: this.hostKey,
      server: this.server,
      encryptedProfiles: this.store.encrypted,
    };
  }

  async connect(profileId, secrets = {}) {
    this.disconnect();
    const profile = this.store.getProfileRaw(profileId);
    if (!profile) throw new Error('Профиль не найден.');

    let privateKey;
    let password = '';
    let passphrase = '';

    if (profile.authType === 'password') {
      password = typeof secrets.password === 'string' && secrets.password !== ''
        ? secrets.password
        : (profile.password || '');
      if (!password) throw new Error('Не задан пароль SSH.');
    } else {
      passphrase = typeof secrets.passphrase === 'string' && secrets.passphrase !== ''
        ? secrets.passphrase
        : (profile.passphrase || '');
      if (profile.keyPath) {
        try {
          privateKey = fs.readFileSync(profile.keyPath);
        } catch (e) {
          throw new Error(`Не удалось прочитать SSH-ключ «${profile.keyPath}»: ${e.message}`);
        }
      } else if (profile.privateKey) {
        privateKey = Buffer.from(profile.privateKey, 'utf8');
      } else if (typeof secrets.privateKey === 'string' && secrets.privateKey.trim()) {
        privateKey = Buffer.from(secrets.privateKey, 'utf8');
      }
      if (!privateKey) throw new Error('Не задан приватный SSH-ключ.');
    }

    const known = this.store.getKnownHost(profile.host, profile.port);
    this.pendingHostKey = null;
    const client = new Client();
    this.client = client;
    this.profile = profile;
    this._closing = false;
    this.queue = Promise.resolve();

    const config = {
      host: profile.host,
      port: profile.port,
      username: profile.user,
      readyTimeout: 30000,
      keepaliveInterval: 10000,
      keepaliveCountMax: 3,
      tryKeyboard: true,
      hostVerifier: (key) => {
        const fp = fingerprint(key);
        const alg = keyAlgorithm(key);
        this.pendingHostKey = { host: profile.host, port: profile.port, fingerprint: fp, algorithm: alg, known: known ? known.fingerprint : null };
        if (known && known.fingerprint !== fp) return false;
        if (!known) {
          this.store.trustHost(profile.host, profile.port, fp, alg);
          this.emit('log', { level: 'info', text: `Новый SSH-ключ сервера сохранён (${fp}).` });
        }
        return true;
      },
    };

    if (privateKey) {
      config.privateKey = privateKey;
      if (passphrase) config.passphrase = passphrase;
    } else {
      config.password = password;
      client.on('keyboard-interactive', (_n, _i, _l, prompts, finish) => {
        finish(prompts.map(() => password));
      });
    }

    await new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err) => {
        if (settled) return;
        settled = true;
        try { client.end(); } catch (_) { /* ignore */ }
        reject(err);
      };
      client.once('ready', () => {
        if (settled) return;
        settled = true;
        resolve();
      });
      client.once('error', (err) => {
        const hk = this.pendingHostKey;
        if (hk && hk.known && hk.known !== hk.fingerprint) {
          const e = new Error('Отпечаток SSH-ключа сервера изменился.');
          e.code = 'HOSTKEY_MISMATCH';
          e.hostKey = hk;
          fail(e);
          return;
        }
        fail(err);
      });
      client.once('close', () => {
        if (!settled) fail(new Error('Соединение закрыто до установления сессии.'));
      });
      client.connect(config);
    });

    this.connected = true;
    this.hostKey = this.pendingHostKey;

    client.on('close', () => {
      const wasConnected = this.connected;
      this.connected = false;
      this.isRoot = false;
      this.sudoReady = false;
      this.sudoPassword = null;
      this.client = null;
      if (wasConnected) {
        this.emit('status', this.status());
        this.emit('log', { level: 'warn', text: 'SSH-соединение закрыто.' });
      }
    });
    client.on('error', (err) => {
      this.emit('log', { level: 'error', text: `SSH: ${err.message}` });
    });

    const uid = await this._execRaw('id -u', { timeout: 15000 });
    this.isRoot = stripAnsi(uid.stdout).trim() === '0';
    if (!this.isRoot) {
      const sudo = await this._execRaw('sudo -n true', { timeout: 15000 });
      this.sudoReady = sudo.code === 0;
    } else {
      this.sudoReady = true;
    }

    let server = { kernel: '', hostname: '', os: '', manageFound: false };
    try {
      const info = await this._execRaw(
        `printf '%s\\n' "$(uname -r)" "$(hostname)" "$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | head -1 | tr -d '\\"')"` +
        `; test -f ${shq(profile.managePath)} && echo yes || echo no`,
        { timeout: 15000 },
      );
      const lines = stripAnsi(info.stdout).split('\n');
      server = {
        kernel: (lines[0] || '').trim(),
        hostname: (lines[1] || '').trim(),
        os: (lines[2] || '').trim().replace(/^"|"$/g, ''),
        manageFound: (lines[3] || '').trim() === 'yes',
      };
    } catch (_) { /* informational only */ }
    this.server = server;

    if (!server.manageFound) {
      this.emit('log', {
        level: 'warn',
        text: `На сервере не найден ${profile.managePath}. Проверьте путь в настройках профиля.`,
      });
    }

    this.emit('status', this.status());
    this.emit('log', {
      level: 'info',
      text: `Подключено к ${profile.host}:${profile.port} (${profile.user}), ${this.isRoot ? 'root' : 'sudo'}.`,
    });
    return this.status();
  }

  disconnect() {
    this._closing = true;
    if (this.client) {
      try { this.client.end(); } catch (_) { /* ignore */ }
    }
    this.client = null;
    this.connected = false;
    this.isRoot = false;
    this.sudoReady = false;
    this.sudoPassword = null;
    this.profile = null;
    this.hostKey = null;
    this.server = null;
    this.queue = Promise.resolve();
  }

  async setSudoPassword(password) {
    if (!this.connected) throw new Error('Нет SSH-соединения.');
    if (this.isRoot) { this.sudoReady = true; return true; }
    const res = await this._execRaw(`sudo -k -S -p '' true`, {
      timeout: 20000,
      stdin: `${password}\n`,
      sensitive: true,
    });
    if (res.code !== 0) {
      throw new Error(stripAnsi(res.stderr).trim() || 'sudo отклонил пароль.');
    }
    this.sudoPassword = password;
    this.sudoReady = true;
    this.emit('status', this.status());
    return true;
  }

  _wrap(command) {
    if (this.isRoot) return command;
    if (this.sudoPassword) return `sudo -k -S -p '' bash -c ${shq(command)}`;
    return `sudo -n bash -c ${shq(command)}`;
  }

  _execRaw(command, opts = {}) {
    const client = this.client;
    if (!client || !this.connected) return Promise.reject(new Error('Нет SSH-соединения.'));
    const timeout = opts.timeout || 60000;
    const requestId = opts.requestId || crypto.randomUUID();

    return new Promise((resolve, reject) => {
      let settled = false;
      let timedOut = false;
      let stdout = '';
      let stderr = '';
      let outTruncated = false;
      let errTruncated = false;
      let timer = null;

      const finish = (result) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        resolve(result);
      };

      client.exec(command, (err, stream) => {
        if (err) {
          if (settled) return;
          settled = true;
          if (timer) clearTimeout(timer);
          reject(err);
          return;
        }
        stream.setEncoding('utf8');
        stream.on('data', (chunk) => {
          if (stdout.length < MAX_OUTPUT) {
            const room = MAX_OUTPUT - stdout.length;
            stdout += chunk.length > room ? chunk.slice(0, room) : chunk;
            if (chunk.length > room) outTruncated = true;
          } else {
            outTruncated = true;
          }
          if (opts.stream) this.emit('output', { requestId, stream: 'stdout', chunk: stripAnsi(chunk) });
        });
        stream.stderr.setEncoding('utf8');
        stream.stderr.on('data', (chunk) => {
          if (stderr.length < MAX_OUTPUT) {
            const room = MAX_OUTPUT - stderr.length;
            stderr += chunk.length > room ? chunk.slice(0, room) : chunk;
            if (chunk.length > room) errTruncated = true;
          } else {
            errTruncated = true;
          }
          if (opts.stream) this.emit('output', { requestId, stream: 'stderr', chunk: stripAnsi(chunk) });
        });
        stream.on('close', (code, signal) => {
          finish({
            code: timedOut ? 124 : (typeof code === 'number' ? code : (signal ? 137 : 1)),
            signal: signal || null,
            stdout,
            stderr,
            outTruncated,
            errTruncated,
            timedOut,
            requestId,
          });
        });
        stream.on('error', (e) => {
          if (settled) return;
          settled = true;
          if (timer) clearTimeout(timer);
          reject(e);
        });

        if (opts.stdin != null) stream.write(opts.stdin);
        stream.end();

        if (timeout > 0) {
          timer = setTimeout(() => {
            timedOut = true;
            try { stream.signal('TERM'); } catch (_) { /* ignore */ }
            setTimeout(() => {
              try { stream.close(); } catch (_) { /* ignore */ }
            }, 1500);
          }, timeout);
        }
      });
    });
  }

  _enqueue(fn) {
    const run = () => fn();
    const p = this.queue.then(run, run);
    this.queue = p.then(() => undefined, () => undefined);
    return p;
  }

  async exec(command, opts = {}) {
    return this._enqueue(async () => {
      const started = Date.now();
      const res = await this._execRaw(command, opts);
      const duration = Date.now() - started;
      return {
        ...res,
        duration,
        stdoutText: stripAnsi(res.stdout),
        stderrText: stripAnsi(res.stderr),
      };
    });
  }

  /** Run a project action command. `json` enables tolerant JSON parsing. */
  async runCommand(command, opts = {}) {
    const useSudo = !opts.noSudo;
    const wrapped = useSudo ? this._wrap(command) : command;
    const stdin = (!this.isRoot && this.sudoPassword && useSudo) ? `${this.sudoPassword}\n` : null;
    const res = await this.exec(wrapped, {
      timeout: opts.timeout || 60000,
      requestId: opts.requestId,
      stream: opts.stream !== false,
      stdin,
    });
    let parsed = null;
    if (opts.json) parsed = parseJsonLoose(res.stdoutText);
    return {
      ...res,
      command,
      parsed,
      jsonOk: opts.json ? Boolean(parsed) : null,
      output: clampText(res.stdoutText, 400000).text,
      errorOutput: clampText(res.stderrText, 200000).text,
    };
  }

  async readFile(remotePath, opts = {}) {
    const maxBytes = opts.maxBytes || 4 * 1024 * 1024;
    const cmd = `test -r ${shq(remotePath)} || { echo 'Файл не найден или нет прав на чтение' >&2; exit 1; }; head -c ${maxBytes + 1} -- ${shq(remotePath)} | base64 | tr -d '\\n'`;
    const res = await this.exec(this._wrap(cmd), { timeout: opts.timeout || 45000 });
    if (res.code !== 0) {
      const msg = res.stderrText.trim() || `Не удалось прочитать ${remotePath}`;
      const e = new Error(msg);
      e.code = 'REMOTE_READ';
      throw e;
    }
    const b64 = res.stdoutText.replace(/\s+/g, '');
    const buf = Buffer.from(b64, 'base64');
    const truncated = buf.length > maxBytes;
    return {
      data: truncated ? buf.subarray(0, maxBytes) : buf,
      truncated,
      size: buf.length,
    };
  }

  async readText(remotePath, opts = {}) {
    const r = await this.readFile(remotePath, opts);
    return { text: r.data.toString('utf8'), truncated: r.truncated, size: r.size };
  }

  async fileExists(remotePath) {
    const res = await this.exec(this._wrap(`test -f ${shq(remotePath)} && echo yes || echo no`), { timeout: 15000 });
    return res.stdoutText.trim() === 'yes';
  }

  async listBackups() {
    const dir = path.posix.join(this.profile.awgDir, 'backups');
    const cmd = `find ${shq(dir)} -maxdepth 1 -type f -name 'awg_backup_*.tar.gz' -printf '%f\\t%s\\t%TY-%Tm-%Td %TH:%TM\\n' 2>/dev/null | sort -r`;
    const res = await this.exec(this._wrap(cmd), { timeout: 30000 });
    if (res.code !== 0) return [];
    return res.stdoutText.split('\n').filter(Boolean).map((line) => {
      const [name, size, date] = line.split('\t');
      return { name, size: Number(size) || 0, date: date || '' };
    }).filter((x) => /^awg_backup_.+\.tar\.gz$/.test(x.name));
  }

  async listLogs() {
    const dir = this.profile.awgDir;
    const cmd = `find ${shq(dir)} -maxdepth 1 -type f -name '*.log' -printf '%f\\t%s\\n' 2>/dev/null | sort`;
    const res = await this.exec(this._wrap(cmd), { timeout: 30000 });
    if (res.code !== 0) return [];
    return res.stdoutText.split('\n').filter(Boolean).map((line) => {
      const [name, size] = line.split('\t');
      return { name, size: Number(size) || 0 };
    });
  }

  async tailLog(name, lines = 300) {
    if (!/^[A-Za-z0-9_.-]+\.log$/.test(String(name))) throw new Error('Некорректное имя журнала.');
    const p = path.posix.join(this.profile.awgDir, name);
    const res = await this.exec(this._wrap(`tail -n ${Math.max(1, Math.min(5000, Number(lines) || 300))} -- ${shq(p)}`), { timeout: 30000 });
    if (res.code !== 0) throw new Error(res.stderrText.trim() || 'Не удалось прочитать журнал.');
    return res.stdoutText;
  }

  /** Truncate manage_amneziawg.log. Returns sizes before/after. */
  async clearManageLog() {
    const file = path.posix.join(this.profile.awgDir, 'manage_amneziawg.log');
    if (!(await this.fileExists(file))) throw new Error(`Журнал не найден: ${file}`);
    const cmd = `f=${shq(file)}; s=$(stat -c%s "$f" 2>/dev/null || echo 0); n=$(wc -l < "$f" 2>/dev/null || echo 0); ` +
      `: > "$f"; a=$(stat -c%s "$f" 2>/dev/null || echo 0); printf '%s\\t%s\\t%s\\n' "$s" "$n" "$a"`;
    const res = await this.exec(this._wrap(cmd), { timeout: 30000 });
    if (res.code !== 0) throw new Error(res.stderrText.trim() || 'Не удалось очистить журнал.');
    const [before, lines, after] = res.stdoutText.trim().split('\t');
    return {
      file,
      beforeSize: Number(before) || 0,
      lines: Number(lines) || 0,
      afterSize: Number(after) || 0,
    };
  }

  /** Download a remote file to a local path over SFTP. */
  async downloadFile(remotePath, localPath, onProgress) {
    if (!this.connected || !this.client) throw new Error('Нет SSH-соединения.');
    const client = this.client;
    await new Promise((resolve, reject) => {
      client.sftp((err, sftp) => {
        if (err) { reject(new Error(`SFTP: ${err.message}`)); return; }
        let last = 0;
        sftp.fastGet(remotePath, localPath, {
          step: (transferred, _chunk, total) => {
            const now = Date.now();
            if (onProgress && (now - last > 120 || transferred === total)) {
              last = now;
              onProgress({ transferred, total });
            }
          },
        }, (e) => {
          if (e) reject(new Error(`SFTP: ${e.message}`));
          else resolve();
        });
      });
    });
    return true;
  }
}

module.exports = { SshManager, fingerprint };
