'use strict';

const { app, BrowserWindow, ipcMain, dialog, clipboard, shell, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const QRCode = require('qrcode');

const { Store } = require('./lib/store');
const { SshManager } = require('./lib/ssh-manager');
const { buildAction } = require('./lib/actions');
const { validateClientName, validateBackupName, shq } = require('./lib/util');

let win = null;
let store = null;
let ssh = null;
let dataDir = '';
let quitting = false;

function resolveDataDir() {
  const candidates = [];
  if (process.env.PORTABLE_EXECUTABLE_DIR) {
    candidates.push(path.join(process.env.PORTABLE_EXECUTABLE_DIR, 'awg-gui-data'));
  } else if (app.isPackaged) {
    candidates.push(path.join(path.dirname(process.execPath), 'awg-gui-data'));
  } else {
    candidates.push(path.join(__dirname, 'awg-gui-data'));
  }
  // Portable exe may live in a read-only folder (Program Files, mounted image).
  // In that case keep the data in the per-user profile instead of failing to start.
  try { candidates.push(path.join(app.getPath('userData'), 'awg-gui-data')); } catch (_) { /* ignore */ }

  for (const dir of candidates) {
    try {
      fs.mkdirSync(dir, { recursive: true });
      const probe = path.join(dir, `.write-test-${process.pid}`);
      fs.writeFileSync(probe, '');
      fs.unlinkSync(probe);
      return dir;
    } catch (_) { /* try next candidate */ }
  }
  return candidates[candidates.length - 1];
}

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

function appLog(level, text) {
  try { store.log(level, text); } catch (_) { /* ignore */ }
  send('app:log', { level, text, ts: Date.now() });
}

function maskSecrets(text) {
  return String(text || '').replace(
    /^(\s*(?:PrivateKey|PresharedKey|HeaderProtectionKey)\s*=\s*).+$/gim,
    '$1<скрыто>',
  );
}

function createWindow() {
  win = new BrowserWindow({
    width: 1380,
    height: 880,
    minWidth: 1020,
    minHeight: 680,
    backgroundColor: '#0b1220',
    show: false,
    autoHideMenuBar: true,
    title: 'AmneziaWG GUI',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      spellcheck: false,
    },
  });

  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  win.once('ready-to-show', () => win.show());

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });

  win.webContents.on('before-input-event', (event, input) => {
    if (input.type === 'keyDown' && input.key === 'F12') {
      win.webContents.toggleDevTools();
      event.preventDefault();
    }
  });

  win.on('closed', () => { win = null; });
}

function initIpc() {
  ipcMain.handle('app:info', () => ({
    version: app.getVersion(),
    dataDir,
    encryptedProfiles: store.encrypted,
    knownHosts: store.listKnownHosts(),
    logPath: path.join(dataDir, 'awg-gui.log'),
    platform: process.platform,
    electron: process.versions.electron,
    node: process.versions.node,
  }));

  ipcMain.handle('app:open-data-dir', async () => {
    await shell.openPath(dataDir);
    return true;
  });

  ipcMain.handle('profiles:list', () => ({
    profiles: store.listProfiles(),
    encrypted: store.encrypted,
    error: store.lastProfileError || null,
  }));

  ipcMain.handle('profiles:save', (_e, input) => {
    const saved = store.saveProfile(input || {});
    appLog('info', `Профиль сохранён: ${saved.name} (${saved.host}:${saved.port}).`);
    return saved;
  });

  ipcMain.handle('profiles:delete', (_e, id) => {
    const p = store.getProfile(id);
    const ok = store.deleteProfile(id);
    if (ok) appLog('info', `Профиль удалён: ${p ? p.name : id}.`);
    return ok;
  });

  ipcMain.handle('knownhosts:list', () => store.listKnownHosts());

  ipcMain.handle('knownhosts:trust', (_e, { host, port, fingerprint, algorithm }) => {
    store.trustHost(host, port, fingerprint, algorithm);
    appLog('warn', `Доверен новый SSH-ключ ${host}:${port} (${fingerprint}).`);
    return true;
  });

  ipcMain.handle('knownhosts:forget', (_e, { host, port }) => {
    store.forgetHost(host, port);
    appLog('warn', `Отпечаток SSH-ключа удалён: ${host}:${port}.`);
    return true;
  });

  ipcMain.handle('dialog:open-key', async () => {
    const res = await dialog.showOpenDialog(win, {
      title: 'Выберите приватный SSH-ключ',
      properties: ['openFile'],
      filters: [
        { name: 'SSH-ключи', extensions: ['pem', 'key', 'txt', 'ppk', 'openssh'] },
        { name: 'Все файлы', extensions: ['*'] },
      ],
    });
    if (res.canceled || !res.filePaths.length) return null;
    return res.filePaths[0];
  });

  ipcMain.handle('clipboard:write', (_e, text) => {
    clipboard.writeText(String(text == null ? '' : text));
    return true;
  });

  ipcMain.handle('qr:generate', async (_e, { text, size }) => {
    if (!text) throw new Error('Пустой текст для QR-кода.');
    return QRCode.toDataURL(String(text), {
      errorCorrectionLevel: 'M',
      margin: 1,
      width: Math.max(256, Math.min(1024, Number(size) || 640)),
      color: { dark: '#0b1220', light: '#ffffff' },
    });
  });

  ipcMain.handle('ssh:connect', async (_e, { profileId, secrets }) => {
    try {
      const status = await ssh.connect(profileId, secrets || {});
      appLog('info', `Сессия открыта: ${status.host}:${status.port}.`);
      return { ok: true, status };
    } catch (err) {
      if (err.code === 'HOSTKEY_MISMATCH') {
        appLog('error', `Отпечаток SSH-ключа изменился для ${err.hostKey ? err.hostKey.host : ''}.`);
        return { ok: false, code: 'HOSTKEY_MISMATCH', message: err.message, hostKey: err.hostKey };
      }
      appLog('error', `Ошибка подключения: ${err.message}`);
      return { ok: false, code: 'CONNECT_FAILED', message: err.message };
    }
  });

  ipcMain.handle('ssh:disconnect', () => {
    ssh.disconnect();
    send('ssh:status', ssh.status());
    appLog('info', 'Сессия закрыта пользователем.');
    return true;
  });

  ipcMain.handle('ssh:status', () => ssh.status());

  ipcMain.handle('actions:preview', (_e, { action, params }) => {
    try {
      if (!ssh.profile) throw new Error('Нет SSH-соединения.');
      const built = buildAction(action, params || {}, ssh.profile);
      return { ok: true, ...built };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle('ssh:sudo-password', async (_e, { password }) => {
    try {
      await ssh.setSudoPassword(String(password || ''));
      appLog('info', 'Пароль sudo принят (хранится только в памяти).');
      return { ok: true, status: ssh.status() };
    } catch (err) {
      return { ok: false, message: err.message };
    }
  });

  ipcMain.handle('ssh:exec', async (_e, { action, params, requestId }) => {
    const rid = requestId || crypto.randomUUID();
    try {
      if (!ssh.connected) throw new Error('Нет SSH-соединения.');
      const built = buildAction(action, params || {}, ssh.profile);
      send('command:start', { requestId: rid, action, title: built.title, command: built.command, danger: built.danger });
      appLog('info', `Команда [${action}]: ${built.title}`);
      const res = await ssh.runCommand(built.command, {
        json: built.json,
        timeout: built.timeout,
        requestId: rid,
        noSudo: built.raw && params && params.useSudo === false,
        stream: true,
      });
      send('command:end', { requestId: rid, code: res.code, duration: res.duration, parsed: res.parsed });
      return {
        ok: res.code === 0,
        requestId: rid,
        code: res.code,
        duration: res.duration,
        command: built.command,
        title: built.title,
        stdout: res.output,
        stderr: res.errorOutput,
        parsed: res.parsed,
        jsonOk: res.jsonOk,
        truncated: res.outTruncated || res.errTruncated,
        timedOut: res.timedOut,
      };
    } catch (err) {
      send('command:end', { requestId: rid, code: -1, error: err.message });
      appLog('error', `Команда [${action}] не выполнена: ${err.message}`);
      return { ok: false, requestId: rid, error: err.message };
    }
  });

  ipcMain.handle('client:artifacts', async (_e, { name, reveal }) => {
    try {
      validateClientName(name);
      const dir = ssh.profile.awgDir.replace(/\/+$/, '');
      const confPath = `${dir}/${name}.conf`;
      const pngPath = `${dir}/${name}.png`;
      const uriPath = `${dir}/${name}.vpnuri`;
      const uriPngPath = `${dir}/${name}.vpnuri.png`;

      const [conf, png, uri, uriPng] = await Promise.all([
        ssh.readFile(confPath, { maxBytes: 1024 * 1024 }).catch(() => null),
        ssh.readFile(pngPath, { maxBytes: 4 * 1024 * 1024 }).catch(() => null),
        ssh.readFile(uriPath, { maxBytes: 1024 * 1024 }).catch(() => null),
        ssh.readFile(uriPngPath, { maxBytes: 4 * 1024 * 1024 }).catch(() => null),
      ]);

      const rawConf = conf ? conf.data.toString('utf8') : '';
      const rawUri = uri ? uri.data.toString('utf8').trim() : '';
      const shownConf = reveal ? rawConf : maskSecrets(rawConf);

      let qrConf = png ? `data:image/png;base64,${png.data.toString('base64')}` : null;
      if (!qrConf && rawConf) {
        qrConf = await QRCode.toDataURL(rawConf, { errorCorrectionLevel: 'M', margin: 1, width: 720 });
      }
      let qrUri = uriPng ? `data:image/png;base64,${uriPng.data.toString('base64')}` : null;
      if (!qrUri && rawUri) {
        qrUri = await QRCode.toDataURL(rawUri, { errorCorrectionLevel: 'M', margin: 1, width: 720 });
      }

      return {
        ok: true,
        name,
        conf: shownConf,
        confMasked: !reveal,
        hasConf: Boolean(rawConf),
        qrConf,
        qrUri,
        vpnuri: reveal ? rawUri : '',
        vpnuriShown: reveal ? rawUri : (rawUri ? `${rawUri.slice(0, 48)}…` : ''),
        files: {
          conf: Boolean(conf),
          png: Boolean(png),
          vpnuri: Boolean(uri),
          vpnuriPng: Boolean(uriPng),
        },
      };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle('client:download', async (_e, { name, kind }) => {
    try {
      validateClientName(name);
      const dir = ssh.profile.awgDir.replace(/\/+$/, '');
      const map = {
        conf: { file: `${name}.conf`, remote: `${dir}/${name}.conf`, filters: [{ name: 'WireGuard/AmneziaWG config', extensions: ['conf'] }] },
        png: { file: `${name}.png`, remote: `${dir}/${name}.png`, filters: [{ name: 'PNG', extensions: ['png'] }] },
        vpnuri: { file: `${name}.vpnuri`, remote: `${dir}/${name}.vpnuri`, filters: [{ name: 'vpn:// URI', extensions: ['vpnuri', 'txt'] }] },
        vpnuriPng: { file: `${name}.vpnuri.png`, remote: `${dir}/${name}.vpnuri.png`, filters: [{ name: 'PNG', extensions: ['png'] }] },
      };
      const item = map[kind];
      if (!item) throw new Error('Неизвестный тип файла.');
      const data = await ssh.readFile(item.remote, { maxBytes: 8 * 1024 * 1024 });
      const res = await dialog.showSaveDialog(win, {
        title: 'Сохранить файл клиента',
        defaultPath: item.file,
        filters: item.filters,
      });
      if (res.canceled || !res.filePath) return { ok: false, canceled: true };
      fs.writeFileSync(res.filePath, data.data);
      appLog('info', `Скачан файл клиента ${name}: ${res.filePath}`);
      return { ok: true, path: res.filePath };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle('server:settings', async (_e, { reveal }) => {
    try {
      const check = await ssh.runCommand(
        `bash ${shq(ssh.profile.managePath)} check --json`,
        { json: true, timeout: 90000, stream: false },
      ).catch((e) => ({ code: -1, parsed: null, errorOutput: e.message, output: '' }));

      const serverConfPath = '/etc/amnezia/amneziawg/awg0.conf';
      const initPath = `${ssh.profile.awgDir.replace(/\/+$/, '')}/awgsetup_cfg.init`;
      const [serverConf, init] = await Promise.all([
        ssh.readText(serverConfPath, { maxBytes: 2 * 1024 * 1024 }).catch((e) => ({ text: `Не удалось прочитать: ${e.message}`, truncated: false })),
        ssh.readText(initPath, { maxBytes: 1024 * 1024 }).catch((e) => ({ text: `Не удалось прочитать: ${e.message}`, truncated: false })),
      ]);

      const snapshotCmd = [
        "echo '### SYSTEM'; uname -a; uptime",
        "echo '### MEMORY'; free -h",
        "echo '### DISK'; df -h /",
        "echo '### AWG'; awg --version 2>&1; echo -n 'module: '; cat /sys/module/amneziawg/version 2>/dev/null || echo 'n/a'",
        "echo '### DKMS'; dkms status 2>&1 | head -20",
        "echo '### SERVICE'; systemctl is-active awg-quick@awg0 2>&1; systemctl show -p ActiveEnterTimestamp --value awg-quick@awg0 2>&1",
        "echo '### UFW'; ufw status verbose 2>&1",
        "echo '### LISTEN'; ss -lunp 2>/dev/null | head -30",
        "echo '### INTERFACE'; ip -brief addr show awg0 2>&1",
        "echo '### SYSCTL'; sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.core.default_qdisc net.ipv4.tcp_congestion_control 2>&1",
        "echo '### CRON'; tail -5 /etc/cron.d/awg-expiry 2>/dev/null || echo 'n/a'",
      ].join('; ');

      const snapshot = await ssh.runCommand(snapshotCmd, { timeout: 90000, stream: false }).catch((e) => ({
        code: -1,
        output: '',
        errorOutput: e.message,
      }));

      return {
        ok: true,
        check: check.parsed,
        checkError: check.parsed ? null : (check.errorOutput || check.output || 'check не вернул JSON'),
        serverConf: reveal ? serverConf.text : maskSecrets(serverConf.text),
        serverConfMasked: !reveal,
        init: reveal ? init.text : maskSecrets(init.text),
        initMasked: !reveal,
        snapshot: snapshot.output || snapshot.errorOutput || '',
      };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle('server:logs', async () => {
    try {
      const logs = await ssh.listLogs();
      return { ok: true, logs };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle('server:tail-log', async (_e, { name, lines }) => {
    try {
      const text = await ssh.tailLog(name, lines);
      return { ok: true, text };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle('server:backups', async () => {
    try {
      const backups = await ssh.listBackups();
      return { ok: true, backups };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle('maintenance:clear-log', async () => {
    try {
      if (!ssh.connected) throw new Error('Нет SSH-соединения.');
      const res = await ssh.clearManageLog();
      appLog('warn', `Журнал manage_amneziawg.log очищен (освобождено ${res.beforeSize} байт).`);
      return { ok: true, ...res };
    } catch (err) {
      appLog('error', `Не удалось очистить журнал: ${err.message}`);
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle('maintenance:download-backup', async (_e, { name }) => {
    try {
      if (!ssh.connected) throw new Error('Нет SSH-соединения.');
      const file = validateBackupName(name);
      const remote = `${ssh.profile.awgDir.replace(/\/+$/, '')}/backups/${file}`;
      const res = await dialog.showSaveDialog(win, {
        title: 'Сохранить резервную копию',
        defaultPath: path.join(app.getPath('downloads'), file),
        filters: [{ name: 'Архив AmneziaWG', extensions: ['gz', 'tgz'] }],
      });
      if (res.canceled || !res.filePath) return { ok: false, canceled: true };
      if (ssh.isRoot) {
        await ssh.downloadFile(remote, res.filePath, ({ transferred, total }) => {
          send('backup:progress', { name: file, transferred, total });
        });
      } else {
        const data = await ssh.readFile(remote, { maxBytes: 6 * 1024 * 1024 });
        if (data.truncated) throw new Error('Архив больше 6 МБ: скачайте его вручную или подключитесь как root.');
        fs.writeFileSync(res.filePath, data.data);
      }
      const stat = fs.statSync(res.filePath);
      if (!stat.size) throw new Error('Получен пустой файл.');
      appLog('info', `Бэкап скачан: ${file} → ${res.filePath} (${stat.size} байт).`);
      return { ok: true, path: res.filePath, size: stat.size };
    } catch (err) {
      appLog('error', `Не удалось скачать бэкап: ${err.message}`);
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle('app:open-external', async (_e, url) => {
    const allowed = new Set(['github.com', 'bivlked.github.io', 'pay.cloudtips.ru', 'amnezia.org']);
    let parsed;
    try { parsed = new URL(String(url)); } catch (_) { return false; }
    if (parsed.protocol !== 'https:' || !allowed.has(parsed.hostname)) return false;
    await shell.openExternal(parsed.toString());
    return true;
  });

  ipcMain.handle('file:save', async (_e, { dataUrl, text, defaultName, filters }) => {
    const res = await dialog.showSaveDialog(win, {
      title: 'Сохранить файл',
      defaultPath: defaultName || 'download.txt',
      filters: filters || [{ name: 'Все файлы', extensions: ['*'] }],
    });
    if (res.canceled || !res.filePath) return { ok: false };
    try {
      if (typeof dataUrl === 'string' && dataUrl.startsWith('data:')) {
        const m = dataUrl.match(/^data:[^;]+;base64,(.*)$/s);
        if (!m) throw new Error('Некорректные данные файла.');
        fs.writeFileSync(res.filePath, Buffer.from(m[1], 'base64'));
      } else {
        fs.writeFileSync(res.filePath, String(text == null ? '' : text), 'utf8');
      }
      appLog('info', `Файл сохранён: ${res.filePath}`);
      return { ok: true, path: res.filePath };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  });
}

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (win) {
      if (win.isMinimized()) win.restore();
      win.focus();
    }
  });

  app.whenReady().then(() => {
    dataDir = resolveDataDir();
    store = new Store(dataDir).init();
    ssh = new SshManager(store, (event, payload) => {
      if (event === 'log') {
        appLog(payload.level || 'info', payload.text || '');
      } else if (event === 'status') {
        send('ssh:status', payload);
      } else if (event === 'output') {
        send('ssh:output', payload);
      }
    });
    Menu.setApplicationMenu(null);
    initIpc();
    createWindow();
    appLog('info', `AmneziaWG GUI ${app.getVersion()} запущен. Данные: ${dataDir}`);

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });

  app.on('before-quit', () => {
    quitting = true;
    if (ssh) ssh.disconnect();
  });
}

module.exports = { maskSecrets };
