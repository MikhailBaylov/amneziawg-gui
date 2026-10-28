'use strict';

const { contextBridge, ipcRenderer } = require('electron');

function subscribe(channel, cb) {
  const handler = (_event, payload) => cb(payload);
  ipcRenderer.on(channel, handler);
  return () => ipcRenderer.removeListener(channel, handler);
}

contextBridge.exposeInMainWorld('api', {
  info: () => ipcRenderer.invoke('app:info'),
  openDataDir: () => ipcRenderer.invoke('app:open-data-dir'),

  listProfiles: () => ipcRenderer.invoke('profiles:list'),
  saveProfile: (profile) => ipcRenderer.invoke('profiles:save', profile),
  deleteProfile: (id) => ipcRenderer.invoke('profiles:delete', id),

  listKnownHosts: () => ipcRenderer.invoke('knownhosts:list'),
  trustHost: (data) => ipcRenderer.invoke('knownhosts:trust', data),
  forgetHost: (data) => ipcRenderer.invoke('knownhosts:forget', data),

  openKeyDialog: () => ipcRenderer.invoke('dialog:open-key'),
  copy: (text) => ipcRenderer.invoke('clipboard:write', text),
  generateQr: (text, size) => ipcRenderer.invoke('qr:generate', { text, size }),

  connect: (profileId, secrets) => ipcRenderer.invoke('ssh:connect', { profileId, secrets: secrets || {} }),
  disconnect: () => ipcRenderer.invoke('ssh:disconnect'),
  status: () => ipcRenderer.invoke('ssh:status'),
  setSudoPassword: (password) => ipcRenderer.invoke('ssh:sudo-password', { password }),

  exec: (action, params, requestId) => ipcRenderer.invoke('ssh:exec', { action, params, requestId }),
  preview: (action, params) => ipcRenderer.invoke('actions:preview', { action, params }),
  artifacts: (name, reveal) => ipcRenderer.invoke('client:artifacts', { name, reveal: Boolean(reveal) }),
  downloadClient: (name, kind) => ipcRenderer.invoke('client:download', { name, kind }),
  serverSettings: (reveal) => ipcRenderer.invoke('server:settings', { reveal: Boolean(reveal) }),
  logs: () => ipcRenderer.invoke('server:logs'),
  tailLog: (name, lines) => ipcRenderer.invoke('server:tail-log', { name, lines }),
  backups: () => ipcRenderer.invoke('server:backups'),
  clearManageLog: () => ipcRenderer.invoke('maintenance:clear-log'),
  downloadBackup: (name) => ipcRenderer.invoke('maintenance:download-backup', { name }),
  openExternal: (url) => ipcRenderer.invoke('app:open-external', url),

  saveFile: (opts) => ipcRenderer.invoke('file:save', opts),

  onOutput: (cb) => subscribe('ssh:output', cb),
  onStatus: (cb) => subscribe('ssh:status', cb),
  onLog: (cb) => subscribe('app:log', cb),
  onCommandStart: (cb) => subscribe('command:start', cb),
  onCommandEnd: (cb) => subscribe('command:end', cb),
  onBackupProgress: (cb) => subscribe('backup:progress', cb),
});
