const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('aegis', {
    get: (endpoint) => ipcRenderer.invoke('backend:get', endpoint),
    post: (endpoint, data) => ipcRenderer.invoke('backend:post', endpoint, data),
    put: (endpoint, data) => ipcRenderer.invoke('backend:put', endpoint, data),
    del: (endpoint) => ipcRenderer.invoke('backend:delete', endpoint),
    openFolder: (folderPath) => ipcRenderer.invoke('open-folder', folderPath),
    openTaskManager: () => ipcRenderer.invoke('open-task-manager'),
    openSettings: (page) => ipcRenderer.invoke('open-settings', page),
    openTerminal: (path) => ipcRenderer.invoke('open-terminal', path),
    openInEditor: (filePath, line) => ipcRenderer.invoke('open-in-editor', filePath, line),
    loadSettings: () => ipcRenderer.invoke('settings:load'),
    saveSettings: (settings) => ipcRenderer.invoke('settings:save', settings),
    notify: (title, body) => ipcRenderer.invoke('notify:send', title, body),
    setAutoStart: (enabled) => ipcRenderer.invoke('autostart:set', enabled),
    getAutoStart: () => ipcRenderer.invoke('autostart:get'),
    isWindowVisible: () => ipcRenderer.invoke('window:isVisible'),
    exportPDF: (data) => ipcRenderer.invoke('report:export', data),
});
