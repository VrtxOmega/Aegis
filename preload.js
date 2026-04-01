const { contextBridge, ipcRenderer, shell } = require('electron');

contextBridge.exposeInMainWorld('aegis', {
    getSystemStatus: () => ipcRenderer.invoke('get-system-status'),
    getProjects: () => ipcRenderer.invoke('get-projects'),
    openProjectFolder: (path) => shell.openPath(path),
    getTasks: () => ipcRenderer.invoke('get-tasks'),
    addTask: (task, status) => ipcRenderer.invoke('add-task', task, status),
    getWeather: () => ipcRenderer.invoke('get-weather')
});