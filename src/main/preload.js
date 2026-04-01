const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('aegisAPI', {
    getSystemStatus: () => ipcRenderer.invoke('get-system-status'),
    getProjects: () => ipcRenderer.invoke('get-projects'),
    openProjectFolder: (path) => ipcRenderer.invoke('open-project-folder', path),
    getTasks: () => ipcRenderer.invoke('get-tasks'),
    addTask: (taskData) => ipcRenderer.invoke('add-task', taskData),
    updateTask: (taskId, taskData) => ipcRenderer.invoke('update-task', taskId, taskData),
    deleteTask: (taskId) => ipcRenderer.invoke('delete-task', taskId),
    getWeather: () => ipcRenderer.invoke('get-weather'),
});
