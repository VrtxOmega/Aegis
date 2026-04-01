const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('aegis', {
  getSystemStatus: () => ipcRenderer.invoke('get-system-status'),
  getProjects: () => ipcRenderer.invoke('get-projects'),
  openProjectFolder: (projectPath) => ipcRenderer.invoke('open-project-folder', projectPath),
  getTasks: () => ipcRenderer.invoke('get-tasks'),
  addTask: (task) => ipcRenderer.invoke('add-task', task),
  updateTaskStatus: (taskId, newStatus) => ipcRenderer.invoke('update-task-status', taskId, newStatus),
  deleteTask: (taskId) => ipcRenderer.invoke('delete-task', taskId),
  getWeather: () => ipcRenderer.invoke('get-weather')
});
