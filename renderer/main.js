const { ipcRenderer } = require('electron');

function updateSystemStatus() {
  fetch('http://localhost:5000/system-status')
    .then(response => response.json())
    .then(data => {
      document.getElementById('cpu').innerText = `CPU: ${data.cpu}%`;
      document.getElementById('ram').innerText = `RAM: ${data.ram}%`;
      document.getElementById('disk').innerText = `Disk: ${data.disk}%`;
    });
}

function launchProject(projectPath) {
  require('shell').openPath(projectPath);
}

function addTask(task, assignee) {
  const taskBoard = document.getElementById('task-board');
  const column = document.createElement('div');
  column.className = `column ${assignee}`;
  const card = document.createElement('div');
  card.innerText = task;
  column.appendChild(card);
  taskBoard.appendChild(column);
}

// Auto-refresh system status every 5 seconds
setInterval(updateSystemStatus, 5000);