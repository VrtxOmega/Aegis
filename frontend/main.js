const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
let pythonProcess = null;

const startPythonBackend = () => {
  if (pythonProcess) {
    console.log('Python backend already running.');
    return;
  }
  const backendPath = path.join(__dirname, '..', 'backend', 'app.py');
  console.log(`Attempting to start Python backend at: ${backendPath}`);
  pythonProcess = spawn('python', [backendPath], {
    cwd: path.join(__dirname, '..', 'backend'),
    stdio: ['pipe', 'pipe', 'pipe'] // Capture stdout and stderr
  });

  pythonProcess.stdout.on('data', (data) => {
    console.log(`Python stdout: ${data}`);
  });

  pythonProcess.stderr.on('data', (data) => {
    console.error(`Python stderr: ${data}`);
  });

  pythonProcess.on('close', (code) => {
    console.log(`Python backend exited with code ${code}`);
    pythonProcess = null; // Reset process on close
  });

  pythonProcess.on('error', (err) => {
    console.error('Failed to start Python backend:', err);
    pythonProcess = null;
  });
};

const stopPythonBackend = () => {
  if (pythonProcess) {
    console.log('Stopping Python backend...');
    pythonProcess.kill('SIGINT'); // Send interrupt signal
    pythonProcess = null;
  }
};

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    icon: path.join(__dirname, 'assets', 'aegis_icon.png'), // Placeholder for an icon
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  // mainWindow.webContents.openDevTools(); // Uncomment for debugging

  // IPC Handlers
  ipcMain.handle('get-system-status', async () => {
    try {
      const response = await fetch('http://127.0.0.1:5000/api/system-status');
      return await response.json();
    } catch (error) {
      console.error('Failed to fetch system status:', error);
      return { error: error.message };
    }
  });

  ipcMain.handle('get-projects', async () => {
    try {
      const response = await fetch('http://127.0.0.1:5000/api/projects');
      return await response.json();
    } catch (error) {
      console.error('Failed to fetch projects:', error);
      return { error: error.message };
    }
  });

  ipcMain.handle('open-project-folder', async (event, projectPath) => {
    try {
      await shell.openPath(projectPath);
      return { success: true };
    } catch (error) {
      console.error('Failed to open project folder:', error);
      return { error: error.message };
    }
  });

  ipcMain.handle('get-tasks', async () => {
    try {
      const response = await fetch('http://127.0.0.1:5000/api/tasks');
      return await response.json();
    } catch (error) {
      console.error('Failed to fetch tasks:', error);
      return { error: error.message };
    }
  });

  ipcMain.handle('add-task', async (event, task) => {
    try {
      const response = await fetch('http://127.0.0.1:5000/api/tasks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(task)
      });
      return await response.json();
    } catch (error) {
      console.error('Failed to add task:', error);
      return { error: error.message };
    }
  });

  ipcMain.handle('update-task-status', async (event, taskId, newStatus) => {
    try {
      const response = await fetch(`http://127.0.0.1:5000/api/tasks/${taskId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      return await response.json();
    } catch (error) {
      console.error('Failed to update task status:', error);
      return { error: error.message };
    }
  });

  ipcMain.handle('delete-task', async (event, taskId) => {
    try {
      const response = await fetch(`http://127.0.0.1:5000/api/tasks/${taskId}`, {
        method: 'DELETE'
      });
      return await response.json();
    } catch (error) {
      console.error('Failed to delete task:', error);
      return { error: error.message };
    }
  });

  ipcMain.handle('get-weather', async () => {
    try {
      const response = await fetch('http://127.0.0.1:5000/api/weather');
      return await response.json();
    } catch (error) {
      console.error('Failed to fetch weather:', error);
      return { error: error.message };
    }
  });
}

app.whenReady().then(() => {
  startPythonBackend();
  setTimeout(createWindow, 3000); // Give Flask a moment to start
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

app.on('before-quit', () => {
  stopPythonBackend();
});
