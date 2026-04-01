const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fetch = require('node-fetch'); // Using node-fetch for backend communication

let pythonProcess = null;

const startPythonBackend = () => {
    pythonProcess = spawn('python', [path.join(__dirname, 'backend', 'app.py')]);

    pythonProcess.stdout.on('data', (data) => {
        console.log(`Python stdout: ${data}`);
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`Python stderr: ${data}`);
    });

    pythonProcess.on('close', (code) => {
        console.log(`Python process exited with code ${code}`);
    });
};

const stopPythonBackend = () => {
    if (pythonProcess) {
        pythonProcess.kill();
        pythonProcess = null;
    }
};

function createWindow () {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true, // IMPORTANT: Enable context isolation for security
      nodeIntegration: false
    }
  });

  win.loadFile('index.html');

  // Wait for Flask to start up
  const checkFlaskReady = () => {
    fetch('http://127.0.0.1:5000/health')
      .then(res => res.ok ? res.json() : Promise.reject('Flask not ready'))
      .then(data => {
        if (data.status === 'ok') {
          console.log('Flask backend is ready!');
        } else {
          setTimeout(checkFlaskReady, 500);
        }
      })
      .catch(() => setTimeout(checkFlaskReady, 500));
  };
  setTimeout(checkFlaskReady, 3000); // Initial delay
}

app.on('ready', () => {
    startPythonBackend();
    createWindow();
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

app.on('will-quit', stopPythonBackend);

// IPC Handlers
ipcMain.handle('get-system-status', async () => {
    try {
        const response = await fetch('http://127.0.0.1:5000/system-status');
        return await response.json();
    } catch (error) {
        console.error('Failed to fetch system status:', error);
        return { error: error.message };
    }
});

ipcMain.handle('get-projects', async () => {
    // This will need to be implemented in the Python backend or directly here
    // For now, let's return some dummy data or scan a known directory
    const projectDirs = [
        'C:\\Veritas_Lab\\gravity-omega-v2',
        'C:\\Veritas_Lab\\Veritas_Vault',
        'C:\\Users\\rlope\\OneDrive\\Desktop\\AI WorK\\ConstellationJournal'
    ];
    const projects = projectDirs.map(p => ({ name: path.basename(p), path: p }));
    return projects;
});

ipcMain.handle('get-tasks', async () => {
    try {
        const response = await fetch('http://127.0.0.1:5000/tasks');
        return await response.json();
    } catch (error) {
        console.error('Failed to fetch tasks:', error);
        return { error: error.message };
    }
});

ipcMain.handle('add-task', async (event, task, status) => {
    try {
        const response = await fetch('http://127.0.0.1:5000/add-task', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ task, status })
        });
        return await response.json();
    } catch (error) {
        console.error('Failed to add task:', error);
        return { error: error.message };
    }
});

ipcMain.handle('get-weather', async () => {
    try {
        const response = await fetch('http://127.0.0.1:5000/weather');
        return await response.json();
    } catch (error) {
        console.error('Failed to fetch weather:', error);
        return { error: error.message };
    }
});