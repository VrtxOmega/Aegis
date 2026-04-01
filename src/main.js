const { app, BrowserWindow, ipcMain, shell, Menu, screen, Tray, nativeImage, Notification, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

let mainWindow;
let flaskProcess;
let tray = null;
let isQuitting = false;

const FLASK_PORT = 5000;
const FLASK_URL = `http://127.0.0.1:${FLASK_PORT}`;

// ─── Window State Persistence ───
const STATE_FILE = path.join(app.getPath('userData'), 'window-state.json');
const SETTINGS_FILE = path.join(app.getPath('userData'), 'aegis-settings.json');

function loadWindowState() {
    try {
        if (fs.existsSync(STATE_FILE)) {
            return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
        }
    } catch (e) { console.warn('Could not load window state:', e); }
    return null;
}

function saveWindowState() {
    if (!mainWindow) return;
    try {
        const bounds = mainWindow.getBounds();
        const isMaximized = mainWindow.isMaximized();
        fs.writeFileSync(STATE_FILE, JSON.stringify({ bounds, isMaximized }), 'utf8');
    } catch (e) { console.warn('Could not save window state:', e); }
}

function loadSettings() {
    try {
        if (fs.existsSync(SETTINGS_FILE)) {
            return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
        }
    } catch (e) { console.warn('Could not load settings:', e); }
    return {};
}

function saveSettings(settings) {
    try {
        const existing = loadSettings();
        const merged = { ...existing, ...settings };
        fs.writeFileSync(SETTINGS_FILE, JSON.stringify(merged, null, 2), 'utf8');
        return merged;
    } catch (e) { console.warn('Could not save settings:', e); return {}; }
}

// ─── System Tray ───
function createTray() {
    const iconPath = path.join(__dirname, 'assets', 'icon.ico');
    let trayIcon;
    try {
        trayIcon = nativeImage.createFromPath(iconPath);
    } catch (e) {
        // Fallback: create a simple 16x16 icon
        trayIcon = nativeImage.createEmpty();
    }

    tray = new Tray(trayIcon);
    tray.setToolTip('Aegis — System Security');

    const contextMenu = Menu.buildFromTemplate([
        {
            label: 'Show Aegis',
            click: () => {
                if (mainWindow) {
                    mainWindow.show();
                    mainWindow.focus();
                }
            }
        },
        { type: 'separator' },
        {
            label: 'Quit',
            click: () => {
                isQuitting = true;
                app.quit();
            }
        }
    ]);

    tray.setContextMenu(contextMenu);

    tray.on('double-click', () => {
        if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
        }
    });
}

function createWindow() {
    const saved = loadWindowState();
    const defaults = { width: 1400, height: 900, x: undefined, y: undefined };
    const bounds = saved?.bounds || defaults;

    // Validate saved position is still on a visible display
    if (bounds.x !== undefined && bounds.y !== undefined) {
        const displays = screen.getAllDisplays();
        const visible = displays.some(d => {
            const b = d.bounds;
            return bounds.x >= b.x && bounds.x < b.x + b.width &&
                   bounds.y >= b.y && bounds.y < b.y + b.height;
        });
        if (!visible) { bounds.x = undefined; bounds.y = undefined; }
    }

    mainWindow = new BrowserWindow({
        width: bounds.width || 1400,
        height: bounds.height || 900,
        x: bounds.x,
        y: bounds.y,
        minWidth: 1000,
        minHeight: 700,
        autoHideMenuBar: true,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            enableRemoteModule: false,
        },
        icon: path.join(__dirname, 'assets', 'icon.ico')
    });

    if (saved?.isMaximized) mainWindow.maximize();

    // Save window state on move/resize
    mainWindow.on('resize', saveWindowState);
    mainWindow.on('move', saveWindowState);

    // Close-to-tray: intercept close event
    mainWindow.on('close', (e) => {
        saveWindowState();
        if (!isQuitting) {
            const settings = loadSettings();
            if (settings.closeToTray) {
                e.preventDefault();
                mainWindow.hide();
                return;
            }
        }
        // If not close-to-tray or isQuitting, let it close normally
    });

    // Remove default menu bar
    Menu.setApplicationMenu(null);

    mainWindow.loadFile(path.join(__dirname, 'index.html'));

    // Open the DevTools.
    // mainWindow.webContents.openDevTools();
}

function startFlaskBackend() {
    // Resolve backend path for both dev and packaged modes
    const backendPath = app.isPackaged
        ? path.join(process.resourcesPath, 'backend')
        : path.join(__dirname, '..', 'backend');
    
    // Use venv Python if available, fall back to system python
    const venvPython = path.join(backendPath, 'venv', 'Scripts', 'python.exe');
    const pythonExe = fs.existsSync(venvPython) ? venvPython : 'python';
    
    flaskProcess = spawn(pythonExe, ['app.py'], { cwd: backendPath, stdio: ['ignore', 'pipe', 'pipe'] });

    flaskProcess.stdout.on('data', (data) => {
        console.log(`Flask stdout: ${data}`);
    });

    flaskProcess.stderr.on('data', (data) => {
        console.error(`Flask stderr: ${data}`);
    });

    flaskProcess.on('close', (code) => {
        console.log(`Flask process exited with code ${code}`);
    });

    flaskProcess.on('error', (err) => {
        console.error('Failed to start Flask process:', err);
    });
}

async function pollFlaskHealth() {
    let retries = 0;
    const maxRetries = 20; // 20 retries * 500ms = 10 seconds

    while (retries < maxRetries) {
        try {
            const response = await fetch(`${FLASK_URL}/api/health`);
            if (response.ok) {
                console.log('Flask backend is healthy. Creating window.');
                createWindow();
                return;
            }
        } catch (error) {
            // Flask not ready yet
        }
        retries++;
        await new Promise(resolve => setTimeout(resolve, 500));
    }
    console.error('Flask backend did not become healthy in time. Exiting.');
    app.quit();
}

app.whenReady().then(() => {
    createTray();
    startFlaskBackend();
    pollFlaskHealth();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    // Don't quit when all windows close — tray keeps the app alive
    // Only quit via tray menu or explicit app.quit()
    const settings = loadSettings();
    if (!settings.closeToTray) {
        if (process.platform !== 'darwin') {
            isQuitting = true;
            app.quit();
        }
    }
});

app.on('will-quit', () => {
    if (flaskProcess) {
        console.log('Terminating Flask process...');
        flaskProcess.kill();
    }
    if (tray) {
        tray.destroy();
        tray = null;
    }
});

// ─── IPC Handlers: Backend Communication ───

ipcMain.handle('backend:get', async (event, endpoint) => {
    try {
        const response = await fetch(`${FLASK_URL}${endpoint}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error(`Backend GET error for ${endpoint}:`, error);
        return { error: error.message };
    }
});

ipcMain.handle('backend:post', async (event, endpoint, data) => {
    try {
        const response = await fetch(`${FLASK_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error(`Backend POST error for ${endpoint}:`, error);
        return { error: error.message };
    }
});

ipcMain.handle('backend:put', async (event, endpoint, data) => {
    try {
        const response = await fetch(`${FLASK_URL}${endpoint}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error(`Backend PUT error for ${endpoint}:`, error);
        return { error: error.message };
    }
});

ipcMain.handle('backend:delete', async (event, endpoint) => {
    try {
        const response = await fetch(`${FLASK_URL}${endpoint}`, {
            method: 'DELETE',
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error(`Backend DELETE error for ${endpoint}:`, error);
        return { error: error.message };
    }
});

// ─── IPC Handlers: OS Integration ───

ipcMain.handle('open-folder', async (event, folderPath) => {
    try {
        await shell.openPath(folderPath);
        return { success: true };
    } catch (error) {
        console.error(`Failed to open folder ${folderPath}:`, error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('open-task-manager', async () => {
    try {
        spawn('taskmgr.exe', [], { detached: true, stdio: 'ignore' }).unref();
        return { success: true };
    } catch (error) {
        console.error('Failed to open Task Manager:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('open-settings', async (event, page) => {
    const pages = {
        'battery': 'ms-settings:batterysaver',
        'storage': 'ms-settings:storagesense',
        'display': 'ms-settings:display',
        'network': 'ms-settings:network',
        'power': 'ms-settings:powersleep',
    };
    const uri = pages[page] || `ms-settings:${page}`;
    try {
        await shell.openExternal(uri);
        return { success: true };
    } catch (error) {
        console.error(`Failed to open settings ${page}:`, error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('open-terminal', async (event, dirPath) => {
    try {
        try {
            spawn('wt.exe', ['-d', dirPath], { detached: true, stdio: 'ignore' }).unref();
        } catch {
            spawn('cmd.exe', ['/k', `cd /d "${dirPath}"`], { detached: true, stdio: 'ignore' }).unref();
        }
        return { success: true };
    } catch (error) {
        console.error(`Failed to open terminal at ${dirPath}:`, error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('open-in-editor', async (event, filePath, line) => {
    try {
        // VS Code supports --goto file:line to jump directly to the issue
        const gotoArg = line ? `${filePath}:${line}` : filePath;
        spawn('code', ['--goto', gotoArg], { detached: true, stdio: 'ignore', shell: true }).unref();
        return { success: true };
    } catch (error) {
        // Fallback: open in default editor via shell
        try {
            shell.openPath(filePath);
            return { success: true, fallback: true };
        } catch (e2) {
            console.error(`Failed to open ${filePath} in editor:`, e2);
            return { success: false, error: e2.message };
        }
    }
});

// ─── IPC Handlers: Settings Persistence ───

ipcMain.handle('settings:load', async () => {
    return loadSettings();
});

ipcMain.handle('settings:save', async (event, settings) => {
    return saveSettings(settings);
});

// ─── IPC Handlers: Notifications ───

ipcMain.handle('notify:send', async (event, title, body) => {
    try {
        const notification = new Notification({
            title: title || 'Aegis',
            body: body || '',
            icon: path.join(__dirname, 'assets', 'icon.ico'),
        });
        notification.on('click', () => {
            if (mainWindow) {
                mainWindow.show();
                mainWindow.focus();
                // Tell renderer to switch to threats tab
                mainWindow.webContents.send('navigate-tab', 'threats');
            }
        });
        notification.show();
        return { success: true };
    } catch (error) {
        console.error('Failed to show notification:', error);
        return { success: false, error: error.message };
    }
});

// ─── IPC Handlers: Auto-Start ───

ipcMain.handle('autostart:set', async (event, enabled) => {
    try {
        app.setLoginItemSettings({
            openAtLogin: enabled,
            openAsHidden: true, // Start minimized to tray
        });
        return { success: true };
    } catch (error) {
        console.error('Failed to set auto-start:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('autostart:get', async () => {
    try {
        const settings = app.getLoginItemSettings();
        return { openAtLogin: settings.openAtLogin };
    } catch (error) {
        return { openAtLogin: false };
    }
});

// ─── IPC Handlers: Window State ───

ipcMain.handle('window:isVisible', async () => {
    if (!mainWindow) return false;
    return mainWindow.isVisible() && mainWindow.isFocused();
});

// ─── IPC Handlers: PDF Report Export ───

ipcMain.handle('report:export', async (event, reportData) => {
    try {
        // Step 1: Generate PDF via backend
        const response = await fetch(`${FLASK_URL}/api/report/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(reportData),
        });

        if (!response.ok) {
            throw new Error(`Report generation failed: ${response.status}`);
        }

        const result = await response.json();
        if (result.status !== 'success' || !result.path) {
            throw new Error(result.error || 'PDF generation returned no path');
        }

        const generatedPath = result.path;

        // Step 2: Show save dialog
        const { canceled, filePath: savePath } = await dialog.showSaveDialog(mainWindow, {
            title: 'Save Aegis Report',
            defaultPath: path.join(app.getPath('desktop'), result.filename),
            filters: [{ name: 'PDF Documents', extensions: ['pdf'] }],
        });

        if (canceled || !savePath) {
            return { success: true, action: 'cancelled', path: generatedPath };
        }

        // Step 3: Copy to user-chosen location
        fs.copyFileSync(generatedPath, savePath);

        // Step 4: Open the PDF
        shell.openPath(savePath);

        return { success: true, path: savePath, size_bytes: result.size_bytes };
    } catch (error) {
        console.error('Report export error:', error);
        return { success: false, error: error.message };
    }
});
