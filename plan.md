# Aegis Home Base - Implementation Plan

## Goal
Build an Electron desktop application with a Python Flask backend, featuring four panels: System Status, Project Launcher, Family Task Board, and Weather Widget, all styled with the VERITAS gold-and-black theme. The application will be located at `C:\Veritas_Lab\aegis-home-base`.

## Steps

### Phase 1: Project Setup & Dependencies
1.  Create the base project directory: `C:\Veritas_Lab\aegis-home-base`.
2.  Initialize Node.js project (`npm init -y`).
3.  Install Electron and `psutil-node` (for system status) as Node.js dependencies.
4.  Create `backend` subdirectory.
5.  Create `backend/requirements.txt`.
6.  Install Python dependencies (`flask`, `flask-cors`, `psutil`, `requests`, `sqlite3`).

### Phase 2: Backend Development (Flask)
1.  Create `backend/app.py`.
2.  Implement Flask application with `CORS`.
3.  Add `init_db()` function for SQLite task board, using `PRAGMA journal_mode=WAL` and `CREATE TABLE IF NOT EXISTS`.
4.  Implement `/api/health` endpoint.
5.  Implement `/api/system/status` endpoint using `psutil` for CPU, RAM, Disk.
6.  Implement `/api/projects` endpoint to scan `C:\Veritas_Lab` and `C:\Users\rlope\OneDrive\Desktop` for project markers (`package.json` or `requirements.txt`).
7.  Implement `/api/tasks` (GET, POST) and `/api/tasks/<id>` (PUT, DELETE) endpoints for the task board.
8.  Implement `/api/weather` endpoint to fetch data from `wttr.in` for Bethalto, IL.
9.  Add port killing logic for Flask before `app.run()`.

### Phase 3: Frontend Development (Electron)
1.  Create `main.js` (Electron main process).
    *   Spawn Flask backend, poll `/api/health` until ready.
    *   Create `BrowserWindow` with `preload.js`.
    *   Set up `ipcMain.handle` for `get`, `post`, `put`, `del` to communicate with Flask.
    *   Implement `openProjectFolder` IPC handler using `child_process.exec`.
2.  Create `preload.js` (Electron preload script).
    *   Expose `get`, `post`, `put`, `del` methods via `contextBridge` to `window.aegis`.
    *   Expose `openProjectFolder` method.
3.  Create `index.html` (main UI).
    *   Define structure for the four panels.
    *   Link `styles.css` and `renderer.js`.
    *   Set appropriate `Content-Security-Policy`.
4.  Create `renderer.js` (frontend logic).
    *   Call `window.aegis` methods to fetch data for each panel.
    *   Update DOM elements with fetched data.
    *   Implement auto-refresh for System Status.
    *   Implement task board UI and interaction (add, update, delete tasks).
    *   Implement project launcher UI and interaction (open folder).
5.  Create `styles.css`.
    *   Apply VERITAS gold-and-black color palette and styling.

### Phase 4: Launch & Verification
1.  Start the Flask backend.
2.  Launch the Electron application (`npm start`).
3.  Verify all four panels are functional and styled correctly.
