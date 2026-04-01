# Aegis Home Base - Family Command Center Plan

## Goal
Build an Electron desktop app with a Python Flask backend for a family command center, featuring System Status, Project Launcher, Family Task Board, and Weather Widget, using the VERITAS gold-and-black design. Create at `C:\Veritas_Lab\aegis-home-base`.

## Steps

### Phase 1: Project Setup & Core Structure
1.  Create project directory `C:\Veritas_Lab\aegis-home-base`.
2.  Initialize Node.js project (`package.json`) with Electron.
3.  Install Node.js dependencies (`electron`).
4.  Create `main.js` (Electron main process) to manage window and backend.
5.  Create `preload.js` for secure IPC communication.
6.  Create `index.html` (Electron renderer) as the main UI.
7.  Create `styles.css` with VERITAS gold-and-black theme.
8.  Create `renderer.js` for frontend logic and IPC calls.

### Phase 2: Python Backend Setup
1.  Create Python virtual environment (`.venv`).
2.  Install Python dependencies (`Flask`, `psutil`, `requests`).
3.  Create `backend.py` (Flask app) to serve API endpoints.
    *   System Status: CPU, RAM, Disk usage.
    *   Project Launcher: Scan specified directories for projects.
    *   Family Task Board: SQLite CRUD operations for tasks.
    *   Weather Widget: Proxy `wttr.in` requests.

### Phase 3: Integration & Feature Implementation
1.  Modify `main.js` to launch `backend.py` as a child process.
2.  Implement IPC handlers in `main.js` to bridge `renderer.js` and `backend.py`.
3.  Implement System Status panel in `renderer.js` and `backend.py`.
4.  Implement Project Launcher panel in `renderer.js` and `backend.py`.
5.  Implement Family Task Board (SQLite) in `renderer.js` and `backend.py`.
6.  Implement Weather Widget in `renderer.js` and `backend.py`.
7.  Ensure auto-refresh for System Status and Weather.

### Phase 4: Launch & Verification
1.  Launch the Electron application (`npm start`).
2.  Verify all panels are functional and styled correctly.
