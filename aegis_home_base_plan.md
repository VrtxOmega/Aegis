# Aegis Home Base - Family Command Center Plan

## Goal
Build an Electron desktop application with a Python Flask backend, named "Aegis Home Base", located at `C:\Veritas_Lab\aegis-home-base`. It will feature four panels: System Status, Project Launcher, Family Task Board (Kanban with SQLite persistence), and a Weather Widget. The design will adhere to the VERITAS gold-and-black palette.

## Steps

### 1. Project Setup & Directory Structure
- Create the root directory: `C:\Veritas_Lab\aegis-home-base`
- Create subdirectories: `frontend` and `backend`
- Create `package.json` in the root for Node.js/Electron dependencies.

### 2. Dependency Installation
- Install Electron: `npm install electron --prefix C:\Veritas_Lab\aegis-home-base`
- Install Flask, `psutil` (for system status), and `requests` (for weather/API calls) for Windows Python: `pip install flask psutil requests`

### 3. Backend Development (Flask - `backend/app.py`)
- Initialize Flask app.
- Implement `init_db()` function for SQLite tasks, ensuring it's idempotent (`CREATE TABLE IF NOT EXISTS`). Call this at app startup.
- Create API endpoints for:
    - **System Status:** Fetch CPU, RAM, Disk usage using `psutil`.
    - **Project Launcher:** Scan `C:\Veritas_Lab` for project directories (look for `package.json`, `requirements.txt`, `main.js`, `app.py`).
    - **Family Task Board:** CRUD operations for tasks (To Do, In Progress, Done) stored in `tasks.db`.
    - **Weather Widget:** Fetch data from `wttr.in`.
- Implement error handling and consistent JSON responses (C1, C2, C5).

### 4. Frontend Development (Electron)
- **`frontend/main.js` (Main Process):**
    - Create `BrowserWindow`.
    - Set `preload.js` for secure IPC (D5, H1).
    - Start the Flask backend process (using `subprocess` in Python, or `spawn` in Node.js, ensuring it runs on Windows Python).
    - Add a delay before creating the window to allow Flask to start (C3).
    - Handle IPC communication with the renderer process.
- **`frontend/preload.js` (Preload Script):**
    - Expose `contextBridge` APIs for renderer to interact with main process (e.g., `window.aegis.getSystemStatus()`, `window.aegis.getProjects()`, `window.aegis.getTasks()`, `window.aegis.addOrUpdateTask()`, `window.aegis.getWeather()`).
- **`frontend/index.html` (Renderer Process):**
    - Structure the HTML for the four panels.
    - Link `styles.css`.
    - Load renderer logic (e.g., `renderer.js` or inline).
- **`frontend/styles.css`:**
    - Implement VERITAS gold-and-black design palette (DASHBOARD QUALITY RULES).
    - Basic layout for the four panels.
- **`frontend/renderer.js` (Renderer Logic - if needed, or inline in `index.html`):**
    - Call `window.aegis` APIs to fetch data from the backend.
    - Update UI elements with fetched data.
    - Implement auto-refresh for System Status and Weather.
    - Implement task board UI and interaction.
    - Use native `fetch()` for any direct external calls (if any, though most will go through backend) (Rule 24).

### 5. Launch & Verification
- Add a `start` script to `package.json` to launch Electron.
- Launch the Flask backend first, then the Electron app.
- Verify all four panels display data correctly and interact as expected.
- Open the Electron app for RJ to review.

## VERITAS Compliance Notes
- All file paths will use raw strings `r"C:\..."` in Python (Rule 34, 35).
- Max file length 150 lines will be respected (Rule 27).
- Dependencies will be installed upfront (Rule 30).
- `electron-builder` will be used for packaging if requested later, but for now, `npm start` (Rule 37).
- All `require()`/`import` statements will be pre-checked (A5).
- No placeholder text in final code (A2).
- All `console.log`/`print` in core runtime will be considered debug debt (DASHBOARD QUALITY RULES).
- `requests.get()` will use `timeout=10` (Rule 49).
- `Get-ChildItem` will use `-Depth` (Rule 28, 39).
- All `SYS` commands will use full absolute paths (CRITICAL ENVIRONMENT RULES).

Let's get started, darling!