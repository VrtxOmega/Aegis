# Aegis Home Base Build Plan

## Objective
Build an Electron app with a Python Flask backend for a family command center, featuring System Status, Project Launcher, Family Task Board (SQLite), and Weather widget, using VERITAS gold-and-black design.

## Architecture
- **Frontend:** Electron (main.js, preload.js, index.html, renderer.js, style.css)
- **Backend:** Flask (app.py, tasks_api.py, weather_api.py, requirements.txt, tasks.db)

## Steps
1.  **Create Project Directory:** `C:\Veritas_Lab\aegis-home-base`
2.  **Initialize Node.js Project:** Create `package.json` with correct dependencies (Electron as devDep).
3.  **Create Electron Main Process (`main.js`):
    -   Spawn Flask backend (`app.py`).
    -   Poll Flask `/api/health` until ready.
    -   Create Electron window.
    -   Set up `ipcMain` handlers for `backend:get`, `backend:post`, `backend:put`, `backend:delete` to bridge to Flask.
    -   Set up `ipcMain` handlers for `shell:openPath` (for project launcher).
4.  **Create Electron Preload Script (`preload.js`):
    -   Expose `window.aegis.get/post/put/del` via `contextBridge`.
    -   Expose `window.aegis.shell.openPath`.
5.  **Create Electron Renderer HTML (`index.html`):
    -   Link `preload.js`.
    -   Link `style.css`.
    -   Load `renderer.js`.
    -   Define basic layout structure for the 4 panels.
6.  **Create Electron Renderer Script (`renderer.js`):
    -   Implement UI logic for each panel.
    -   Use `window.aegis` for all backend and shell interactions.
    -   Auto-refresh System Status and Weather.
    -   Handle task board interactions (add, update status).
7.  **Create CSS Styling (`style.css`):
    -   Implement VERITAS gold-and-black theme.
    -   Basic layout for panels.
8.  **Create Flask Backend Directory:** `C:\Veritas_Lab\aegis-home-base\backend`
9.  **Create Flask `requirements.txt`:** `Flask`, `psutil`, `requests`, `Flask-Cors`.
10. **Create Flask Main App (`app.py`):
    -   Initialize Flask app.
    -   Register blueprints for `tasks_api` and `weather_api`.
    -   Implement `/api/health` endpoint.
    -   Implement port killing logic before `app.run(debug=False)`.
    -   Initialize SQLite database (`tasks.db`) with `CREATE TABLE IF NOT EXISTS`.
11. **Create Flask Tasks API Blueprint (`tasks_api.py`):
    -   Define routes for `GET /api/tasks`, `POST /api/tasks`, `PUT /api/tasks/:id`, `DELETE /api/tasks/:id`.
    -   Interact with `tasks.db`.
12. **Create Flask Weather API Blueprint (`weather_api.py`):
    -   Define route for `GET /api/weather`.
    -   Fetch data from `wttr.in` for Bethalto, IL (Fahrenheit).
13. **Install Dependencies:** `npm install` (Electron), `pip install -r requirements.txt` (Flask).
14. **Launch Application:** `npm start`.
15. **Open UI:** Ensure the Electron window is visible and functional.