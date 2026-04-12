from flask import Flask, jsonify, request
import psutil
import platform
import os
import subprocess
import json
import sqlite3
import requests
import time
import re

app = Flask(__name__)
DATABASE = 'tasks.db'

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            assignedTo TEXT,
            dueDate TEXT,
            status TEXT NOT NULL DEFAULT 'todo'
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- System Status ---
@app.route('/api/system-status')
def get_system_status():
    cpu_percent = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    # Get disk usage for C: drive specifically on Windows
    disk_c_usage = 'N/A'
    if platform.system() == 'Windows':
        try:
            # Use wmic to get C: drive info
            result = subprocess.run(['wmic', 'logicaldisk', 'where', 'DeviceID="C:"', 'get', 'Size,FreeSpace', '/value'], capture_output=True, text=True, check=True)
            output_lines = result.stdout.strip().split('\n')
            size = None
            free_space = None
            for line in output_lines:
                if line.startswith('Size='):
                    size = int(line.split('=')[1])
                elif line.startswith('FreeSpace='):
                    free_space = int(line.split('=')[1])
            if size and free_space:
                used_gb = (size - free_space) / (1024**3)
                total_gb = size / (1024**3)
                disk_c_usage = f'{used_gb:.2f}GB / {total_gb:.2f}GB ({((size - free_space) / size) * 100:.1f}%)'
        except Exception as e:
            print(f"Error getting C: drive usage: {e}")
            disk_c_usage = 'Error'
    else: # For WSL/Linux
        used_gb = disk.used / (1024**3)
        total_gb = disk.total / (1024**3)
        disk_c_usage = f'{used_gb:.2f}GB / {total_gb:.2f}GB ({disk.percent:.1f}%)'


    return jsonify({
        'cpu': f'{cpu_percent}%',
        'ram': f'{ram.used / (1024**3):.2f}GB / {ram.total / (1024**3):.2f}GB ({ram.percent:.1f}%)',
        'disk': disk_c_usage
        # Calculate disk pressure level
        disk_percent = disk.percent if hasattr(disk, 'percent') else 0
        if disk_percent < 50:
            disk_pressure = 'LOW'
        elif disk_percent < 80:
            disk_pressure = 'MED'
        else:
            disk_pressure = 'HIGH'
        'disk_pressure': disk_pressure,
    })

# --- Project Launcher ---
def find_projects_in_dir(base_dir, depth=2):
    projects = []
    for root, dirs, files in os.walk(base_dir):
        # Prune directories to avoid deep dives into node_modules, .git, etc.
        dirs[:] = [d for d in dirs if d not in {'node_modules', '.git', 'dist', 'build', '__pycache__', 'venv', '.venv'}]

        # Check for project markers (package.json for Node/Electron, .py files for Python)
        if 'package.json' in files:
            try:
                with open(os.path.join(root, 'package.json'), 'r') as f:
                    pkg_json = json.load(f)
                    project_name = pkg_json.get('name', os.path.basename(root))
                    projects.append({'name': project_name, 'path': root, 'type': 'Node/Electron'})
            except json.JSONDecodeError:
                pass # Malformed package.json
        elif any(f.endswith('.py') for f in files) and not any(f.endswith('.js') for f in files):
            # Simple heuristic for Python projects if no package.json
            projects.append({'name': os.path.basename(root), 'path': root, 'type': 'Python'})

        # Limit search depth
        current_depth = root[len(base_dir):].count(os.sep)
        if current_depth >= depth:
            del dirs[:] # Don't recurse further

    return projects

@app.route('/api/projects')
def get_projects():
    project_dirs = [
        r'C:\Veritas_Lab',
        r'C:\Users\rlope\OneDrive\Desktop\AI WorK',
        r'C:\Users\rlope\OneDrive\Desktop'
    ]
    all_projects = []
    seen_paths = set()

    for p_dir in project_dirs:
        # Resolve shortcuts if the path is a .lnk
        if p_dir.lower().endswith('.lnk'):
            try:
                shell = subprocess.run(['powershell.exe', '-Command',
                                        f'$shell = New-Object -ComObject WScript.Shell; '
                                        f'$lnk = $shell.CreateShortcut("{p_dir}"); '
                                        f'$lnk.WorkingDirectory'],
                                       capture_output=True, text=True, check=True)
                resolved_path = shell.stdout.strip()
                if resolved_path and os.path.isdir(resolved_path):
                    p_dir = resolved_path
            except Exception as e:
                print(f"Could not resolve shortcut {p_dir}: {e}")
                continue # Skip if shortcut resolution fails

        if os.path.isdir(p_dir):
            found_projects = find_projects_in_dir(p_dir, depth=3) # Increased depth slightly
            for project in found_projects:
                if project['path'] not in seen_paths:
                    all_projects.append(project)
                    seen_paths.add(project['path'])
    return jsonify(all_projects)

@app.route('/api/open-folder', methods=['POST'])
def open_folder():
    data = request.get_json()
    folder_path = data.get('path')
    if not folder_path or not os.path.isdir(folder_path):
        return jsonify({'error': 'Invalid path'}), 400
    try:
        subprocess.Popen(f'explorer "{folder_path}"')
        return jsonify({'message': f'Opened folder: {folder_path}'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to open folder: {e}'}), 500

# --- Family Task Board ---
@app.route('/api/tasks', methods=['GET'])
def get_tasks():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT id, title, assignedTo, dueDate, status FROM tasks')
    tasks = [{'id': row[0], 'title': row[1], 'assignedTo': row[2], 'dueDate': row[3], 'status': row[4]} for row in c.fetchall()]
    conn.close()
    return jsonify(tasks)

@app.route('/api/tasks', methods=['POST'])
def add_task():
    data = request.get_json()
    title = data.get('title')
    assignedTo = data.get('assignedTo', 'Unassigned')
    dueDate = data.get('dueDate', 'No Date')
    status = data.get('status', 'todo')

    if not title:
        return jsonify({'error': 'Title is required'}), 400

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('INSERT INTO tasks (title, assignedTo, dueDate, status) VALUES (?, ?, ?, ?)',
              (title, assignedTo, dueDate, status))
    conn.commit()
    new_task_id = c.lastrowid
    conn.close()
    return jsonify({'id': new_task_id, 'title': title, 'assignedTo': assignedTo, 'dueDate': dueDate, 'status': status}), 201

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    data = request.get_json()
    title = data.get('title')
    assignedTo = data.get('assignedTo')
    dueDate = data.get('dueDate')
    status = data.get('status')

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    update_fields = []
    update_values = []
    if title:
        update_fields.append('title = ?')
        update_values.append(title)
    if assignedTo:
        update_fields.append('assignedTo = ?')
        update_values.append(assignedTo)
    if dueDate:
        update_fields.append('dueDate = ?')
        update_values.append(dueDate)
    if status:
        update_fields.append('status = ?')
        update_values.append(status)

    if not update_fields:
        return jsonify({'error': 'No fields to update'}), 400

    query = f'UPDATE tasks SET {", ".join(update_fields)} WHERE id = ?'
    update_values.append(task_id)
    c.execute(query, tuple(update_values))
    conn.commit()
    conn.close()

    if c.rowcount == 0:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify({'message': 'Task updated successfully'}), 200

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    conn.commit()
    conn.close()

    if c.rowcount == 0:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify({'message': 'Task deleted successfully'}), 200

# --- Weather Widget ---
@app.route('/api/weather')
def get_weather():
    try:
        # wttr.in can be slow, add a timeout
        response = requests.get('https://wttr.in/?format=j1', timeout=10)
        response.raise_for_status() # Raise an exception for HTTP errors
        weather_data = response.json()

        current_condition = weather_data['current_condition'][0]
        weather_info = {
            'condition': current_condition['weatherDesc'][0]['value'],
            'temperature': f'{current_condition["temp_F"]}°F ({current_condition["temp_C"]}°C)',
            'feels_like': f'{current_condition["FeelsLikeF"]}°F ({current_condition["FeelsLikeC"]}°C)',
            'humidity': f'{current_condition["humidity"]}%',
            'wind_speed': f'{current_condition["windspeedMiles"]}mph ({current_condition["windspeedKmph"]}km/h)',
            'pressure': f'{current_condition["pressureInches"]}in ({current_condition["pressureMB"]}mb)',
            'visibility': f'{current_condition["visibilityMiles"]}miles ({current_condition["visibilityKm"]}km)',
            'uv_index': current_condition['uvIndex'],
            'moon_phase': weather_data['weather'][0]['astronomy'][0]['moon_phase'],
            'sunrise': weather_data['weather'][0]['astronomy'][0]['sunrise'],
            'sunset': weather_data['weather'][0]['astronomy'][0]['sunset'],
        }
        return jsonify(weather_info)
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Weather API request timed out'}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Failed to fetch weather data: {e}'}), 500
    except json.JSONDecodeError:
        return jsonify({'error': 'Failed to parse weather data'}), 500
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500

if __name__ == '__main__':
    # Ensure the database is initialized before running the app
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=False) # debug=False for production
