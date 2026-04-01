import os
import subprocess
from flask import Blueprint, jsonify, request

projects_bp = Blueprint('projects', __name__)

PROJECT_SEARCH_PATHS = [
    r'C:\Veritas_Lab',
    r'C:\Users\rlope\OneDrive\Desktop\AI WorK',
    r'C:\Users\rlope\OneDrive\Desktop'
]

PROJECT_MARKERS = [
    'package.json',
    'requirements.txt',
    'Cargo.toml',
    'go.mod'
]

EXCLUDE_DIRS = {'node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'venv', '.next', 'out', 'coverage'}

def find_projects():
    found_projects = []
    for base_path in PROJECT_SEARCH_PATHS:
        if not os.path.exists(base_path):
            continue
        # Only scan direct children (depth=1), not recursive
        try:
            entries = os.listdir(base_path)
        except PermissionError:
            continue
        for entry in entries:
            full_path = os.path.join(base_path, entry)
            if not os.path.isdir(full_path):
                continue
            if entry in EXCLUDE_DIRS:
                continue
            # Check if this directory has a project marker
            for marker in PROJECT_MARKERS:
                if os.path.exists(os.path.join(full_path, marker)):
                    if not any(p['path'] == full_path for p in found_projects):
                        found_projects.append({
                            'name': entry,
                            'path': full_path,
                            'marker': marker
                        })
                    break
    return sorted(found_projects, key=lambda x: x['name'].lower())

@projects_bp.route('/')
def get_projects():
    projects = find_projects()
    return jsonify({'projects': projects})

@projects_bp.route('/open', methods=['POST'])
def open_project_folder():
    data = request.get_json()
    project_path = data.get('path')

    if not project_path or not os.path.isdir(project_path):
        return jsonify({'error': 'Invalid project path'}), 400

    try:
        # Use 'explorer' on Windows to open the folder
        subprocess.Popen(['explorer', project_path])
        return jsonify({'message': f'Opened {project_path}'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to open folder: {str(e)}'}), 500
