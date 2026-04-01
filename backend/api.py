from flask import Blueprint, jsonify, request
import psutil
import requests
import os
from datetime import datetime, timezone

from db import get_projects, add_project, get_tasks, add_task, get_task_by_id, update_task, delete_task

# Blueprints
system_bp = Blueprint('system_bp', __name__, url_prefix='/api/system')
projects_bp = Blueprint('projects_bp', __name__, url_prefix='/api/projects')
tasks_bp = Blueprint('tasks_bp', __name__, url_prefix='/api/tasks')
weather_bp = Blueprint('weather_bp', __name__, url_prefix='/api/weather')

# --- System Status API ---
@system_bp.route('/status', methods=['GET'])
def get_system_status():
    try:
        cpu_percent = psutil.cpu_percent(interval=0.5)
        ram_info = psutil.virtual_memory()
        disk_info = psutil.disk_usage('/')

        return jsonify({
            'cpu_percent': cpu_percent,
            'ram_percent': ram_info.percent,
            'disk_percent': disk_info.percent,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as e:
        return jsonify({'error': str(e), 'route': '/api/system/status'}), 500

# --- Project Launcher API ---
@projects_bp.route('/', methods=['GET'])
def get_all_projects():
    try:
        projects = get_projects()
        return jsonify(projects), 200
    except Exception as e:
        return jsonify({'error': str(e), 'route': '/api/projects'}), 500

@projects_bp.route('/', methods=['POST'])
def create_project():
    try:
        data = request.get_json()
        if not data or 'name' not in data or 'path' not in data:
            return jsonify({'error': 'Missing name or path'}), 400
        
        name = data['name']
        project_path = data['path']

        # Basic path validation: check if path exists
        if not os.path.isdir(project_path):
            return jsonify({'error': f'Path does not exist: {project_path}'}), 400

        success = add_project(name, project_path)
        if success:
            return jsonify({'message': 'Project added successfully', 'name': name}), 201
        else:
            return jsonify({'error': 'Project with this name or path already exists'}), 409
    except Exception as e:
        return jsonify({'error': str(e), 'route': '/api/projects'}), 500

# --- Family Task Board API ---
@tasks_bp.route('/', methods=['GET'])
def get_all_tasks():
    try:
        tasks = get_tasks()
        return jsonify(tasks), 200
    except Exception as e:
        return jsonify({'error': str(e), 'route': '/api/tasks'}), 500

@tasks_bp.route('/', methods=['POST'])
def create_task():
    try:
        data = request.get_json()
        if not data or 'name' not in data or 'assignee' not in data:
            return jsonify({'error': 'Missing name or assignee'}), 400
        
        name = data['name']
        assignee = data['assignee']
        status = data.get('status', 'todo')

        task_id = add_task(name, assignee, status)
        return jsonify({'message': 'Task added successfully', 'id': task_id}), 201
    except Exception as e:
        return jsonify({'error': str(e), 'route': '/api/tasks'}), 500

@tasks_bp.route('/<int:task_id>', methods=['GET'])
def get_single_task(task_id):
    try:
        task = get_task_by_id(task_id)
        if task:
            return jsonify(task), 200
        return jsonify({'error': 'Task not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e), 'route': f'/api/tasks/{task_id}'}), 500

@tasks_bp.route('/<int:task_id>', methods=['PUT'])
def update_single_task(task_id):
    try:
        data = request.get_json()
        if not data or 'name' not in data or 'assignee' not in data or 'status' not in data:
            return jsonify({'error': 'Missing name, assignee, or status'}), 400
        
        task = get_task_by_id(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404

        update_task(task_id, data['name'], data['assignee'], data['status'])
        return jsonify({'message': 'Task updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e), 'route': f'/api/tasks/{task_id}'}), 500

@tasks_bp.route('/<int:task_id>', methods=['DELETE'])
def delete_single_task(task_id):
    try:
        task = get_task_by_id(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404

        delete_task(task_id)
        return jsonify({'message': 'Task deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e), 'route': f'/api/tasks/{task_id}'}), 500

# --- Weather Widget API ---
@weather_bp.route('/', methods=['GET'])
def get_weather():
    try:
        # Using wttr.in for Bethalto, IL, with JSON format
        # D4: Allowed domain: wttr.in (via requests library)
        weather_url = "https://wttr.in/Bethalto+IL?format=j1"
        response = requests.get(weather_url, timeout=10)
        response.raise_for_status() # Raise an exception for HTTP errors
        weather_data = response.json()
        
        # Extract relevant info for a concise report
        current_condition = weather_data['current_condition'][0]
        report = (
            f"Location: {weather_data['nearest_area'][0]['areaName'][0]['value']}, "
            f"{weather_data['nearest_area'][0]['region'][0]['value']}\
"
            f"Temperature: {current_condition['temp_F']}°F (Feels like {current_condition['FeelsLikeF']}°F)\
"
            f"Condition: {current_condition['weatherDesc'][0]['value']}\
"
            f"Humidity: {current_condition['humidity']}%\
"
            f"Wind: {current_condition['windspeedMiles']}mph {current_condition['winddir16Point']}"
        )

        return jsonify({'report': report}), 200
    except requests.exceptions.ConnectionError as ce:
        return jsonify({'error': f'Network error fetching weather: {str(ce)}', 'route': '/api/weather'}), 503
    except requests.exceptions.Timeout as te:
        return jsonify({'error': f'Weather API request timed out: {str(te)}', 'route': '/api/weather'}), 504
    except Exception as e:
        return jsonify({'error': f'Error fetching weather: {str(e)}', 'route': '/api/weather'}), 500
