from flask import Blueprint, jsonify, request
from db import get_db

tasks_bp = Blueprint('tasks', __name__)

@tasks_bp.route('/', methods=['GET'])
def get_tasks():
    db = get_db()
    tasks = db.execute('SELECT * FROM tasks ORDER BY created_at DESC').fetchall()
    return jsonify({'tasks': [dict(task) for task in tasks]})

@tasks_bp.route('/', methods=['POST'])
def add_task():
    data = request.get_json()
    title = data.get('title')
    description = data.get('description', '')
    assignee = data.get('assignee', 'Unassigned')
    status = data.get('status', 'todo')

    if not title:
        return jsonify({'error': 'Title is required'}), 400

    db = get_db()
    cursor = db.execute(
        'INSERT INTO tasks (title, description, status, assignee) VALUES (?, ?, ?, ?)',
        (title, description, status, assignee)
    )
    db.commit()
    new_task_id = cursor.lastrowid
    new_task = db.execute('SELECT * FROM tasks WHERE id = ?', (new_task_id,)).fetchone()
    return jsonify({'task': dict(new_task)}), 201

@tasks_bp.route('/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    data = request.get_json()
    db = get_db()
    
    # Fetch existing task to merge updates
    existing_task = db.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()
    if not existing_task:
        return jsonify({'error': 'Task not found'}), 404
    
    # Convert Row object to dict for easier merging
    task_data = dict(existing_task)
    task_data.update({
        'title': data.get('title', task_data['title']),
        'description': data.get('description', task_data['description']),
        'status': data.get('status', task_data['status']),
        'assignee': data.get('assignee', task_data['assignee'])
    })

    db.execute(
        'UPDATE tasks SET title = ?, description = ?, status = ?, assignee = ? WHERE id = ?',
        (task_data['title'], task_data['description'], task_data['status'], task_data['assignee'], task_id)
    )
    db.commit()
    updated_task = db.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()
    return jsonify({'task': dict(updated_task)})

@tasks_bp.route('/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    db = get_db()
    cursor = db.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    db.commit()
    if cursor.rowcount == 0:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify({'message': 'Task deleted'}), 200
