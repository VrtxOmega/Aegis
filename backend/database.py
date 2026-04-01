import sqlite3

DATABASE = 'tasks.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            assignee TEXT NOT NULL,
            status TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def get_tasks():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT id, title, assignee, status FROM tasks')
    tasks = [{'id': row[0], 'title': row[1], 'assignee': row[2], 'status': row[3]} for row in c.fetchall()]
    conn.close()
    return tasks

def add_task(title, assignee, status):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('INSERT INTO tasks (title, assignee, status) VALUES (?, ?, ?)', (title, assignee, status))
    task_id = c.lastrowid
    conn.commit()
    conn.close()
    return {'id': task_id, 'title': title, 'assignee': assignee, 'status': status}

def update_task_status(task_id, status):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('UPDATE tasks SET status = ? WHERE id = ?', (status, task_id))
    conn.commit()
    conn.close()
    return c.rowcount > 0

if __name__ == '__main__':
    init_db()
    print("Database initialized and 'tasks' table created.")
