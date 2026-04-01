import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(__file__), 'tasks.db')

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            assigned_to TEXT,
            status TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print(f"Database initialized at {DATABASE}")

if __name__ == '__main__':
    init_db()
