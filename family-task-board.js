const sqlite3 = require('sqlite3').verbose();

let db;

function initDB() {
  return new Promise((resolve) => {
    const dbPath = 'C:\Users\rlope\.veritas\	asks.db';
    db = new sqlite3.Database(dbPath, (err) => {
      if (err) throw err;
      resolve();
    });
  });
}

function addTask(task) {
  return new Promise((resolve) => {
    db.run(`INSERT INTO tasks (title, status) VALUES (?, ?)`, [task.title, task.status], function(err) {
      if (err) throw err;
      resolve(this.lastID);
    });
  });
}

function getTasks() {
  return new Promise((resolve) => {
    db.all(`SELECT * FROM tasks`, [], (err, rows) => {
      if (err) throw err;
      resolve(rows);
    });
  });
}

module.exports = { initDB, addTask, getTasks };