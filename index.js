const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'my_super_secret_key_12345';
const DB_PATH = path.join(__dirname, 'todo_app.db');
const db = new Database(DB_PATH);

// Create tables if not exist
// Users
// Tasks

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    description TEXT,
    completed INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

// Add missing columns if not exist (SQLite allows adding columns)
try {
  db.exec('ALTER TABLE tasks ADD COLUMN tag TEXT');
} catch (e) {}
try {
  db.exec('ALTER TABLE tasks ADD COLUMN checklist TEXT');
} catch (e) {}

// JWT middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ message: 'All fields required' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)');
    stmt.run(username, email, hash);
    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      res.status(409).json({ message: 'Username or email already exists' });
    } else {
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'All fields required' });
  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ token, username: user.username });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get all tasks for logged-in user
app.get('/api/tasks', authenticateToken, (req, res) => {
  try {
    const rows = db.prepare('SELECT * FROM tasks WHERE user_id = ?').all(req.user.id);
    // Parse checklist JSON for each task
    const tasks = rows.map(row => ({
      ...row,
      checklist: row.checklist ? JSON.parse(row.checklist) : [],
      tag: row.tag || '',
    }));
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Add a new task
app.post('/api/tasks', authenticateToken, (req, res) => {
  const { text, description, tag, checklist, color } = req.body;
  if (!text) return res.status(400).json({ message: 'Task text required' });
  try {
    const stmt = db.prepare('INSERT INTO tasks (user_id, text, description, tag, checklist, completed, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)');
    const info = stmt.run(
      req.user.id,
      text,
      description || '',
      tag || '',
      checklist ? JSON.stringify(checklist) : '[]'
    );
    res.status(201).json({ id: info.lastInsertRowid, text, description, tag, checklist: checklist || [], completed: false });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Update a task
app.put('/api/tasks/:id', authenticateToken, (req, res) => {
  const { text, description, completed, tag, checklist } = req.body;
  try {
    const stmt = db.prepare('UPDATE tasks SET text = ?, description = ?, completed = ?, tag = ?, checklist = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?');
    const info = stmt.run(
      text,
      description,
      completed ? 1 : 0,
      tag || '',
      checklist ? JSON.stringify(checklist) : '[]',
      req.params.id,
      req.user.id
    );
    if (info.changes === 0) return res.status(404).json({ message: 'Task not found' });
    res.json({ message: 'Task updated' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Delete a task
app.delete('/api/tasks/:id', authenticateToken, (req, res) => {
  try {
    const stmt = db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?');
    const info = stmt.run(req.params.id, req.user.id);
    if (info.changes === 0) return res.status(404).json({ message: 'Task not found' });
    res.json({ message: 'Task deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// User info endpoint
app.get('/api/userinfo', authenticateToken, (req, res) => {
  try {
    const user = db.prepare('SELECT username, email, created_at FROM users WHERE id = ?').get(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`SQLite DB at ${DB_PATH}`);
}); 