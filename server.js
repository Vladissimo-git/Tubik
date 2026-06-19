// ═══════════════════════════════════════════════════════════
//  Tubik Backend - SQLite + Local Storage (No Supabase/R2)
// ═══════════════════════════════════════════════════════════
require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tubik-secret-key-change-in-prod';

// ── UPLOADS DIR ──
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// ── MIDDLEWARE ──
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use('/uploads', express.static(uploadsDir));

// ── MULTER ──
const upload = multer({
  dest: uploadsDir,
  limits: { fileSize: 500 * 1024 * 1024 } // 500MB
});

// ── DATABASE ──
const db = new sqlite3.Database(path.join(__dirname, 'tubik.db'), (err) => {
  if (err) console.error('DB error:', err);
  else console.log('✓ SQLite connected');
});

db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    avatar_url TEXT,
    joined DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Videos table
  db.run(`CREATE TABLE IF NOT EXISTS videos (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    file_url TEXT NOT NULL,
    thumbnail_url TEXT,
    duration TEXT,
    is_short BOOLEAN DEFAULT 0,
    emoji TEXT,
    bg TEXT,
    views INTEGER DEFAULT 0,
    likes INTEGER DEFAULT 0,
    tags TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Likes table
  db.run(`CREATE TABLE IF NOT EXISTS likes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    video_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, video_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(video_id) REFERENCES videos(id)
  )`);

  // Comments table
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    video_id TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(video_id) REFERENCES videos(id)
  )`);
});

// ── UTILS ──
const genId = () => Math.random().toString(36).substr(2, 9);
const hashPassword = (pwd) => bcrypt.hashSync(pwd, 10);
const verifyPassword = (pwd, hash) => bcrypt.compareSync(pwd, hash);

// ── MIDDLEWARE: AUTH ──
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ── AUTH ROUTES ──
app.post('/auth/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });

  const id = genId();
  const hashedPwd = hashPassword(password);

  db.run(
    'INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)',
    [id, name, email, hashedPwd],
    function (err) {
      if (err) return res.status(409).json({ error: 'Email already exists' });
      const token = jwt.sign({ id }, JWT_SECRET, { expiresIn: '30d' });
      res.json({ token, user: { id, name, email } });
    }
  );
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!verifyPassword(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  });
});

app.get('/auth/me', authMiddleware, (req, res) => {
  db.get('SELECT id, name, email, avatar_url, joined FROM users WHERE id = ?', [req.userId], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  });
});

// ── VIDEO ROUTES ──
app.post('/videos/upload', authMiddleware, upload.single('video'), (req, res) => {
  const { title, description, emoji, bg, tags, is_short, duration } = req.body;
  if (!title || !req.file) return res.status(400).json({ error: 'Missing title or video' });

  const videoId = genId();
  const fileUrl = `/uploads/${req.file.filename}`;

  const tagsArr = tags ? JSON.parse(tags) : [];

  db.run(
    `INSERT INTO videos (id, user_id, title, description, file_url, emoji, bg, tags, is_short, duration)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [videoId, req.userId, title, description || '', fileUrl, emoji || '🎬', bg || '#6C47FF', JSON.stringify(tagsArr), is_short === 'true' ? 1 : 0, duration || 'unknown'],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: videoId, file_url: fileUrl });
    }
  );
});

app.get('/videos', (req, res) => {
  const { tag, search, limit = 20, offset = 0 } = req.query;
  let query = 'SELECT * FROM videos';
  const params = [];

  if (tag) {
    query += ' WHERE tags LIKE ?';
    params.push(`%${tag}%`);
  } else if (search) {
    query += ' WHERE title LIKE ? OR description LIKE ?';
    params.push(`%${search}%`, `%${search}%`);
  }

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));

  db.all(query, params, (err, videos) => {
    if (err) return res.status(500).json({ error: err.message });
    
    const vids = videos.map(v => ({
      ...v,
      tags: v.tags ? JSON.parse(v.tags) : []
    }));
    
    res.json({ videos: vids });
  });
});

app.get('/videos/:id', (req, res) => {
  db.get(
    `SELECT v.*, u.name as author_name, u.avatar_url as author_avatar FROM videos v
     LEFT JOIN users u ON v.user_id = u.id WHERE v.id = ?`,
    [req.params.id],
    (err, video) => {
      if (err || !video) return res.status(404).json({ error: 'Video not found' });
      
      // Increment views
      db.run('UPDATE videos SET views = views + 1 WHERE id = ?', [req.params.id]);
      
      res.json({
        video: {
          ...video,
          tags: video.tags ? JSON.parse(video.tags) : []
        }
      });
    }
  );
});

app.get('/users/:id/videos', (req, res) => {
  db.all(
    'SELECT id, title, emoji, views, created_at FROM videos WHERE user_id = ? ORDER BY created_at DESC',
    [req.params.id],
    (err, videos) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ videos });
    }
  );
});

// ── LIKE ROUTES ──
app.post('/videos/:id/like', authMiddleware, (req, res) => {
  const likeId = genId();
  db.run(
    'INSERT INTO likes (id, user_id, video_id) VALUES (?, ?, ?)',
    [likeId, req.userId, req.params.id],
    function (err) {
      if (err) return res.status(409).json({ error: 'Already liked' });
      db.run('UPDATE videos SET likes = likes + 1 WHERE id = ?', [req.params.id]);
      res.json({ success: true });
    }
  );
});

app.delete('/videos/:id/unlike', authMiddleware, (req, res) => {
  db.run(
    'DELETE FROM likes WHERE user_id = ? AND video_id = ?',
    [req.userId, req.params.id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes > 0) {
        db.run('UPDATE videos SET likes = likes - 1 WHERE id = ? AND likes > 0', [req.params.id]);
      }
      res.json({ success: true });
    }
  );
});

// ── COMMENT ROUTES ──
app.post('/videos/:id/comments', authMiddleware, (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Missing text' });

  const commentId = genId();
  db.run(
    'INSERT INTO comments (id, user_id, video_id, text) VALUES (?, ?, ?, ?)',
    [commentId, req.userId, req.params.id, text],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: commentId });
    }
  );
});

app.get('/videos/:id/comments', (req, res) => {
  db.all(
    `SELECT c.id, c.text, c.created_at, u.name, u.avatar_url FROM comments c
     LEFT JOIN users u ON c.user_id = u.id WHERE c.video_id = ? ORDER BY c.created_at DESC`,
    [req.params.id],
    (err, comments) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ comments });
    }
  );
});

// ── START SERVER ──
app.listen(PORT, () => {
  console.log(`🚀 Tubik backend running on port ${PORT}`);
});
