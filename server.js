const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const db = require('better-sqlite3')('users.db');

db.prepare(
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    u TEXT UNIQUE,
    p TEXT)`).run();

db.prepare(
  `CREATE TABLE IF NOT EXISTS vids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    t TEXT,
    u TEXT)`).run();
    
const app = express();
app.use(express.json());
app.use(cors());
const JWT_SECRET = process.env.JWT_SECRET || 'SI-Secret123';

app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });}
  const saltRounds = 8;
  const hashedPassword = bcrypt.hashSync(password, saltRounds);
  try {
    const statement = db.prepare('INSERT INTO users (u, p) VALUES (?, ?)');
    statement.run(username, hashedPassword);
    res.status(201).json({ message: 'User created successfully.' });
  } catch (error) {
    res.status(409).json({ error: 'Username already exists.' });
  }});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE u = ?').get(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }
  const isPasswordCorrect = bcrypt.compareSync(password, user.p);
  if (!isPasswordCorrect) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }
  const payload = { id: user.id, username: user.u };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  try {
    const decodedPayload = jwt.verify(token, JWT_SECRET);
    req.user = decodedPayload;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Token is invalid or has expired.' });
  }
}

app.post('/vids', authenticateToken, (req, res) => {
  const { title, url } = req.body;
  if (!title || !url) {
    return res.status(400).json({ error: 'Title and URL are required.' });
  }
  const statement = db.prepare('INSERT INTO vids (t, u) VALUES (?, ?)');
  const info = statement.run(title, url);
  res.status(201).json({ id: info.lastInsertRowid, title, url });});

app.get('/vids', authenticateToken, (req, res) => {
  const videos = db.prepare('SELECT * FROM vids').all();
  res.json(videos);});
  
app.delete('/vids/:id', authenticateToken, (req, res) => {
  const videoId = req.params.id;
  db.prepare('DELETE FROM vids WHERE id = ?').run(videoId);
  res.json({ message: 'Video deleted successfully.' });});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
