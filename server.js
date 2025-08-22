// A simple Express server for managing user accounts and a video list.
// Includes JWT for authentication.

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

//using better-sqlite3 for synchronous queries
const db = require('better-sqlite3')('users.db');

// --- Database Setup ---
//making sure our tables exist on startup.
const usersSchema = `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL)`;
const videosSchema = `
  CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    url TEXT NOT NULL)`;
db.exec(usersSchema);
db.exec(videosSchema);


const app = express();
app.use(express.json());
app.use(cors());

// Use an environment variable for the secret, but have a clear placeholder for development.
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key_change_in_production';

// --- Auth Routes ---

app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }
  try {
    const saltRounds = 10; // Increased salt rounds from 8 for better security
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const statement = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
    statement.run(username, hashedPassword);
    res.status(201).json({ message: 'User created successfully!' });
  } catch (error) {
    // This usually means the username is already taken (due to UNIQUE constraint)
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).json({ message: 'This username is already taken.' });
    }
    res.status(500).json({ message: 'Something went wrong on our end.' });
  }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  const passwordIsValid = user ? bcrypt.compareSync(password, user.password) : false;
  if (!user || !passwordIsValid) {
    return res.status(401).json({ message: 'Incorrect credentials, please try again.' });}
  const payload = { id: user.id, username: user.username };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// --- Middleware ---
function authenticateToken(req, res, next) {
  // The token is expected to be in the 'Authorization: Bearer <TOKEN>' header
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) {
    return res.status(401).send({ message: 'Access denied. No token provided.' });
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err.message);
      return res.status(403).send({ message: 'Token is invalid or has expired.' });
    }
    // Attach the user payload to the request for other routes to use
    req.user = user;
    next();
  });
}

// --- Video Routes (Protected) ---
app.post('/vids', authenticateToken, (req, res) => {
  const { title, url } = req.body;
  if (!title || !url) {
    return res.status(400).json({ message: 'Title and URL are required.' });}
  const statement = db.prepare('INSERT INTO videos (title, url) VALUES (?, ?)');
  const info = statement.run(title, url);
  console.log(`Video added by user ${req.user.username}. ID: ${info.lastInsertRowid}`);
  res.status(201).json({ id: info.lastInsertRowid, title, url });
});
app.get('/vids', authenticateToken, (req, res) => {
  const videos = db.prepare('SELECT * FROM videos').all();
  res.json(videos);
});
app.delete('/vids/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const info = db.prepare('DELETE FROM videos WHERE id = ?').run(id);

  if (info.changes > 0) {
    res.json({ message: `Video with ID ${id} deleted successfully.` });
  } else {
    res.status(404).json({ message: `Video with ID ${id} not found.` });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is startingg at port ${PORT}`);
});

