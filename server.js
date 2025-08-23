const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// Basic middleware
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'SI-dev-secret';

// Using file database instead of memory for actual persistence
const db = new Database('./notes.db');

// Database setup - keeping it simple initially
db.exec(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);

db.exec(`CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT,
        author_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (author_id) REFERENCES users (id))`);

//added tags
db.exec(`
    CREATE TABLE IF NOT EXISTS tags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL)`);

db.exec(`
    CREATE TABLE IF NOT EXISTS note_tags (
        note_id INTEGER,
        tag_id INTEGER,
        FOREIGN KEY (note_id) REFERENCES notes (id),
        FOREIGN KEY (tag_id) REFERENCES tags (id))`);

// Version history - added when users requested it
db.exec(`CREATE TABLE IF NOT EXISTS note_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        note_id INTEGER,
        title TEXT,
        body TEXT,
        version_num INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (note_id) REFERENCES notes (id))`);

// Basic auth check
function checkAuth(req, res, next) {
    const token = req.header('Authorization');
    if (!token) {
        return res.status(401).json({ error: 'No token' });
    }
    
    const actualToken = token.replace('Bearer ', '');
    try {
        const user = jwt.verify(actualToken, JWT_SECRET);
        req.user = user;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Token Is wrong' });
    }
}

// Sign up endpoint
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Fields are missing' });
    }
    
    const hashedPwd = bcrypt.hashSync(password, 10);
    
    try {
        const stmt = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
        const result = stmt.run(username, email, hashedPwd);
        res.json({ message: 'User Created', id: result.lastInsertRowid });
    } catch (error) {
        // SQLite constraint error usually means duplicate
        res.status(400).json({ error: 'User already exists get original' });
    }
});

// Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    
    const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
    const user = stmt.get(email);
    
    if (!user) {
        return res.status(400).json({ error: 'wrong username or password' });
    }
    
    if (bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET);
        res.json({ 
            token, 
            user: { id: user.id, username: user.username, role: user.role }
        });
    } else {
        res.status(400).json({ error: 'wrong username or password' });
    }
});

// Create note
app.post('/notes', checkAuth, (req, res) => {
    const { title, body, tags } = req.body;
    
    if (!title) {
        return res.status(400).json({ error: 'Title is required' });
    }
    
    const insertStmt = db.prepare('INSERT INTO notes (title, body, author_id) VALUES (?, ?, ?)');
    const result = insertStmt.run(title, body || '', req.user.userId);
    const noteId = result.lastInsertRowid;
    
    // Save first version
    const versionStmt = db.prepare('INSERT INTO note_versions (note_id, title, body, version_num) VALUES (?, ?, ?, ?)');
    versionStmt.run(noteId, title, body || '', 1);
    
    // Handle tags if any
    if (tags && tags.length > 0) {
        tags.forEach(tagName => {
            //Insert tag if it doesn't exist already
            try {
                const tagStmt = db.prepare('INSERT INTO tags (name) VALUES (?)');
                tagStmt.run(tagName);
            } catch (e) {
                //Tag probably already exists
            }
            
            // Link note to tag
            const getTagStmt = db.prepare('SELECT id FROM tags WHERE name = ?');
            const tag = getTagStmt.get(tagName);
            if (tag) {
                const linkStmt = db.prepare('INSERT INTO note_tags (note_id, tag_id) VALUES (?, ?)');
                try {
                    linkStmt.run(noteId, tag.id);
                } catch (e) {
                    //Duplicate link (ignore)
                }
            }
        });
    }
    
    res.json({ id: noteId, title, body, tags: tags || [] });
});

// Get notes
app.get('/notes', checkAuth, (req, res) => {
    const { tag } = req.query;
    
    let query = `SELECT n.*, u.username as author_name
        FROM notes n 
        JOIN users u ON n.author_id = u.id`;
    
    let params = [];
    
    if (tag) {
        query = `SELECT n.*, u.username as author_name
            FROM notes n 
            JOIN users u ON n.author_id = u.id
            JOIN note_tags nt ON n.id = nt.note_id
            JOIN tags t ON nt.tag_id = t.id
            WHERE t.name = ?`;
        params.push(tag);
    }
    
    query += ' ORDER BY n.created_at DESC';
    
    const stmt = db.prepare(query);
    const notes = stmt.all(...params);
    
    // Get tags for each note - not the most efficient but it works
    notes.forEach(note => {
        const tagStmt = db.prepare(`
            SELECT t.name FROM tags t
            JOIN note_tags nt ON t.id = nt.tag_id
            WHERE nt.note_id = ?`);
        const noteTags = tagStmt.all(note.id);
        note.tags = noteTags.map(t => t.name);
    });
    res.json(notes);
});

// Update note
app.put('/notes/:id', checkAuth, (req, res) => {
    const { title, body, tags } = req.body;
    const noteId = req.params.id;
    
    // Check if user owns this note
    const checkStmt = db.prepare('SELECT author_id FROM notes WHERE id = ?');
    const note = checkStmt.get(noteId);
    
    if (!note) {
        return res.status(404).json({ error: 'Note not found' });
    }
    
    if (note.author_id !== req.user.userId && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Not authorized' });
    }
    
    // Get current version number
    const versionStmt = db.prepare('SELECT MAX(version_num) as max_ver FROM note_versions WHERE note_id = ?');
    const versionResult = versionStmt.get(noteId);
    const nextVersion = (versionResult.max_ver || 0) + 1;
    
    // Update note
    const updateStmt = db.prepare('UPDATE notes SET title = ?, body = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    updateStmt.run(title, body, noteId);
    
    // Save version
    const saveVersionStmt = db.prepare('INSERT INTO note_versions (note_id, title, body, version_num) VALUES (?, ?, ?, ?)');
    saveVersionStmt.run(noteId, title, body, nextVersion);
    
    // Update tags (remove old ones first)
    const deleteTagsStmt = db.prepare('DELETE FROM note_tags WHERE note_id = ?');
    deleteTagsStmt.run(noteId);
    
    if (tags && tags.length > 0) {
        tags.forEach(tagName => {
            // Insert tag whenever you need to
            try {
                const tagStmt = db.prepare('INSERT INTO tags (name) VALUES (?)');
                tagStmt.run(tagName);
            } catch (e) {}
            
            // Link it
            const getTagStmt = db.prepare('SELECT id FROM tags WHERE name = ?');
            const tag = getTagStmt.get(tagName);
            if (tag) {
                const linkStmt = db.prepare('INSERT INTO note_tags (note_id, tag_id) VALUES (?, ?)');
                linkStmt.run(noteId, tag.id);
            }
        });
    }
    
    res.json({ message: 'Updated', version: nextVersion });
});

// Get versions
app.get('/notes/:id/versions', checkAuth, (req, res) => {
    const noteId = req.params.id;
    
    // Check access
    const checkStmt = db.prepare('SELECT author_id FROM notes WHERE id = ?');
    const note = checkStmt.get(noteId);
    
    if (!note) {
        return res.status(404).json({ error: 'Note not found' });
    }
    
    if (note.author_id !== req.user.userId && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Not authorized' });
    }
    
    const stmt = db.prepare('SELECT * FROM note_versions WHERE note_id = ? ORDER BY version_num DESC');
    const versions = stmt.all(noteId);
    res.json(versions);
});

//Simple search
app.post('/search', checkAuth, (req, res) => {
    const { q } = req.body;
    
    if (!q) {
        return res.status(400).json({ error: 'Query required' });
    }
    
    let query = `SELECT n.*, u.username as author_name
        FROM notes n 
        JOIN users u ON n.author_id = u.id
        WHERE 1=1`;
    
    let params = [];
    
    // Simple text search in title/body
    if (q.includes('title:')) {
        const titleSearch = q.replace('title:', '').trim();
        query += ' AND n.title LIKE ?';
        params.push(`%${titleSearch}%`);
    } else if (q.includes('author:')) {
        const authorSearch = q.replace('author:', '').trim();
        query += ' AND u.username LIKE ?';
        params.push(`%${authorSearch}%`);
    } else {
        // Default: search title and body
        query += ' AND (n.title LIKE ? OR n.body LIKE ?)';
        params.push(`%${q}%`, `%${q}%`);
    }
    
    query += ' ORDER BY n.updated_at DESC';
    
    const stmt = db.prepare(query);
    const results = stmt.all(...params);
    
    // Add tags to results
    results.forEach(note => {
        const tagStmt = db.prepare(`SELECT t.name FROM tags t
            JOIN note_tags nt ON t.id = nt.tag_id
            WHERE nt.note_id = ?`);
        const noteTags = tagStmt.all(note.id);
        note.tags = noteTags.map(t => t.name);
    });
    res.json(results);
});

// Admin endpoint to see all users
app.get('/users', checkAuth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin only' });
    }
    
    const stmt = db.prepare('SELECT id, username, email, role, created_at FROM users');
    const users = stmt.all();
    res.json(users);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;
