const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors());
const JWT_SECRET = 'your-secret-key-here';
const db = new Database(':memory:');

// db setup
db.exec(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'collaborator',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
db.exec(`CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    author_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES users (id)
)`);

db.exec(`CREATE TABLE tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
)`);

db.exec(`CREATE TABLE note_tags (
    note_id INTEGER,
    tag_id INTEGER,
    PRIMARY KEY (note_id, tag_id),
    FOREIGN KEY (note_id) REFERENCES notes (id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE)`);
db.exec(`CREATE TABLE collaborations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES users (id),
    FOREIGN KEY (user_id) REFERENCES users (id))`);

db.exec(`CREATE TABLE note_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    version_number INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (note_id) REFERENCES notes (id) ON DELETE CASCADE)`);

// create admin user
const hashedPw = bcrypt.hashSync('admin123', 10);
const insertUser = db.prepare('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)');
insertUser.run('admin', 'admin@test.com', hashedPw, 'admin');

// auth middleware
const auth = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Access denied' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(400).json({ error: 'Invalid token' });
    }
};

// register
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields required' });
    }

    const hashedPw = bcrypt.hashSync(password, 10);
    const insertUser = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
    
    try {
        const result = insertUser.run(username, email, hashedPw);
        res.json({ message: 'User created', userId: result.lastInsertRowid });
    } catch (err) {
        res.status(400).json({ error: 'User already exists' });
    }
});

// login
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const getUser = db.prepare('SELECT * FROM users WHERE email = ?');
    const user = getUser.get(email);
    
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    
    if (bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET);
        res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
    } else {
        res.status(400).json({ error: 'Invalid credentials' });
    }
});

// create note
app.post('/notes', auth, (req, res) => {
    const { title, body, tags } = req.body;
    if (!title || !body) return res.status(400).json({ error: 'Title and body required' });

    const insertNote = db.prepare('INSERT INTO notes (title, body, author_id) VALUES (?, ?, ?)');
    const result = insertNote.run(title, body, req.user.userId);
    const noteId = result.lastInsertRowid;
    
    // save initial version
    const insertVersion = db.prepare('INSERT INTO note_versions (note_id, title, body, version_number) VALUES (?, ?, ?, ?)');
    insertVersion.run(noteId, title, body, 1);

    if (tags && tags.length > 0) {
        const insertTag = db.prepare('INSERT OR IGNORE INTO tags (name) VALUES (?)');
        const getTag = db.prepare('SELECT id FROM tags WHERE name = ?');
        const insertNoteTag = db.prepare('INSERT INTO note_tags (note_id, tag_id) VALUES (?, ?)');
        
        tags.forEach(tagName => {
            insertTag.run(tagName);
            const tag = getTag.get(tagName);
            if (tag) insertNoteTag.run(noteId, tag.id);
        });
    }

    res.json({ id: noteId, title, body, tags: tags || [] });
});

// get notes
app.get('/notes', auth, (req, res) => {
    const { tag } = req.query;
    let query = `
        SELECT n.*, u.username as author, GROUP_CONCAT(t.name) as tags
        FROM notes n
        JOIN users u ON n.author_id = u.id
        LEFT JOIN note_tags nt ON n.id = nt.note_id
        LEFT JOIN tags t ON nt.tag_id = t.id`;
    let params = [];
    
    if (tag) {
        query += ` WHERE n.id IN (
            SELECT DISTINCT n.id FROM notes n
            JOIN note_tags nt ON n.id = nt.note_id
            JOIN tags t ON nt.tag_id = t.id
            WHERE t.name = ?
        )`;
        params.push(tag);
    }
    
    query += ' GROUP BY n.id ORDER BY n.created_at DESC';
    
    const stmt = db.prepare(query);
    const rows = stmt.all(...params);
    
    const notes = rows.map(row => ({
        ...row,
        tags: row.tags ? row.tags.split(',') : []
    }));
    
    res.json(notes);
});

// update note
app.put('/notes/:id', auth, (req, res) => {
    const { title, body, tags } = req.body;
    const noteId = req.params.id;

    // get current version number
    const getMaxVersion = db.prepare('SELECT MAX(version_number) as max_version FROM note_versions WHERE note_id = ?');
    const result = getMaxVersion.get(noteId);
    const nextVersion = (result.max_version || 0) + 1;
    
    // update note
    const updateNote = db.prepare('UPDATE notes SET title = ?, body = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    updateNote.run(title, body, noteId);

    // save version
    const insertVersion = db.prepare('INSERT INTO note_versions (note_id, title, body, version_number) VALUES (?, ?, ?, ?)');
    insertVersion.run(noteId, title, body, nextVersion);

    // update tags
    const deleteNoteTags = db.prepare('DELETE FROM note_tags WHERE note_id = ?');
    deleteNoteTags.run(noteId);
    
    if (tags && tags.length > 0) {
        const insertTag = db.prepare('INSERT OR IGNORE INTO tags (name) VALUES (?)');
        const getTag = db.prepare('SELECT id FROM tags WHERE name = ?');
        const insertNoteTag = db.prepare('INSERT INTO note_tags (note_id, tag_id) VALUES (?, ?)');
        
        tags.forEach(tagName => {
            insertTag.run(tagName);
            const tag = getTag.get(tagName);
            if (tag) insertNoteTag.run(noteId, tag.id);
        });
    }

    res.json({ message: 'Note updated', version: nextVersion });
});

// get note versions
app.get('/notes/:id/versions', auth, (req, res) => {
    const getVersions = db.prepare('SELECT * FROM note_versions WHERE note_id = ? ORDER BY version_number DESC');
    const versions = getVersions.all(req.params.id);
    res.json(versions);
});

// invite collaborator (admin only)
app.post('/invite', auth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    
    const { email } = req.body;
    const getUser = db.prepare('SELECT id FROM users WHERE email = ?');
    const user = getUser.get(email);
    
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const insertCollab = db.prepare('INSERT OR IGNORE INTO collaborations (admin_id, user_id) VALUES (?, ?)');
    insertCollab.run(req.user.userId, user.id);
    res.json({ message: 'Collaborator invited' });
});

// natural language query
app.post('/query', auth, (req, res) => {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: 'Query required' });

    let sqlQuery = `
        SELECT n.*, u.username as author, GROUP_CONCAT(t.name) as tags
        FROM notes n
        JOIN users u ON n.author_id = u.id
        LEFT JOIN note_tags nt ON n.id = nt.note_id
        LEFT JOIN tags t ON nt.tag_id = t.id
    `;
    let params = [];
    let conditions = [];

    // simple rule-based parsing
    const lowQuery = query.toLowerCase();

    // date patterns
    const dateMatch = lowQuery.match(/after\s+(\w+\s+\d{4})/);
    if (dateMatch) {
        const dateStr = dateMatch[1];
        conditions.push("date(n.created_at) > date(?)");
        params.push(`${dateStr.split(' ')[1]}-${getMonthNumber(dateStr.split(' ')[0])}-01`);
    }

    // author patterns
    const authorMatch = lowQuery.match(/by\s+(\w+)/);
    if (authorMatch) {
        conditions.push("u.username LIKE ?");
        params.push(`%${authorMatch[1]}%`);
    }

    // tag patterns
    const tagMatch = lowQuery.match(/tag\s+'([^']+)'|with.*tag.*'([^']+)'/);
    if (tagMatch) {
        const tag = tagMatch[1] || tagMatch[2];
        conditions.push(`n.id IN (
            SELECT DISTINCT n.id FROM notes n
            JOIN note_tags nt ON n.id = nt.note_id
            JOIN tags t ON nt.tag_id = t.id
            WHERE t.name LIKE ?
        )`);
        params.push(`%${tag}%`);
    }

    if (conditions.length > 0) {
        sqlQuery += ' WHERE ' + conditions.join(' AND ');
    }

    sqlQuery += ' GROUP BY n.id ORDER BY n.created_at DESC';

    try {
        const stmt = db.prepare(sqlQuery);
        const rows = stmt.all(...params);
        
        const notes = rows.map(row => ({
            ...row,
            tags: row.tags ? row.tags.split(',') : []
        }));
        
        res.json({ query, results: notes });
    } catch (err) {
        res.status(500).json({ error: 'Query failed' });
    }
});

function getMonthNumber(month) {
    const months = { jan: '01', feb: '02', mar: '03', apr: '04', may: '05', jun: '06',
                    jul: '07', aug: '08', sep: '09', oct: '10', nov: '11', dec: '12' };
    return months[month.toLowerCase().substr(0, 3)] || '01';
}

// get all users (for admin)
app.get('/users', auth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    
    const getUsers = db.prepare('SELECT id, username, email, role, created_at FROM users');
    const users = getUsers.all();
    res.json(users);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports = app;