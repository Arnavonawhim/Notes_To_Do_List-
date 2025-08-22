const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const db = new Database('notes.db');

//initialize tables
db.exec(`
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user');
    CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, content TEXT, tags TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS note_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, note_id INTEGER, version_number INTEGER, content TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(note_id) REFERENCES notes(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS collaborations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        note_id INTEGER,
        user_id INTEGER,
        role TEXT CHECK(role IN ('editor', 'viewer')),
        FOREIGN KEY(note_id) REFERENCES notes(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(note_id, user_id));`);

// Check if admin exists before inserting
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
    const hashedAdminPw = bcrypt.hashSync('admin123', 10);
    db.prepare('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)')
      .run('admin','admin@test.com',hashedAdminPw,'admin');
    console.log('Admin user created.');}

//Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();});
}

function checkNoteAccess(noteId, userId) {
    const note = db.prepare('SELECT user_id FROM notes WHERE id = ?').get(noteId);
    if (!note) return false; // Note doesn't exist
    if (note.user_id === userId) return 'owner'; // User is the owner

    const collaboration = db.prepare('SELECT role FROM collaborations WHERE note_id = ? AND user_id = ?').get(noteId, userId);
    return collaboration ? collaboration.role : false; // Returns 'editor', 'viewer', or false}


// Register
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields required' });
    }
    const hashedPw = bcrypt.hashSync(password, 10);
    try {
        const result = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)').run(username, email, hashedPw);
        res.status(201).json({ message: 'User created', userId: result.lastInsertRowid });
    } catch (err) {
        if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(409).json({ error: 'Username or email already exists' });
        }
        res.status(500).json({ error: 'Failed to create user' });
    }
});

// Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ error: 'Incorrect password' });
    }
    const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// CRUD for notes
app.post('/notes', authenticateToken, (req, res) => {
    const { title, content, tags } = req.body;
    const stmt = db.prepare('INSERT INTO notes (user_id, title, content, tags) VALUES (?, ?, ?, ?)');
    const result = stmt.run(req.user.userId, title, content, tags);
    res.status(201).json({ id: result.lastInsertRowid, title, content, tags });
});

app.get('/notes', authenticateToken, (req, res) => {
    // Show notes owned by the user OR shared with the user
    const notes = db.prepare(`
        SELECT n.*, 'owner' as permission FROM notes n WHERE n.user_id = ?
        UNION
        SELECT n.*, c.role as permission FROM notes n
        JOIN collaborations c ON n.id = c.note_id
        WHERE c.user_id = ?
    `).all(req.user.userId, req.user.userId);
    res.json(notes);
});


app.put('/notes/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { title, content, tags } = req.body;
    
    const permission = checkNoteAccess(id, req.user.userId);
    if (!permission) {
        return res.status(404).json({ error: 'Note not found or access denied' });
    }
    if (permission !== 'owner' && permission !== 'editor') {
        return res.status(403).json({ error: 'You do not have permission to edit this note' });
    }


    // The version is only saved if the note update is also successful.
    const updateTransaction = db.transaction((noteData) => {
        const note = db.prepare('SELECT content FROM notes WHERE id = ?').get(id);
        
        db.prepare('INSERT INTO note_versions (note_id, version_number, content) VALUES (?, (SELECT IFNULL(MAX(version_number), 0) + 1 FROM note_versions WHERE note_id = ?), ?)')
          .run(id, id, note.content);
        

        const result = db.prepare('UPDATE notes SET title = ?, content = ?, tags = ? WHERE id = ?')
          .run(noteData.title, noteData.content, noteData.tags, id);

        return result;
    });

    try {
        updateTransaction({ title, content, tags });
        res.json({ message: 'Note updated successfully' });
    } catch (err) {
        console.error("Update failed:", err);
        res.status(500).json({ error: 'Failed to update note' });
    }
});


app.delete('/notes/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
  
    const note = db.prepare('SELECT user_id FROM notes WHERE id = ?').get(id);
    if (!note || note.user_id !== req.user.userId) {
        return res.status(404).json({ error: 'Note not found or you are not the owner' });
    }

    const result = db.prepare('DELETE FROM notes WHERE id = ?').run(id);
    if (result.changes > 0) {
        res.json({ message: 'Note deleted successfully' });
    } else {
        res.status(404).json({ error: 'Note not found' });
    }
});


app.post('/notes/:id/share', authenticateToken, (req, res) => {
    const noteId = req.params.id;
    const ownerId = req.user.userId;
    const { shareWithUserId, role } = req.body;

    if (!shareWithUserId || !role) {
        return res.status(400).json({ error: 'shareWithUserId and role are required' });
    }
    
    const note = db.prepare('SELECT user_id FROM notes WHERE id = ?').get(noteId);
    if (!note || note.user_id !== ownerId) {
        return res.status(403).json({ error: 'You must be the owner to share this note' });
    }

    if (ownerId === shareWithUserId) {
        return res.status(400).json({ error: "You can't share a note with yourself" });
    }

    try {
        db.prepare('INSERT INTO collaborations (note_id, user_id, role) VALUES (?, ?, ?)')
          .run(noteId, shareWithUserId, role);
        res.status(201).json({ message: 'Note shared successfully' });
    } catch (err) {
        if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(409).json({ error: 'Note is already shared with this user.' });
        }
        res.status(500).json({ error: 'Could not share note' });
    }
});

// Retrieve versions
app.get('/notes/:id/versions', authenticateToken, (req, res) => {
    const { id } = req.params;
    const hasAccess = checkNoteAccess(id, req.user.userId);
    if (!hasAccess) {
        return res.status(404).json({ error: 'Note not found or access denied' });
    }

    const versions = db.prepare('SELECT * FROM note_versions WHERE note_id = ? ORDER BY version_number DESC').all(id);
    res.json(versions);
});

// This uses URL query parameters, which is the standard for REST APIs.
// e.g., /notes/search?tag=work&contains=report
app.get('/search/notes', authenticateToken, (req, res) => {
    const { tag, contains } = req.query;
    let sql = "SELECT * FROM notes WHERE user_id = ?";
    const params = [req.user.userId];

    if (tag) {
        sql += " AND tags LIKE ?";
        params.push(`%${tag}%`);}

    if (contains) {
        sql += " AND (title LIKE ? OR content LIKE ?)";
        params.push(`%${contains}%`, `%${contains}%`);}
    try {
        const results = db.prepare(sql).all(...params);
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: "Failed to search notes" });
    }
});

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
