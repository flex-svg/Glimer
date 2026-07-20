const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_super_secret_glimer_key_123';

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ===== ВАЖНО: ИСПОЛЬЗУЕМ /tmp ДЛЯ RENDER =====
const db = new sqlite3.Database('/tmp/glimer.db');

// Создание таблиц
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            avatar TEXT,
            bio TEXT,
            verified INTEGER DEFAULT 0,
            birthday TEXT,
            gender TEXT DEFAULT 'not_specified',
            blocked INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS verify_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            who TEXT NOT NULL,
            why TEXT NOT NULL,
            link TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
});

// 1. Регистрация
app.post('/api/register', async (req, res) => {
    const { username, name, email, password, avatar, bio, birthday, gender } = req.body;
    db.get("SELECT id FROM users WHERE username = ? OR email = ?", [username, email], async (err, row) => {
        if (err) return res.status(500).json({ error: "Ошибка базы данных" });
        if (row) return res.status(400).json({ error: "Юзернейм или почта уже заняты" });
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            "INSERT INTO users (username, name, email, password_hash, avatar, bio, birthday, gender) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [username, name, email, hashedPassword, avatar, bio, birthday, gender],
            function(err) {
                if (err) return res.status(500).json({ error: "Ошибка создания пользователя" });
                const newUser = { id: this.lastID, username, name, email, avatar, bio, verified: 0 };
                const token = jwt.sign({ id: this.lastID }, SECRET_KEY);
                res.json({ user: newUser, token });
            }
        );
    });
});

// 2. Авторизация
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) return res.status(500).json({ error: "Ошибка сервера" });
        if (!user) return res.status(401).json({ error: "Пользователь не найден" });
        const validPass = await bcrypt.compare(password, user.password_hash);
        if (!validPass) return res.status(401).json({ error: "Неверный пароль" });
        const token = jwt.sign({ id: user.id }, SECRET_KEY);
        const { password_hash, ...userData } = user;
        res.json({ user: userData, token });
    });
});

// 3. Глобальный поиск
app.get('/api/search', (req, res) => {
    const query = req.query.q;
    if (!query) return res.json({ users: [] });
    const searchPattern = `%${query}%`;
    db.all(
        "SELECT id, username, name, avatar, verified FROM users WHERE (username LIKE ? OR id LIKE ?) AND blocked = 0 LIMIT 20",
        [searchPattern, searchPattern],
        (err, users) => {
            if (err) return res.status(500).json({ error: "Ошибка поиска" });
            res.json({ users });
        }
    );
});

// 4. Получение профиля пользователя
app.get('/api/user/:identifier', (req, res) => {
    const identifier = req.params.identifier;
    const isId = !isNaN(identifier);
    let query = isId ? "SELECT id, username, name, avatar, bio, verified FROM users WHERE id = ?" : "SELECT id, username, name, avatar, bio, verified FROM users WHERE username = ?";
    db.get(query, [identifier], (err, user) => {
        if (err || !user) return res.status(404).json({ error: "Пользователь не найден" });
        res.json(user);
    });
});

// 5. Заявка на верификацию
app.post('/api/verify-request', (req, res) => {
    const { userId, who, why, link } = req.body;
    db.run(
        "INSERT INTO verify_requests (user_id, who, why, link) VALUES (?, ?, ?, ?)",
        [userId, who, why, link],
        function(err) {
            if (err) return res.status(500).json({ error: "Ошибка отправки заявки" });
            res.json({ success: true, message: "Заявка отправлена" });
        }
    );
});

app.listen(PORT, () => {
    console.log(`🚀 Glimer Backend запущен на https://glimer.onrender.com `);
});
