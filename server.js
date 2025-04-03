const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;

// Простой файловый кэш
const cache = {
  data: null,
  timestamp: null,
  get: function() {
    if (this.data && Date.now() - this.timestamp < 60000) { // 1 минута
      return this.data;
    }
    return null;
  },
  set: function(data) {
    this.data = data;
    this.timestamp = Date.now();
    // Сохраняем в файл для персистентности
    fs.writeFileSync(path.join(__dirname, 'cache.json'), JSON.stringify({
      data: this.data,
      timestamp: this.timestamp
    }));
  }
};

// Загрузка кэша при старте
if (fs.existsSync(path.join(__dirname, 'cache.json'))) {
  const cacheData = JSON.parse(fs.readFileSync(path.join(__dirname, 'cache.json')));
  cache.data = cacheData.data;
  cache.timestamp = cacheData.timestamp;
}

const users = [];

app.use(bodyParser.json());
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false
  }
}));

// Middleware для проверки авторизации
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  next();
};

// Роуты
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (users.some(u => u.username === username)) {
      return res.status(400).json({ message: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { id: Date.now().toString(), username, password: hashedPassword };
    users.push(user);
    res.status(201).json({ message: 'User created' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    req.session.userId = user.id;
    res.json({ message: 'Logged in' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/profile', requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.session.userId);
  res.json({ username: user.username });
});

app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ message: 'Logout failed' });
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out' });
  });
});

app.get('/data', requireAuth, (req, res) => {
  try {
    const cachedData = cache.get();
    if (cachedData) {
      return res.json({ data: cachedData, source: 'cache' });
    }
    
    // Генерация новых данных
    const newData = {
      value: Math.random().toString(36).substring(7),
      timestamp: Date.now()
    };
    
    cache.set(newData);
    res.json({ data: newData, source: 'new' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.use(express.static('public'));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});