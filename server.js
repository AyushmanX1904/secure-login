const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.db', dir: __dirname }),
    secret: 'thiranex-secret-key-please-change',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 2
    }
  })
);

async function initDb() {
  const db = await open({
    filename: path.join(__dirname, 'auth.db'),
    driver: sqlite3.Database
  });

  await db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      twofa_secret TEXT,
      twofa_enabled INTEGER DEFAULT 0
    )
  `);

  return db;
}

function validateEmail(email) {
  return typeof email === 'string' && /\S+@\S+\.\S+/.test(email);
}

function validatePassword(password) {
  return typeof password === 'string' && password.length >= 8;
}

function requireLogin(req, res, next) {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
}

function requireAuthenticated(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  if (req.session.twofaEnabled && !req.session.isTwofaAuthenticated) {
    return res.redirect('/2fa-verify');
  }
  next();
}

app.get('/', (req, res) => {
  if (req.session.userId) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', requireAuthenticated, (req, res) => {
  res.render('dashboard', {
    email: req.session.email,
    twofaEnabled: req.session.twofaEnabled
  });
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!validateEmail(email) || !validatePassword(password)) {
    return res.status(400).send('Invalid email or password. Password must be at least 8 characters.');
  }

  const db = await initDb();
  const hashedPassword = await bcrypt.hash(password, 12);

  try {
    await db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email.toLowerCase(), hashedPassword]);
    res.redirect('/login?registered=1');
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(400).send('A user with this email already exists.');
    }
    console.error(err);
    res.status(500).send('Registration failed.');
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!validateEmail(email) || !validatePassword(password)) {
    return res.status(400).send('Invalid email or password.');
  }

  const db = await initDb();
  const user = await db.get('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).send('Invalid email or password.');
  }

  req.session.userId = user.id;
  req.session.email = user.email;
  req.session.twofaEnabled = Boolean(user.twofa_enabled);
  req.session.twofaSecret = user.twofa_secret;

  if (user.twofa_enabled) {
    return res.redirect('/2fa-verify');
  }

  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

app.get('/2fa-setup', requireLogin, async (req, res) => {
  const secret = speakeasy.generateSecret({ length: 20, name: `Thiranex (${req.session.email})` });
  req.session.tempTwofaSecret = secret.base32;

  const qrData = await qrcode.toDataURL(secret.otpauth_url);
  res.render('2fa-setup', { qrData });
});

app.post('/2fa-setup', requireLogin, async (req, res) => {
  const { token } = req.body;
  const base32Secret = req.session.tempTwofaSecret;

  if (!base32Secret) {
    return res.status(400).send('2FA setup session expired. Please try again.');
  }

  const verified = speakeasy.totp.verify({
    secret: base32Secret,
    encoding: 'base32',
    token,
    window: 1
  });

  if (!verified) {
    return res.status(400).send('Invalid 2FA token.');
  }

  const db = await initDb();
  await db.run('UPDATE users SET twofa_secret = ?, twofa_enabled = 1 WHERE id = ?', [base32Secret, req.session.userId]);
  req.session.twofaEnabled = true;
  req.session.twofaSecret = base32Secret;
  delete req.session.tempTwofaSecret;

  res.redirect('/dashboard');
});

app.get('/2fa-verify', requireLogin, (req, res) => {
  if (!req.session.twofaEnabled) {
    return res.redirect('/dashboard');
  }
  res.render('2fa-verify');
});

app.post('/2fa-verify', requireLogin, (req, res) => {
  const { token } = req.body;
  const verified = speakeasy.totp.verify({
    secret: req.session.twofaSecret,
    encoding: 'base32',
    token,
    window: 1
  });

  if (!verified) {
    return res.status(401).send('Incorrect 2FA code.');
  }

  req.session.isTwofaAuthenticated = true;
  res.redirect('/dashboard');
});

app.use((req, res) => {
  res.status(404).send('Page not found.');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server started at http://localhost:${PORT}`);
});
