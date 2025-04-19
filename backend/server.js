const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = 3001;
const SECRET_KEY = 'your-secret-key'; // In production, use environment variable

app.use(cors());
app.use(bodyParser.json());

// Initialize database
const db = new sqlite3.Database('./starbit.db', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the Starbit database.');
});

// Create user_data table if it doesn't exist
db.run(`CREATE TABLE IF NOT EXISTS user_data (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  bits INTEGER DEFAULT 0,
  streak INTEGER DEFAULT 0,
  last_updated TEXT,
  habits TEXT,  -- JSON string of habits
  rewards TEXT, -- JSON string of rewards
  FOREIGN KEY(user_id) REFERENCES users(id),
  UNIQUE(user_id)
)`);

// Signup endpoint
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;

  // Basic validation
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    // Check if user already exists
    db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], async (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (row) {
        return res.status(400).json({ error: 'Username or email already exists' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert new user
      db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, hashedPassword],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Error creating user' });
          }

          // Create JWT token
          const token = jwt.sign({ userId: this.lastID }, SECRET_KEY, { expiresIn: '1h' });

          res.json({
            message: 'User created successfully',
            token,
            user: { id: this.lastID, username, email }
          });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login endpoint
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Find user by username or email
  db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create JWT token
    const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, username: user.username, email: user.email }
    });
  });
});

// Protected route example
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is protected data', user: req.user });
});

// Middleware to authenticate token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}


// Get user data
app.get('/api/user-data', authenticateToken, (req, res) => {
  const userId = req.user.userId;

  db.get('SELECT * FROM user_data WHERE user_id = ?', [userId], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (row) {
      // Parse the JSON strings back to objects
      const userData = {
        ...row,
        habits: JSON.parse(row.habits || '{}'),
        rewards: JSON.parse(row.rewards || '{}')
      };
      res.json(userData);
    } else {
      // Return default state if no data exists
      res.json({
        bits: 0,
        streak: 0,
        lastUpdated: null,
        habits: {},
        rewards: {}
      });
    }
  });
});

// Save user data
app.post('/api/save-data', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const { bits, streak, lastUpdated, habits, rewards } = req.body;

  // Convert objects to JSON strings for storage
  const habitsJson = JSON.stringify(habits);
  const rewardsJson = JSON.stringify(rewards);

  // Upsert (update or insert) user data
  db.run(
    `INSERT INTO user_data (user_id, bits, streak, last_updated, habits, rewards)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       bits = excluded.bits,
       streak = excluded.streak,
       last_updated = excluded.last_updated,
       habits = excluded.habits,
       rewards = excluded.rewards`,
    [userId, bits, streak, lastUpdated, habitsJson, rewardsJson],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Error saving data' });
      }
      res.json({ message: 'Data saved successfully' });
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});