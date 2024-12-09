require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const argon2 = require('argon2');
const rateLimit = require('express-rate-limit');

// Initialize Express
const app = express();
app.use(express.json()); // Support JSON request bodies

const port = 8080;
const dbFilePath = './totally_not_my_privateKeys.db';

// AES Encryption Key from Environment Variable
const AES_KEY = process.env.NOT_MY_KEY;

if (!AES_KEY || AES_KEY.length !== 32) {
  throw new Error('NOT_MY_KEY environment variable must be a 32-byte key');
}

// AES Encryption Helper Functions
function encryptKey(plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, encrypted]).toString('base64');
}

function decryptKey(ciphertext) {
  const buffer = Buffer.from(ciphertext, 'base64');
  const iv = buffer.slice(0, 16);
  const encrypted = buffer.slice(16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', AES_KEY, iv);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// Initialize SQLite Database
const db = new sqlite3.Database(dbFilePath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    // Create necessary tables
    db.run(
      `CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS auth_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        success INTEGER NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS auth_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )`
    );
  }
});

// Store keys at startup
async function storeKeysAtStartup() {
  const validKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  const expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });

  const validExpiration = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
  const expiredExpiration = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago

  const encryptedValidKey = encryptKey(validKeyPair.toPEM(true));
  const encryptedExpiredKey = encryptKey(expiredKeyPair.toPEM(true));

  db.run(`INSERT INTO keys (key, exp) VALUES (?, ?)`, [encryptedValidKey, validExpiration]);
  db.run(`INSERT INTO keys (key, exp) VALUES (?, ?)`, [encryptedExpiredKey, expiredExpiration]);
}

// Rate limiter for authentication with 10 requests per second
const authRateLimiter = rateLimit({
  windowMs: 1000,  // 1 second window
  max: 10,         // Limit to 10 requests per second
  message: {
    error: 'Too many authentication attempts. Please try again later.',
  },
  standardHeaders: true,  // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false,   // Disable the `X-RateLimit-*` headers
});


// Fetch Key from Database
function fetchKeyFromDatabase(expired, callback) {
  const currentTime = Math.floor(Date.now() / 1000);
  const query = expired
    ? `SELECT * FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1`
    : `SELECT * FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1`;

  db.get(query, [currentTime], (err, row) => {
    if (err) {
      console.error('Error fetching key from database:', err);
      callback(err, null);
    } else if (!row) {
      callback(new Error('No appropriate key found'), null);
    } else {
      try {
        const decryptedKey = decryptKey(row.key);
        callback(null, { ...row, key: decryptedKey });
      } catch (decryptErr) {
        console.error('Error decrypting key:', decryptErr);
        callback(decryptErr, null);
      }
    }
  });
}

// User Registration Endpoint
app.post('/register', async (req, res) => {
  const { username, email } = req.body;

  if (!username || !email) {
    return res.status(400).json({ error: 'Username and email are required' });
  }

  try {
    // Generate secure password
    const password = uuidv4();

    // Hash the password with Argon2
    const passwordHash = await argon2.hash(password, {
      timeCost: 3,
      memoryCost: 2 ** 16, // 64 MiB
      parallelism: 1,
      type: argon2.argon2id,
    });

    // Insert user into the database
    db.run(
      `INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`,
      [username, passwordHash, email],
      function (err) {
        if (err) {
          console.error('Error inserting user:', err);
          return res.status(500).json({ error: 'Failed to register user' });
        }

        // Respond with generated password
        res.status(201).json({ password });
      }
    );
  } catch (err) {
    console.error('Error during registration:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Example Authentication Endpoint with Rate Limiting
app.post('/auth', authRateLimiter, async (req, res) => {
  const { username, password } = req.body;
  const requestIp = req.ip;  // Capture the IP address of the requester

  if (!username || !password) {
    await logAuthRequest(username || 'unknown', false, requestIp);
    return res.status(400).json({ error: 'Username and password are required' });
  }

  db.get(
    `SELECT id, password_hash FROM users WHERE username = ?`,
    [username],
    async (err, row) => {
      if (err) {
        console.error('Database error during authentication:', err);
        await logAuthRequest(username, false, requestIp);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (!row) {
        await logAuthRequest(username, false, requestIp);
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      try {
        const passwordMatches = await argon2.verify(row.password_hash, password);

        if (passwordMatches) {
          await logAuthRequest(username, true, requestIp);
          const payload = { user: username, iat: Math.floor(Date.now() / 1000) };
          fetchKeyFromDatabase(false, (err, keyRow) => {
            if (err || !keyRow) {
              return res.status(500).json({ error: 'No valid keys available' });
            }

            const token = jwt.sign(payload, keyRow.key, {
              algorithm: 'RS256',
              header: { typ: 'JWT', alg: 'RS256', kid: keyRow.kid },
              expiresIn: 3600,
            });

            res.json({ token });
          });
        } else {
          await logAuthRequest(username, false, requestIp);
          res.status(401).json({ error: 'Invalid username or password' });
        }
      } catch (err) {
        console.error('Error verifying password:', err);
        await logAuthRequest(username, false, requestIp);
        res.status(500).json({ error: 'Failed to authenticate user' });
      }
    }
  );
});

// Helper function to log authentication request to the `auth_logs` table
function logAuthRequest(username, success, requestIp) {
  return new Promise((resolve, reject) => {
    db.get(
      `SELECT id FROM users WHERE username = ?`,
      [username],
      (err, row) => {
        if (err) {
          console.error('Error fetching user ID:', err);
          reject(err);
        } else {
          const userId = row ? row.id : null;  // Use user ID if found, otherwise null

          db.run(
            `INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)`,
            [requestIp, userId],
            function (err) {
              if (err) {
                console.error('Error logging authentication request:', err);
                reject(err);
              } else {
                resolve();
              }
            }
          );
        }
      }
    );
  });
}

// Start the server
app.listen(port, () => {
  console.log(`JWKS server running on port ${port}`);
  storeKeysAtStartup();
});

// Export app for testing
module.exports = { app, db, fetchKeyFromDatabase, storeKeysAtStartup, encryptKey, decryptKey };
