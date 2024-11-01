const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 8080;
const dbFilePath = './totally_not_my_privateKeys.db';

// Initialize SQLite Database
const db = new sqlite3.Database(dbFilePath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    db.run(
      `CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
      )`,
      (err) => {
        if (err) {
          console.error('Error creating keys table:', err);
        }
      }
    );
  }
});

// Generate and store keys at startup
async function storeKeysAtStartup() {
  const validKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  const expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });

  const validExpiration = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
  const expiredExpiration = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago

  console.log('Storing valid key:', validKeyPair.toPEM(true));
  console.log('Storing expired key:', expiredKeyPair.toPEM(true));

  db.run(`INSERT INTO keys (key, exp) VALUES (?, ?)`, [validKeyPair.toPEM(true), validExpiration]);
  db.run(`INSERT INTO keys (key, exp) VALUES (?, ?)`, [expiredKeyPair.toPEM(true), expiredExpiration]);
}

// Call storeKeysAtStartup at program start
storeKeysAtStartup();

// Helper to fetch key from database based on expiration requirement
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
      callback(null, row);
    }
  });
}

// POST:/auth endpoint
app.post('/auth', (req, res) => {
  const expired = req.query.expired === 'true';

  fetchKeyFromDatabase(expired, (err, keyRow) => {
    if (err || !keyRow) {
      return res.status(400).json({ error: expired ? 'No expired keys available' : 'No valid keys available' });
    }

    // Define payload and JWT options
    const payload = { user: 'sampleUser', iat: Math.floor(Date.now() / 1000) };
    const tokenExpiry = expired ? Math.floor(Date.now() / 1000) - 60 : Math.floor(Date.now() / 1000) + 3600;
    const options = {
      algorithm: 'RS256',
      header: { typ: 'JWT', alg: 'RS256', kid: keyRow.kid },
      expiresIn: tokenExpiry - payload.iat,
    };

    // Sign the JWT
    const token = jwt.sign(payload, keyRow.key, options);
    res.send(token);
  });
});

// GET:/.well-known/jwks.json endpoint
app.get('/.well-known/jwks.json', (req, res) => {
  const currentTime = Math.floor(Date.now() / 1000);
  const query = `SELECT kid, key FROM keys WHERE exp > ?`;

  db.all(query, [currentTime], async (err, rows) => {
    if (err) {
      console.error('Error fetching keys for JWKS:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    const keys = await Promise.all(
      rows.map(async (row) => {
        const jwk = await jose.JWK.asKey(row.key, 'pem');
        return jwk.toJSON();
      })
    );

    res.json({ keys });
  });
});

// Start server
const server = app.listen(port, () => {
  console.log(`Server started on http://localhost:${port}`);
});

// Export the app for testing
module.exports = { app, server, storeKeysAtStartup };