require('dotenv').config();
const request = require('supertest');
const { app, db, fetchKeyFromDatabase, storeKeysAtStartup, encryptKey, decryptKey } = require('../server');
const argon2 = require('argon2');
const { v4: uuidv4 } = require('uuid');

// Mock AES_KEY for testing purposes
process.env.NOT_MY_KEY = '12345678901234567890123456789012'; // 32-byte key

describe('JWKS Server', () => {

  beforeAll(() => {
    // Initialize database with test data
    db.run(`DELETE FROM keys`);
    db.run(`DELETE FROM users`);
    db.run(`DELETE FROM auth_requests`);
    db.run(`DELETE FROM auth_logs`);
  });

  describe('User Registration', () => {
    it('should register a new user and return a password', async () => {
      const response = await request(app)
        .post('/register')
        .send({
          username: 'testuser',
          email: 'testuser@example.com',
        });

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('password');
      expect(response.body.password).toBeDefined();

      // Check if user is created in DB
      db.get('SELECT * FROM users WHERE username = ?', ['testuser'], (err, row) => {
        expect(row).toBeDefined();
        expect(row.username).toBe('testuser');
        expect(row.email).toBe('testuser@example.com');
      });
    });

    it('should return an error if username or email is missing', async () => {
      const response = await request(app)
        .post('/register')
        .send({ username: 'testuser' });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Username and email are required');
    });
  });

  describe('Authentication', () => {
    let passwordHash;
    let username = 'authuser';

    beforeAll(async () => {
      const password = uuidv4();
      passwordHash = await argon2.hash(password, {
        timeCost: 3,
        memoryCost: 2 ** 16, // 64 MiB
        parallelism: 1,
        type: argon2.argon2id,
      });

      // Add a test user
      db.run(
        `INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`,
        [username, passwordHash, 'authuser@example.com']
      );
    });

    it('should authenticate a user with correct credentials', async () => {
      const response = await request(app)
        .post('/auth')
        .send({
          username: 'authuser',
          password: uuidv4(), // Correct password would match the hash stored
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('token');
      expect(response.body.token).toBeDefined();
    });

    it('should return an error for invalid credentials', async () => {
      const response = await request(app)
        .post('/auth')
        .send({
          username: 'authuser',
          password: 'wrongpassword', // Wrong password
        });

      expect(response.status).toBe(401);
      expect(response.body.error).toBe('Invalid username or password');
    });

    it('should rate-limit failed authentication attempts', async () => {
      // Make multiple failed attempts
      for (let i = 0; i < 12; i++) {
        await request(app)
          .post('/auth')
          .send({
            username: 'authuser',
            password: 'wrongpassword',
          });
      }

      const response = await request(app)
        .post('/auth')
        .send({
          username: 'authuser',
          password: 'wrongpassword',
        });

      expect(response.status).toBe(429); // Too many requests
      expect(response.body.error).toBe('Too many authentication attempts. Please try again later.');
    });
  });

  describe('Key Management and Encryption', () => {
    it('should store and fetch keys correctly from the database', async () => {
      // Call the function that stores keys at startup
      await new Promise((resolve) => {
        storeKeysAtStartup(resolve);
      });

      // Fetch the valid key from the database
      fetchKeyFromDatabase(false, (err, keyRow) => {
        expect(err).toBeNull();
        expect(keyRow).toHaveProperty('key');
        expect(keyRow.key).toBeDefined();
        expect(keyRow.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
      });

      // Fetch the expired key from the database
      fetchKeyFromDatabase(true, (err, keyRow) => {
        expect(err).toBeNull();
        expect(keyRow).toHaveProperty('key');
        expect(keyRow.key).toBeDefined();
        expect(keyRow.exp).toBeLessThan(Math.floor(Date.now() / 1000));
      });
    });

    it('should return error if no valid keys are found', async () => {
      // Simulate expired keys
      db.run(`DELETE FROM keys`);

      const response = await request(app).post('/auth').send({
        username: 'authuser',
        password: 'correctpassword',
      });

      expect(response.status).toBe(500);
      expect(response.body.error).toBe('No valid keys available');
    });

    it('should encrypt and decrypt keys correctly using AES', () => {
      const testKey = 'Test encryption key';
      const encryptedKey = encryptKey(testKey);
      const decryptedKey = decryptKey(encryptedKey);

      expect(decryptedKey).toBe(testKey); // Ensure decrypted key matches original
    });
  });

  describe('Authentication Logs', () => {
    it('should log successful authentication attempts', async () => {
      const response = await request(app)
        .post('/auth')
        .send({
          username: 'authuser',
          password: 'correctpassword', // Correct password (make sure this matches the hashed password)
        });
  
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('token');
  
      // Wait for the auth log to be inserted and check the log
      const logRow = await new Promise((resolve, reject) => {
        db.get('SELECT * FROM auth_logs WHERE request_ip = ?', [response.headers['x-forwarded-for']], (err, row) => {
          if (err) return reject(err);
          resolve(row);
        });
      });
  
      expect(logRow).toBeDefined();
      expect(logRow.request_ip).toBe(response.headers['x-forwarded-for']);
    });
  
    it('should log failed authentication attempts', async () => {
      const response = await request(app)
        .post('/auth')
        .send({
          username: 'authuser',
          password: 'wrongpassword',
        });
  
      expect(response.status).toBe(401);
      expect(response.body.error).toBe('Invalid username or password');
  
      // Wait for the auth log to be inserted and check the log
      const logRow = await new Promise((resolve, reject) => {
        db.get('SELECT * FROM auth_logs WHERE request_ip = ?', [response.headers['x-forwarded-for']], (err, row) => {
          if (err) return reject(err);
          resolve(row);
        });
      });
  
      expect(logRow).toBeDefined();
      expect(logRow.request_ip).toBe(response.headers['x-forwarded-for']);
    });
  });
});