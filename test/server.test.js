require('dotenv').config();
const request = require('supertest');
const { app, db } = require('../server');
const jwt = require('jsonwebtoken');
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
          password: uuidv4(), // Same password used above for hashing
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('token');
    });

    it('should return an error for incorrect password', async () => {
      const response = await request(app)
        .post('/auth')
        .send({
          username: 'authuser',
          password: 'wrongpassword',
        });

      expect(response.status).toBe(401);
      expect(response.body.error).toBe('Invalid username or password');
    });

    it('should handle authentication failures gracefully', async () => {
      const response = await request(app)
        .post('/auth')
        .send({
          username: 'unknownuser',
          password: 'anywrongpassword',
        });

      expect(response.status).toBe(401);
      expect(response.body.error).toBe('Invalid username or password');
    });
  });

  describe('Key Fetching', () => {
    beforeAll(async () => {
      // Insert a valid key in DB
      const validKey = await jwt.sign({ user: 'testuser' }, 'testkey');
      const exp = Math.floor(Date.now() / 1000) + 3600; // 1 hour expiration
      db.run(
        `INSERT INTO keys (key, exp) VALUES (?, ?)`,
        [validKey, exp]
      );
    });

    it('should fetch a valid key', async () => {
      const response = await request(app).get('/keys/valid');
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('key');
    });

    it('should return error if no valid key is found', async () => {
      // Make key expire
      const expiredTime = Math.floor(Date.now() / 1000) - 3600;
      db.run(`UPDATE keys SET exp = ?`, [expiredTime]);

      const response = await request(app).get('/keys/valid');
      expect(response.status).toBe(500);
      expect(response.body.error).toBe('No valid keys available');
    });
  });

  describe('Rate Limiting', () => {
    it('should return an error after too many authentication attempts', async () => {
      // Make 6 requests in quick succession
      for (let i = 0; i < 6; i++) {
        const response = await request(app)
          .post('/auth')
          .send({ username: 'authuser', password: 'wrongpassword' });

        if (i === 5) {
          expect(response.status).toBe(429);
          expect(response.body.error).toBe('Too many authentication attempts. Please try again later.');
        } else {
          expect(response.status).toBe(401);
        }
      }
    });require('dotenv').config();
    const request = require('supertest');
    const { app, db } = require('../server');
    const jwt = require('jsonwebtoken');
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
              password: uuidv4(), // Same password used above for hashing
            });
    
          expect(response.status).toBe(200);
          expect(response.body).toHaveProperty('token');
        });
    
        it('should return an error for incorrect password', async () => {
          const response = await request(app)
            .post('/auth')
            .send({
              username: 'authuser',
              password: 'wrongpassword',
            });
    
          expect(response.status).toBe(401);
          expect(response.body.error).toBe('Invalid username or password');
        });
    
        it('should handle authentication failures gracefully', async () => {
          const response = await request(app)
            .post('/auth')
            .send({
              username: 'unknownuser',
              password: 'anywrongpassword',
            });
    
          expect(response.status).toBe(401);
          expect(response.body.error).toBe('Invalid username or password');
        });
      });
    
      describe('Key Fetching', () => {
        beforeAll(async () => {
          // Insert a valid key in DB
          const validKey = await jwt.sign({ user: 'testuser' }, 'testkey');
          const exp = Math.floor(Date.now() / 1000) + 3600; // 1 hour expiration
          db.run(
            `INSERT INTO keys (key, exp) VALUES (?, ?)`,
            [validKey, exp]
          );
        });
    
        it('should fetch a valid key', async () => {
          const response = await request(app).get('/keys/valid');
          expect(response.status).toBe(200);
          expect(response.body).toHaveProperty('key');
        });
    
        it('should return error if no valid key is found', async () => {
          // Make key expire
          const expiredTime = Math.floor(Date.now() / 1000) - 3600;
          db.run(`UPDATE keys SET exp = ?`, [expiredTime]);
    
          const response = await request(app).get('/keys/valid');
          expect(response.status).toBe(500);
          expect(response.body.error).toBe('No valid keys available');
        });
      });
    
      describe('Rate Limiting', () => {
        it('should return an error after too many authentication attempts', async () => {
          // Make 6 requests in quick succession
          for (let i = 0; i < 6; i++) {
            const response = await request(app)
              .post('/auth')
              .send({ username: 'authuser', password: 'wrongpassword' });
    
            if (i === 5) {
              expect(response.status).toBe(429);
              expect(response.body.error).toBe('Too many authentication attempts. Please try again later.');
            } else {
              expect(response.status).toBe(401);
            }
          }
        });
      });
    });
    
    afterAll(() => {
      // Clean up the database after tests
      db.close();
    });
    
  });
});

afterAll(() => {
  // Clean up the database after tests
  db.close();
});
