import request from 'supertest';
import app, { encrypt, decrypt } from '../index.js'; // Import encrypt and decrypt
import jwt from 'jsonwebtoken';
import { openDatabase } from '../db.js';

describe('JWKS Server', () => {
  let db;

  beforeAll(async () => {
    // Set up environment variables
    process.env.NOT_MY_KEY = '1234567890abcdef1234567890abcdef';

    db = await openDatabase(); // Open the database connection
  });

  afterAll(async () => {
    await db.close(); // Close the database connection

    delete process.env.NOT_MY_KEY;
  });

  test('should encrypt private keys', async () => {
    const key = 'mySecretPrivateKey';
    const encryptedKey = encrypt(key); // Call the encrypt function directly

    expect(encryptedKey).not.toBe(key); // Check that the key has been encrypted
  });

  test('should create users table', async () => {
    const tables = await db.all("SELECT name FROM sqlite_master WHERE type='table' AND name='users'");
    expect(tables.length).toBe(1);
    expect(tables[0].name).toBe('users');
  });

  test('should create auth_logs table', async () => {
    const tables = await db.all("SELECT name FROM sqlite_master WHERE type='table' AND name='auth_logs'");
    expect(tables.length).toBe(1);
    expect(tables[0].name).toBe('auth_logs');
  });

  test('should register a new user', async () => {
    const newUser = {
      username: 'testUser',
      email: 'test@example.com'
    };
    
    const res = await request(app).post('/register').send(newUser);
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('password'); // Adjusted to check for password return

    const user = await db.get('SELECT * FROM users WHERE username = ?', newUser.username);
    expect(user).toBeTruthy();
  });

  test('should log auth requests', async () => {
    const authRequest = {
      username: 'testUser',
      password: 'password123' // Use the correct generated password
    };

    await request(app).post('/auth').send(authRequest);
    
    const logs = await db.all('SELECT * FROM auth_logs');
    expect(logs.length).toBeGreaterThan(0); // Check that at least one log exists
    expect(logs[0]).toHaveProperty('request_ip');
    expect(logs[0]).toHaveProperty('user_id'); // Assuming user_id is set upon successful login
  });

  test('should limit auth requests', async () => {
    const authRequest = {
      username: 'testUser',
      password: 'password123' // Use the correct generated password
    };

    for (let i = 0; i < 5; i++) {
      await request(app).post('/auth').send(authRequest);
    }

    const res = await request(app).post('/auth').send(authRequest);
    expect(res.status).toBe(429); // Expecting Too Many Requests status
    expect(res.body).toHaveProperty('error', 'Too many requests, please try again later.');
  });

  test('should return valid public keys from /jwks', async () => {
    const res = await request(app).get('/jwks');
    expect(res.status).toBe(200);
    expect(res.body.keys).toBeInstanceOf(Array);
    res.body.keys.forEach(key => {
      expect(key).toHaveProperty('kid');
      expect(key.kty).toBe('RSA');
    });
  });

  test('should return a valid JWT from /auth', async () => {
    const authRequest = {
      username: 'testUser',
      password: 'password123' // Use the correct generated password
    };
    
    const res = await request(app).post('/auth').send(authRequest);
    expect(res.status).toBe(200);
    expect(typeof res.body.token).toBe('string');
    
    const decodedToken = jwt.decode(res.body.token, { complete: true });
    expect(decodedToken).toHaveProperty('header');
    expect(decodedToken.header).toHaveProperty('kid');
  });

  test('should return an expired JWT when expired=true', async () => {
    const authRequest = {
      username: 'testUser',
      password: 'password123' // Use the correct generated password
    };

    const res = await request(app).post('/auth?expired=true').send(authRequest);
    expect(res.status).toBe(200);
    expect(typeof res.body.token).toBe('string');
    
    const decodedToken = jwt.decode(res.body.token, { complete: true });
    expect(decodedToken).toHaveProperty('header');
    expect(decodedToken.payload).toHaveProperty('exp');
    expect(decodedToken.payload.exp).toBeLessThan(Math.floor(Date.now() / 1000)); // Token should be expired
  });

  test('should return 404 for /jwks when no valid keys exist', async () => {
    // Clear keys to simulate no valid keys
    global.keys = []; // Ensure `keys` is properly scoped or imported if necessary
  
    const res = await request(app).get('/jwks');
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'No valid keys found');
  });
  
  test('should return 400 for /auth when no valid keys exist', async () => {
    // Clear keys to simulate no valid keys
    global.keys = []; // Ensure `keys` is properly scoped or imported if necessary
  
    const authRequest = {
      username: 'testUser',
      password: 'password123' // Use the correct generated password
    };

    const res = await request(app).post('/auth').send(authRequest);
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'No valid keys available');
  });
  
  test('should return 400 for /auth when only expired keys exist', async () => {
    // Generate an expired key for testing
    generateKeyPair(true); // Ensure this function is available and correctly generates expired keys
  
    const authRequest = {
      username: 'testUser',
      password: 'password123' // Use the correct generated password
    };

    const res = await request(app).post('/auth').send(authRequest);
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'No valid keys available');
  });
  
});
