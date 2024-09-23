import request from 'supertest';
import app from '../index.js';  // Adjust the path if necessary
import jwt from 'jsonwebtoken';

describe('JWKS Server', () => {

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
    const res = await request(app).post('/auth');
    expect(res.status).toBe(200);
    expect(typeof res.body.token).toBe('string');
    
    const decodedToken = jwt.decode(res.body.token, { complete: true });
    expect(decodedToken).toHaveProperty('header');
    expect(decodedToken.header).toHaveProperty('kid');
  });

  test('should return an expired JWT when expired=true', async () => {
    const res = await request(app).post('/auth?expired=true');
    expect(res.status).toBe(200);
    expect(typeof res.body.token).toBe('string');
    
    const decodedToken = jwt.decode(res.body.token, { complete: true });
    expect(decodedToken).toHaveProperty('header');
    expect(decodedToken.payload).toHaveProperty('exp');
    expect(decodedToken.payload.exp).toBeLessThan(Math.floor(Date.now() / 1000)); // Token should be expired
  });

  test('should return 404 for /jwks when no valid keys exist', async () => {
    // Clear keys to simulate no valid keys
    keys = []; // Ensure `keys` is properly scoped or imported if necessary
  
    const res = await request(app).get('/jwks');
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'No valid keys found');
  });
  
  test('should return 400 for /auth when no valid keys exist', async () => {
    // Clear keys to simulate no valid keys
    keys = []; // Ensure `keys` is properly scoped or imported if necessary
  
    const res = await request(app).post('/auth');
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'No valid keys available for authentication');
  });
  
  test('should return 400 for /auth when only expired keys exist', async () => {
    // Generate an expired key for testing
    generateKeyPair(true); // Ensure this function is available and correctly generates expired keys
  
    const res = await request(app).post('/auth');
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error', 'No valid keys available for authentication');
  });
  
});




