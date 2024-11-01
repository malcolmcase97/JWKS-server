const request = require('supertest');
const { app, server, storeKeysAtStartup } = require('../server'); // Adjust the path according to your project structure
const sqlite3 = require('sqlite3').verbose();

// Create a fresh SQLite database for testing
const testDbFilePath = './totally_not_my_privateKeys.db';
const db = new sqlite3.Database(testDbFilePath);

// Function to reset the test database
async function resetDatabase() {
  await new Promise((resolve, reject) => {
    db.serialize(() => {
      db.run(`DROP TABLE IF EXISTS keys`, (err) => {
        if (err) reject(err);
        db.run(
          `CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
          )`,
          (err) => {
            if (err) reject(err);
            resolve();
          }
        );
      });
    });
  });
}

// Before all tests, reset the database
beforeAll(async () => {
  await resetDatabase();
  await storeKeysAtStartup(); // Ensure to call your function that stores keys
});

// After all tests, close the database connection and server
afterAll((done) => {
  // Drop the keys table after tests
  db.serialize(() => {
    db.run(`DROP TABLE IF EXISTS keys`, (err) => {
      if (err) console.error(err);
      db.close(); // Close the database connection
      server.close(done); // Close the server
    });
  });
});

// Test cases
describe('JWKS Server', () => {
  test('POST /auth - valid key', async () => {
    const response = await request(app).post('/auth');
    expect(response.statusCode).toBe(200);
    expect(response.text).toMatch(/^eyJ/); // Check if the response is a JWT
  });

  test('POST /auth - expired key', async () => {
    const response = await request(app).post('/auth?expired=true');
    expect(response.statusCode).toBe(200);
    expect(response.text).toMatch(/^eyJ/); // Check if the response is a JWT
  });

  test('GET /.well-known/jwks.json - valid keys', async () => {
    const response = await request(app).get('/.well-known/jwks.json');
    expect(response.statusCode).toBe(200);
    expect(response.body.keys).toBeInstanceOf(Array);
    expect(response.body.keys.length).toBeGreaterThan(0); // Ensure there are valid keys
  });

  test('GET /.well-known/jwks.json - no valid keys', async () => {
    // Manually remove all valid keys from the database for this test
    await new Promise((resolve, reject) => {
      db.run(`DELETE FROM keys`, (err) => {
        if (err) reject(err);
        resolve();
      });
    });

    const response = await request(app).get('/.well-known/jwks.json');
    expect(response.statusCode).toBe(200);
    expect(response.body.keys).toEqual([]); // No valid keys should return an empty array
  });
});
