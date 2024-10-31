import express from 'express'; // Import Express
import jwt from 'jsonwebtoken'; // Import JWT library
import forge from 'node-forge'; // Import Forge for cryptography
import rateLimit from 'express-rate-limit'; // Correct import
import { v4 as uuidv4 } from 'uuid'; // UUID for unique IDs
import { openDatabase } from './db.js'; // Import database handling
import crypto from 'crypto'; // For encryption
import argon2 from 'argon2'; // For password hashing
import dotenv from 'dotenv';

dotenv.config();

const app = express(); // Create Express app
const port = process.env.PORT || 8080; // Set port

app.use(express.json()); // Parse JSON bodies

let db; // Database connection variable

// Open database connection
app.use(async (req, res, next) => {
    db = await openDatabase();
    next();
});

// Rate Limiter
const authLimiter = rateLimit({
    windowMs: 1000, // 1 second
    max: 10, // Limit each IP to 10 requests per windowMs
    message: 'Too many requests, please try again later.',
});

// Generate RSA key pair
let keys = []; // Store key pairs

function generateKeyPair(expired = false) {
    const keypair = forge.pki.rsa.generateKeyPair(2048);
    const privateKey = forge.pki.privateKeyToPem(keypair.privateKey);
    const publicKey = forge.pki.publicKeyToPem(keypair.publicKey);
    const kid = `key-${Date.now()}`;
    const expiresAt = new Date();
    expired ? expiresAt.setHours(expiresAt.getHours() - 1) : expiresAt.setHours(expiresAt.getHours() + 24);
    keys.push({ kid, publicKey, privateKey, expiresAt });
}

generateKeyPair(); // Valid key for testing
generateKeyPair(true); // Expired key for testing

// Get valid keys
function getValidKeys() {
    return keys.filter(key => new Date() < key.expiresAt);
}

// JWKS endpoint
app.get('/jwks', (req, res) => {
    try {
        const validKeys = getValidKeys();
        console.log('Valid keys found:', validKeys);
        if (validKeys.length === 0) {
            console.log('No valid keys found');
            return res.status(404).json({ error: 'No valid keys found' });
        }
        
        const responseKeys = validKeys.map(key => {
            const publicKey = forge.pki.publicKeyFromPem(key.publicKey);
            return {
                kty: 'RSA',
                kid: key.kid,
                use: 'sig',
                alg: 'RS256',
                n: publicKey.n.toString(16),
                e: publicKey.e.toString(16),
            };
        });
        console.log('Response keys:', responseKeys);
        res.json({ keys: responseKeys });
    } catch (error) {
        console.error('Error retrieving keys:', error);
        res.status(500).send('Internal Server Error');
    }
});

// User Registration
app.post('/register', async (req, res) => {
    const { username, email } = req.body;
    const password = uuidv4(); // Generate a secure password
    try {
        const passwordHash = await argon2.hash(password);
        await db.run(`INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`, [username, passwordHash, email]);
        res.status(201).json({ password });
    } catch (err) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Logging Authentication Requests
app.post('/auth', authLimiter, async (req, res) => {
    const { username, password } = req.body;
    const user = await db.get(`SELECT * FROM users WHERE username = ?`, [username]);

    if (user && await argon2.verify(user.password_hash, password)) {
        await db.run(`INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)`, [req.ip, user.id]);
        const expired = req.query.expired === 'true';
        let keyToUse;

        console.log(`Auth request received, expired: ${expired}`);
        if (expired) {
            keyToUse = keys.find(key => key.expiresAt <= new Date());
            if (!keyToUse) {
                console.log('No expired keys available');
                return res.status(400).json({ error: 'No expired keys available' });
            }
        } else {
            const validKeys = getValidKeys();
            if (validKeys.length === 0) {
                console.log('No valid keys available');
                return res.status(400).json({ error: 'No valid keys available' });
            }
            keyToUse = validKeys[0];
        }

        const payload = {
            sub: user.id,
            name: user.username,
            iat: Math.floor(Date.now() / 1000),
        };

        const tokenExpiry = expired ? Math.floor(Date.now() / 1000) - 60 : Math.floor(Date.now() / 1000) + (60 * 60);
        const token = jwt.sign(payload, keyToUse.privateKey, {
            algorithm: 'RS256',
            expiresIn: tokenExpiry - Math.floor(Date.now() / 1000),
            keyid: keyToUse.kid,
        });

        console.log('Generated token with kid:', keyToUse.kid);
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Authentication failed' });
    }
});

// AES Encryption of Private Keys
const ENCRYPTION_KEY = process.env.NOT_MY_KEY;

function encrypt(text) {
    if (!text) throw new Error("Text is required for encryption");
    
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted;
    
    try {
        encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
    } catch (error) {
        console.error('Encryption Error:', error);
        throw error;
    }
    
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    const [iv, encryptedText] = text.split(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(Buffer.from(encryptedText, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// Close the database connection when the server shuts down
process.on('SIGINT', async () => {
    if (db) {
        await db.close();
        console.log("Database connection closed.");
    }
    process.exit();
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

export { encrypt, decrypt }
export default app; // Export app
