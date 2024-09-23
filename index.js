import express from 'express'; // Import Express
import jwt from 'jsonwebtoken'; // Import JWT library
import forge from 'node-forge'; // Import Forge for cryptography

const app = express(); // Create Express app
const port = process.env.PORT || 8080; // Set port

app.use(express.json()); // Parse JSON bodies

let keys = []; // Store key pairs

// Generate RSA key pair
function generateKeyPair(expired = false) {
    const keypair = forge.pki.rsa.generateKeyPair(2048); // Create key pair
    const privateKey = forge.pki.privateKeyToPem(keypair.privateKey); // PEM format private key
    const publicKey = forge.pki.publicKeyToPem(keypair.publicKey); // PEM format public key

    const kid = `key-${Date.now()}`; // Unique key ID
    const expiresAt = new Date();
    expired ? expiresAt.setHours(expiresAt.getHours() - 1) : expiresAt.setHours(expiresAt.getHours() + 24); // Set expiration
  
    keys.push({ kid, publicKey, privateKey, expiresAt }); // Store keys
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
        const validKeys = getValidKeys(); // Get valid keys
        const responseKeys = validKeys.map(key => {
            const publicKey = forge.pki.publicKeyFromPem(key.publicKey);
            return {
                kty: 'RSA',
                kid: key.kid,
                use: 'sig',
                alg: 'RS256',
                n: publicKey.n.toString(16),
                e: publicKey.e.toString(16)
            };
        });
        res.json({ keys: responseKeys }); // Send keys as response
    } catch (error) {
        res.status(500).send('Internal Server Error'); // Error handling
    }
});

// Auth endpoint
app.post('/auth', (req, res) => {
    const expired = req.query.expired === 'true';
    let keyToUse;

    if (expired) {
        keyToUse = keys.find(key => key.expiresAt <= new Date());
        if (!keyToUse) return res.status(400).json({ error: 'No expired keys available' });
    } else {
        const validKeys = getValidKeys();
        if (validKeys.length === 0) return res.status(500).json({ error: 'No valid keys available' });
        keyToUse = validKeys[0];
    }

    const payload = {
        sub: '1234567890',
        name: 'John Doe',
        iat: Math.floor(Date.now() / 1000),
    };

    const tokenExpiry = expired ? Math.floor(Date.now() / 1000) - 60 : Math.floor(Date.now() / 1000) + (60 * 60);
    const token = jwt.sign(payload, keyToUse.privateKey, {
        algorithm: 'RS256',
        expiresIn: tokenExpiry - Math.floor(Date.now() / 1000),
        keyid: keyToUse.kid,
    });

    res.json({ token }); // Send token
});

// Start server
if (process.env.TEST_ENV !== 'true') {
    app.listen(port, () => {
        console.log(`Server running on port ${port}`);
    });
}

export default app; // Export app
