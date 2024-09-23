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
        const validKeys = getValidKeys(); 
        console.log('Valid keys found:', validKeys); // Log valid keys
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
                e: publicKey.e.toString(16)
            };
        });
        console.log('Response keys:', responseKeys); // Log response keys
        res.json({ keys: responseKeys });
    } catch (error) {
        console.error('Error retrieving keys:', error); // Log error details
        res.status(500).send('Internal Server Error');
    }
});

// Auth endpoint
app.post('/auth', (req, res) => {
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

    console.log('Generated token with kid:', keyToUse.kid); // Log generated token details
    res.json({ token });
});

// Start server
if (process.env.TEST_ENV !== 'true') {
    app.listen(port, () => {
        console.log(`Server running on port ${port}`);
    });
}

export default app; // Export app
