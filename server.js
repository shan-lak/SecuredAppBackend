const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

//Load secrets
const APP_SIGNATURE_HASH = process.env.APP_SIGNATURE_HASH;
const HMAC_SECRET_KEY = process.env.HMAC_SECRET_KEY;

if(!APP_SIGNATURE_HASH || !HMAC_SECRET_KEY) {
    console.error("Missing required security secrets");
    process.exit(1);
}

app.use(cors());
app.use(express.json());

// Security Middleware
const verifyAppSignature = (req, res, next) => {
    const receivedAppSignature = req.headers['X-App-Signature'];
    const receivedNonce = req.headers['X-Nonce'];
    const receivedPayloadSignature = req.headers['X-Payload-Signature'];

    if (!receivedAppSignature || !receivedNonce || !receivedPayloadSignature) {
        return res.status(400).json({ error: 'Missing required headers' });
    }

    if(receivedAppSignature != APP_SIGNATURE_HASH) {
        console.warn(`Tampering attempt detected: Invalid app signature.`);
        return res.status(403).json({ error: 'Forbidden: Invalid App Signature' });
    }

    const requestTime = parseInt(receivedNonce, 10);
    const currentTime = Date.now();
    const FIVE_MINUTES_IN_MS = 5 * 60 * 1000;

    if (isNaN(requestTime) || Math.abs(currentTime - requestTime) > FIVE_MINUTES_IN_MS) {
        console.warn(`Stale request rejected. Nonce: ${receivedNonce}`);
        return res.status(403).json({ error: 'Forbidden: Stale or invalid request' });
    }

    const stringToSign = `${receivedAppSignature}.${receivedNonce}`;
    const expectedPayloadSignature = crypto.createHmac('sha256', HMAC_SECRET_KEY)
        .update(stringToSign)
        .digest('base64');

    try{
        const receivedBuf = Buffer.from(receivedPayloadSignature, 'base64');
        const expectedBuf = Buffer.from(expectedPayloadSignature, 'base64');

        if (receivedBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(receivedBuf, expectedBuf)) {
            console.warn(`Tampering attempt detected: Invalid payload signature.`);
            return res.status(403).json({ error: 'Forbidden: Invalid Payload Signature' });
        }
    } catch (error) {
        console.error(`Error processing payload signature: ${error.message}`);
        return res.status(500).json({ error: 'Internal Server Error' });
    }

    console.log("Request verified successfully!");

    next();
};

app.use('/api',verifyAppSignature);

app.get('/api/v1/sensitive-data', (req, res) => {
    res.json({ message: 'Secure data accessed successfully!' });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
