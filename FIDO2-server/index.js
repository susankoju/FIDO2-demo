require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse,
} = require('@simplewebauthn/server');

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use((req, res, next) => {
    console.log(req.url);
    next();
});

const userDB = new Map();

const rpName = process.env.RP_NAME;
const rpId = process.env.RP_ID;
const origin = process.env.ORIGIN;
const PORT = process.env.PORT;

app.post('/registration-initiate', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ error: 'Username is required!' });
    }

    const user = {
        username,
        id: uuidv4(),
        credentials: []
    }

    const options = await generateRegistrationOptions({
        rpName,
        rpID: rpId,
        userName: username,
        userID: Buffer.from(user.id),
        attestationType: 'none',
        authenticatorSelection: {
            userVerification: 'preferred'
        }
    });

    user.pendingChallenge = options.challenge;
    userDB.set(username, user);
    console.log(userDB)

    res.json(options);
});

app.post('/registration-complete', async (req, res) => {
    const { username, attestationResponse } = req.body;
    const user = userDB.get(username);

    if (!user || !user.pendingChallenge) {
        return res.status(400).json({ error: 'Invalid user or challenge!' });
    }

    try {
        const verification = await verifyRegistrationResponse({
            response: attestationResponse,
            expectedChallenge: user.pendingChallenge,
            expectedOrigin: origin,
            expectedRPID: rpId,
            requireUserVerification: false,
        });

        if (verification.verified) {
            user.credentials.push(verification.registrationInfo.credential);
            delete user.pendingChallenge
            userDB.set(username, user);
            console.log(userDB)
            res.json({ success: true })
        } else {
            res.status(400).json({ error: 'Verification failed' })
        }
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.post('/login-initiate', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ error: 'Username is required!' });
    }
    const user = userDB.get(username);

    if (!user || !user.credentials.length) {
        return res.status(404).json({ error: 'User not found or no credentials registered!' });
    }

    const options = await generateAuthenticationOptions({
        allowCredentials: user.credentials.map((cred) => ({
            id: cred.id,
            type: 'public-key',
            transports: cred.transports
        })),
        userVerification: 'preferred',
        rpID: rpId,
    });

    user.pendingChallenge = options.challenge;
    userDB.set(username, user);
    console.log(userDB)

    res.json(options);
});

app.post('/login-complete', async (req, res) => {
    const { username, authenticationResponse } = req.body;
    const user = userDB.get(username);

    if (!user || !user.pendingChallenge) {
        return res.status(404).json({ error: 'User not found or no credentials registered!' });
    }

    try {
        const credential = user.credentials.find((cred) => cred?.id === authenticationResponse.id);

        if (!credential) {
            return res.status(400).json({ error: 'Credential not found' })
        }

        const verification = await verifyAuthenticationResponse({
            response: authenticationResponse,
            expectedChallenge: user.pendingChallenge,
            expectedOrigin: origin,
            expectedRPID: rpId,
            credential,
            requireUserVerification: false
        });

        if (verification.verified) {
            delete user.pendingChallenge;
            userDB.set(username, user);
            console.log(userDB)
            res.json({ success: true })
        } else {
            res.status(400).json({ error: 'Verification failed' })
        }
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
})
