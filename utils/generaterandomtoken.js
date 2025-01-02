const bcrypt = require('bcrypt');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const saltRounds = 10;
const randomToken = crypto.randomBytes(64).toString('hex');

bcrypt.hash(randomToken, saltRounds, (err, hash) => {
    if (err) {
        console.error('Error generating bcrypt hash:', err);
        return;
    }

    console.log('Random token:', randomToken);
    console.log('Bcrypt hash for random token:', hash);

    // Update the .env file with the hashed refresh token
    const envPath = path.join(__dirname, '.env');
    const envContent = fs.readFileSync(envPath, 'utf8');
    const updatedEnvContent = envContent.replace(/REFRESH_TOKEN=.*/, `REFRESH_TOKEN='${hash}'`);

    fs.writeFileSync(envPath, updatedEnvContent, 'utf8');
    console.log('.env file updated with hashed refresh token');
});