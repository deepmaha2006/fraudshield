// lib/secrets.js — AES-256-GCM encryption for credentials stored at rest
// (Gmail app passwords). The key never touches the database.

const crypto = require('crypto');
const config = require('./config');

const TAG_LENGTH = 16; // full 128-bit GCM tag

function key() {
    const hex = config.dataKey;
    if (!/^[0-9a-f]{64}$/i.test(hex)) {
        throw new Error('DATA_ENCRYPTION_KEY must be 64 hex characters (32 bytes). Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    }
    return Buffer.from(hex, 'hex');
}

function encrypt(plain) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key(), iv, { authTagLength: TAG_LENGTH });
    const data = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
    return ['v1', iv.toString('base64'), cipher.getAuthTag().toString('base64'), data.toString('base64')].join(':');
}

function decrypt(blob) {
    const [version, iv, tag, data] = String(blob).split(':');
    if (version !== 'v1') throw new Error('Unknown secret format');
    const ivBuf = Buffer.from(iv || '', 'base64');
    const tagBuf = Buffer.from(tag || '', 'base64');
    // Pin IV and tag lengths: without authTagLength, GCM accepts truncated tags,
    // which makes ciphertext forgery far cheaper (CWE-310).
    if (ivBuf.length !== 12 || tagBuf.length !== TAG_LENGTH) throw new Error('Malformed secret');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key(), ivBuf, { authTagLength: TAG_LENGTH });
    decipher.setAuthTag(tagBuf);
    return Buffer.concat([decipher.update(Buffer.from(data, 'base64')), decipher.final()]).toString('utf8');
}

const sha256 = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

module.exports = { encrypt, decrypt, sha256, randomToken };
