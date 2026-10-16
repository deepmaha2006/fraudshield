// routes/integrations.js — Gmail connector, Android device pairing, SMS ingest.

const express = require('express');
const os = require('os');
const { run, get, all } = require('../db');
const config = require('../lib/config');
const { log } = require('../lib/logger');
const { authenticate, requireCsrf, rateLimit, validate, httpError, EMAIL } = require('../lib/http');
const { encrypt, sha256, randomToken } = require('../lib/secrets');
const { recordDetection } = require('../lib/detections');
const { publish } = require('../lib/realtime');
const { analyzeMessage } = require('../engine');
const gmail = require('../integrations/gmail');

const router = express.Router();

function serverUrls(req) {
    // In production only the public HTTPS origin is advertised; LAN addresses are a development convenience.
    if (config.isProd) return [config.publicBaseUrl];
    const port = req.socket.localPort;
    const urls = [];
    for (const list of Object.values(os.networkInterfaces())) {
        for (const n of list || []) if (n.family === 'IPv4' && !n.internal) urls.push(`http://${n.address}:${port}`);
    }
    if (config.publicBaseUrl) urls.unshift(config.publicBaseUrl);
    return urls;
}

// ---------------------------------------------------------------- Android SMS ingest (device-token auth)
const deviceLimiter = rateLimit({ name: 'device', windowMs: 60 * 1000, max: 60, keyFn: req => `d${req.device.id}`, message: 'Device rate limit reached.' });
const ingestIpLimiter = rateLimit({ name: 'ingest-ip', windowMs: 60 * 1000, max: 120, keyFn: req => req.ip, perIp: true, message: 'Too many requests.' });

async function authenticateDevice(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Device ') ? header.slice(7).trim() : (req.headers['x-device-token'] || '').trim();
    if (!token || token.length > 100) return res.status(401).json({ message: 'Device token required.' });
    const device = await get('SELECT * FROM devices WHERE token_hash = ?', [sha256(token)]);
    if (!device) {
        log.security('device.auth_failed', { rid: req.id, ip: req.ip });
        return res.status(401).json({ message: 'Unknown or revoked device token.' });
    }
    req.device = device;
    next();
}

const scalar = v => (typeof v === 'string' || typeof v === 'number') ? String(v) : null;
function parseTime(raw) {
    if (!raw) return null;
    const d = new Date(/^\d+$/.test(raw) ? Number(raw) : raw);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

router.post('/ingest/sms', ingestIpLimiter, authenticateDevice, deviceLimiter, async (req, res) => {
    const b = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
    // Accept the companion app's payload and common SMS-forwarder field names; only scalars.
    // eslint-disable-next-line no-control-regex -- deliberately strips control characters (log/header injection defence)
    const sender = (scalar(b.sender ?? b.from ?? b.address ?? b.phone) || 'unknown').replace(/[\u0000-\u001f]/g, ' ').slice(0, 64);
    const body = (scalar(b.body ?? b.message ?? b.text ?? b.msg) || '').slice(0, 5000);
    const receivedAt = parseTime(scalar(b.receivedAt ?? b.timestamp));
    if (!body.trim()) throw httpError(400, 'SMS body is empty.');

    const { device } = req;
    await run(`UPDATE devices SET messages_received = messages_received + 1, last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`, [device.id]);
    publish(device.user_id, 'integration', { type: 'device', id: device.id, status: 'seen' });

    const report = await analyzeMessage({ text: body });
    report.channel = { type: 'sms', device: device.name, deviceId: device.id, sender, receivedAt };
    const detection = await recordDetection(device.user_id, {
        source: 'sms', sender, subject: null, target: report.links[0]?.url || report.preview.slice(0, 160), report,
    });
    res.json({
        id: detection.id,
        verdict: report.verdict,
        risk: report.risk,
        summary: report.summary,
        advice: report.verdict === 'legit' ? null : 'Do not tap links, call back, or share OTP / PIN. Delete and block the sender.',
    });
});

router.get('/ingest/ping', ingestIpLimiter, authenticateDevice, async (req, res) => {
    await run(`UPDATE devices SET last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`, [req.device.id]);
    publish(req.device.user_id, 'integration', { type: 'device', id: req.device.id, status: 'seen' });
    res.json({ ok: true, device: req.device.name });
});

// ---------------------------------------------------------------- everything below needs a console session
router.use('/integrations', authenticate, requireCsrf);

router.get('/integrations', async (req, res) => {
    const [g, devices] = await Promise.all([
        get('SELECT email, enabled, status, last_error, messages_scanned, last_event_at, created_at FROM gmail_accounts WHERE user_id = ?', [req.user.id]),
        all('SELECT id, name, platform, messages_received, last_seen_at, created_at FROM devices WHERE user_id = ? ORDER BY id', [req.user.id]),
    ]);
    res.json({ gmail: g ? { ...g, live: gmail.watcherStatus(req.user.id) } : null, devices, serverUrls: serverUrls(req) });
});

router.post('/integrations/gmail', rateLimit({ name: 'gmail-connect', windowMs: 10 * 60 * 1000, max: 8, keyFn: req => `g${req.user.id}` }), validate({
    email: { ...EMAIL, required: true, label: 'Gmail address' },
    appPassword: { type: 'string', required: true, max: 40, label: 'App Password' },
}), async (req, res) => {
    const { email } = req.valid;
    const appPassword = req.valid.appPassword.replace(/\s+/g, '');
    if (!/^[a-z]{16}$/i.test(appPassword)) throw httpError(400, 'Enter the 16-letter Google App Password (spaces are fine).');

    await gmail.testCredentials(email, appPassword);
    await run(`INSERT INTO gmail_accounts (user_id, email, secret, enabled, status, last_error, last_uid, uid_validity)
               VALUES (?, ?, ?, 1, 'connecting', NULL, NULL, NULL)
               ON CONFLICT(user_id) DO UPDATE SET email = excluded.email, secret = excluded.secret, enabled = 1,
               status = 'connecting', last_error = NULL, last_uid = NULL, uid_validity = NULL`,
        [req.user.id, email, encrypt(appPassword)]);
    gmail.startWatcher(req.user.id).catch(err => log.error('gmail.start_failed', { uid: req.user.id, message: err.message }));
    log.security('integration.gmail_connected', { rid: req.id, uid: req.user.id, level: 'info' });
    res.json({ message: `Monitoring ${email} in real time. The latest messages are being analysed now.` });
});

router.patch('/integrations/gmail', validate({ enabled: { type: 'boolean', required: true } }), async (req, res) => {
    const { enabled } = req.valid;
    const { changes } = await run('UPDATE gmail_accounts SET enabled = ?, status = ? WHERE user_id = ?', [+enabled, enabled ? 'connecting' : 'paused', req.user.id]);
    if (!changes) throw httpError(404, 'No Gmail account connected.');
    if (enabled) gmail.startWatcher(req.user.id).catch(err => log.error('gmail.start_failed', { uid: req.user.id, message: err.message }));
    else {
        await gmail.stopWatcher(req.user.id);
        publish(req.user.id, 'integration', { type: 'gmail', status: 'paused' });
    }
    res.json({ message: enabled ? 'Gmail monitoring resumed.' : 'Gmail monitoring paused.' });
});

router.delete('/integrations/gmail', async (req, res) => {
    await gmail.stopWatcher(req.user.id);
    await run('DELETE FROM gmail_accounts WHERE user_id = ?', [req.user.id]);
    publish(req.user.id, 'integration', { type: 'gmail', status: 'disconnected' });
    log.security('integration.gmail_disconnected', { rid: req.id, uid: req.user.id, level: 'info' });
    res.json({ message: 'Gmail disconnected and stored credentials deleted.' });
});

router.post('/integrations/devices', validate({ name: { type: 'string', max: 60, label: 'Device name' } }), async (req, res) => {
    const name = req.valid.name || 'Android phone';
    const count = await get('SELECT COUNT(*) n FROM devices WHERE user_id = ?', [req.user.id]);
    if (count.n >= 10) throw httpError(400, 'Device limit reached (10). Revoke an old device first.');
    const token = `fsd_${randomToken(24)}`;
    const { lastID } = await run('INSERT INTO devices (user_id, name, token_hash) VALUES (?, ?, ?)', [req.user.id, name, sha256(token)]);
    publish(req.user.id, 'integration', { type: 'device', id: lastID, status: 'paired' });
    log.security('integration.device_paired', { rid: req.id, uid: req.user.id, device: lastID, level: 'info' });
    // The raw token is returned exactly once; only its hash is stored.
    res.status(201).json({ id: lastID, name, token, endpoint: '/api/ingest/sms', serverUrls: serverUrls(req) });
});

router.delete('/integrations/devices/:id', async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id)) throw httpError(404, 'Device not found.');
    const { changes } = await run('DELETE FROM devices WHERE id = ? AND user_id = ?', [id, req.user.id]);
    if (!changes) throw httpError(404, 'Device not found.');
    publish(req.user.id, 'integration', { type: 'device', id, status: 'revoked' });
    log.security('integration.device_revoked', { rid: req.id, uid: req.user.id, device: id, level: 'info' });
    res.json({ message: 'Device revoked. Its token no longer works.' });
});

module.exports = router;
