// routes/account.js — registration, sessions, password recovery, profile,
// identity verification, support.

const express = require('express');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const config = require('../lib/config');
const { run, get, all, tx } = require('../db');
const { log } = require('../lib/logger');
const { sha256, randomToken } = require('../lib/secrets');
const { createSession, clearCookie, loadSession, revokeSession, revokeAllForUser } = require('../lib/sessions');
const { authenticate, requireCsrf, rateLimit, loginThrottle, validate, httpError, EMAIL, PASSWORD } = require('../lib/http');
const { inspectImage } = require('../lib/images');
const { sendPasswordReset, sendEmailVerification } = require('../mailer');

const router = express.Router();
const AVATAR_DIR = path.join(config.uploadDir, 'avatars');
const BCRYPT_COST = 12;
const RESET_TTL_MS = 30 * 60 * 1000;
// Compared against when the account does not exist, so response time does not reveal registered e-mails.
const DUMMY_HASH = bcrypt.hashSync('timing-equaliser-not-a-password', BCRYPT_COST);

const ipKey = req => req.ip;
const authLimiter = rateLimit({ name: 'auth-ip', windowMs: 15 * 60 * 1000, max: 30, keyFn: ipKey, perIp: true, message: 'Too many attempts from this network. Try again in 15 minutes.' });
const recoveryLimiter = rateLimit({ name: 'recovery-ip', windowMs: 60 * 60 * 1000, max: 10, keyFn: ipKey, perIp: true, message: 'Too many recovery requests. Try again later.' });
const recoveryEmailLimiter = rateLimit({ name: 'recovery-email', windowMs: 60 * 60 * 1000, max: 3, keyFn: req => `e:${String(req.body?.email || '').toLowerCase()}`, message: 'Too many recovery requests. Try again later.' });

const avatarUpload = multer({
    storage: multer.diskStorage({
        // eslint-disable-next-line security/detect-non-literal-fs-filename -- path is server-generated (config dir + multer/regex-validated name), never user input
        destination: (req, file, cb) => fs.mkdir(AVATAR_DIR, { recursive: true }, err => cb(err, AVATAR_DIR)),
        // Server-chosen name; the client's filename and extension are never used.
        filename: (req, file, cb) => cb(null, `u${req.user.id}-${randomToken(9)}.upload`),
    }),
    limits: { fileSize: 2 * 1024 * 1024, files: 1, fields: 0 },
    fileFilter: (req, file, cb) => cb(null, /^image\/(png|jpeg|webp|gif)$/.test(file.mimetype)),
});

const removeAvatarFile = url => {
    const name = url && /^\/uploads\/avatars\/(u\d+-[\w-]+\.(png|jpg|webp|gif))$/.exec(url)?.[1];
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- path is server-generated (config dir + multer/regex-validated name), never user input
    if (name) fs.promises.unlink(path.join(AVATAR_DIR, name)).catch(() => {});
};

const baseUrl = req => config.publicBaseUrl || `${req.protocol}://${req.get('host')}`;

const VERIFY_TTL_MS = 24 * 60 * 60 * 1000;
/** Issue a single-use e-mail verification link; older links are invalidated. */
async function issueVerification(user, req) {
    const token = randomToken(32);
    await tx(async () => {
        await run(`UPDATE email_verifications SET used_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE user_id = ? AND used_at IS NULL`, [user.id]);
        await run('INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
            [user.id, sha256(token), new Date(Date.now() + VERIFY_TTL_MS).toISOString()]);
    });
    await sendEmailVerification(user, `${baseUrl(req)}/verify-email.html#token=${token}`);
}

// ---------------------------------------------------------------- registration & sessions
router.post('/register', authLimiter, validate({
    fullName: { type: 'string', required: true, min: 2, max: 120, label: 'Full name' },
    email: { ...EMAIL, required: true, label: 'Email' },
    password: { ...PASSWORD, required: true },
}), async (req, res) => {
    if (!config.allowRegistration) throw httpError(403, 'Registration is closed. Ask an administrator for access.');
    const { fullName, email, password } = req.valid;
    const generic = { message: 'If this address can be registered, the account is ready. Sign in to continue.' };

    const hash = await bcrypt.hash(password, BCRYPT_COST);
    try {
        const userId = await tx(async () => {
            const { lastID } = await run('INSERT INTO users (full_name, email) VALUES (?, ?)', [fullName, email]);
            await run('INSERT INTO user_credentials (user_id, password_hash) VALUES (?, ?)', [lastID, hash]);
            return lastID;
        });
        log.security('account.registered', { rid: req.id, ip: req.ip, uid: userId, level: 'info' });
        await issueVerification({ id: userId, full_name: fullName, email }, req);
    } catch (err) {
        if (!/UNIQUE/.test(err.message)) throw err;
        // Same response as success: registration must not reveal which e-mails exist.
        log.security('account.register_duplicate', { rid: req.id, ip: req.ip, level: 'info' });
    }
    res.status(201).json(generic);
});

router.post('/login', authLimiter, validate({
    email: { ...EMAIL, required: true, label: 'Email' },
    password: { type: 'string', trim: false, required: true, max: 256, label: 'Password' },
}), async (req, res) => {
    const { email, password } = req.valid;
    const key = sha256(email);
    const wait = loginThrottle.check(key);
    if (wait) {
        log.security('auth.login_throttled', { rid: req.id, ip: req.ip, account: key.slice(0, 12) });
        res.setHeader('Retry-After', wait);
        throw httpError(429, `Too many failed attempts for this account. Try again in ${Math.ceil(wait / 60)} minute(s).`);
    }

    const user = await get(`SELECT u.id, u.full_name, u.email, u.avatar_url, uc.password_hash
                            FROM users u JOIN user_credentials uc ON u.id = uc.user_id WHERE lower(u.email) = ?`, [email]);
    const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !ok) {
        const failures = loginThrottle.fail(key);
        log.security('auth.login_failed', { rid: req.id, ip: req.ip, account: key.slice(0, 12), failures });
        throw httpError(401, 'Invalid email or password.');
    }
    loginThrottle.succeed(key);

    // Opportunistically upgrade legacy hashes (cost 10) to the current cost.
    if (bcrypt.getRounds(user.password_hash) < BCRYPT_COST) {
        await run('UPDATE user_credentials SET password_hash = ? WHERE user_id = ?', [await bcrypt.hash(password, BCRYPT_COST), user.id]);
    }
    // Session fixation: any session cookie presented at login is discarded.
    const previous = await loadSession(req);
    if (previous) await revokeSession(previous.id);

    const session = await createSession(res, user, req);
    log.security('auth.login_succeeded', { rid: req.id, ip: req.ip, uid: user.id, level: 'info' });
    res.json({ message: 'Signed in.', csrf: session.csrf, user: { name: user.full_name, email: user.email, avatarUrl: user.avatar_url } });
});

router.get('/session', authenticate, (req, res) => {
    const s = req.session;
    res.json({ user: { name: s.full_name, email: s.email, avatarUrl: s.avatar_url }, csrf: s.csrf_token, expiresAt: s.expires_at });
});

router.post('/logout', authenticate, requireCsrf, async (req, res) => {
    await revokeSession(req.session.id);
    clearCookie(res);
    log.security('auth.logout', { rid: req.id, uid: req.user.id, level: 'info' });
    res.json({ message: 'Signed out.' });
});

// ---------------------------------------------------------------- password recovery
router.post('/password/forgot', recoveryLimiter, recoveryEmailLimiter, validate({ email: { ...EMAIL, required: true } }), async (req, res) => {
    const { email } = req.valid;
    const generic = { message: 'If an account exists for that address, a reset link has been sent.' };
    const user = await get('SELECT id, full_name, email FROM users WHERE lower(email) = ?', [email]);
    if (!user) {
        log.security('auth.reset_unknown_account', { rid: req.id, ip: req.ip, level: 'info' });
        return res.json(generic);
    }
    const token = randomToken(32);
    await tx(async () => {
        // Only the newest link is valid.
        await run(`UPDATE password_resets SET used_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE user_id = ? AND used_at IS NULL`, [user.id]);
        await run('INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
            [user.id, sha256(token), new Date(Date.now() + RESET_TTL_MS).toISOString()]);
    });
    // Token travels in the URL fragment so it never reaches server logs or Referer headers.
    await sendPasswordReset(user, `${baseUrl(req)}/reset-password.html#token=${token}`);
    log.security('auth.reset_requested', { rid: req.id, ip: req.ip, uid: user.id, level: 'info' });
    res.json(generic);
});

router.post('/password/reset', recoveryLimiter, validate({
    token: { type: 'string', required: true, min: 20, max: 100, pattern: /^[\w-]+$/ },
    newPassword: { ...PASSWORD, required: true, label: 'New password' },
}), async (req, res) => {
    const { token, newPassword } = req.valid;
    const hash = await bcrypt.hash(newPassword, BCRYPT_COST);
    const userId = await tx(async () => {
        const row = await get('SELECT id, user_id, expires_at, used_at FROM password_resets WHERE token_hash = ?', [sha256(token)]);
        if (!row || row.used_at || new Date(row.expires_at).getTime() < Date.now()) return null;
        await run(`UPDATE password_resets SET used_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE user_id = ? AND used_at IS NULL`, [row.user_id]);
        await run('UPDATE user_credentials SET password_hash = ? WHERE user_id = ?', [hash, row.user_id]);
        await revokeAllForUser(row.user_id);
        return row.user_id;
    });
    if (!userId) {
        log.security('auth.reset_token_invalid', { rid: req.id, ip: req.ip });
        throw httpError(400, 'This reset link is invalid or has expired. Request a new one.');
    }
    log.security('auth.password_reset', { rid: req.id, ip: req.ip, uid: userId });
    res.json({ message: 'Password updated. All sessions were signed out — sign in with the new password.' });
});

// ---------------------------------------------------------------- e-mail verification
router.post('/email/verify', recoveryLimiter, validate({
    token: { type: 'string', required: true, min: 20, max: 100, pattern: /^[\w-]+$/ },
}), async (req, res) => {
    const userId = await tx(async () => {
        const row = await get('SELECT id, user_id, expires_at, used_at FROM email_verifications WHERE token_hash = ?', [sha256(req.valid.token)]);
        if (!row || row.used_at || new Date(row.expires_at).getTime() < Date.now()) return null;
        await run(`UPDATE email_verifications SET used_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`, [row.id]);
        await run(`UPDATE users SET email_verified_at = COALESCE(email_verified_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = ?`, [row.user_id]);
        return row.user_id;
    });
    if (!userId) {
        log.security('account.verify_token_invalid', { rid: req.id, ip: req.ip, level: 'info' });
        throw httpError(400, 'This confirmation link is invalid or has expired. Request a new one from Settings.');
    }
    log.security('account.email_verified', { rid: req.id, uid: userId, level: 'info' });
    res.json({ message: 'E-mail address confirmed. High-risk alerts can now be delivered.' });
});

// ---------------------------------------------------------------- everything under /user requires a session + CSRF
router.use('/user', authenticate, requireCsrf);

router.get('/user/profile', async (req, res) => {
    const profile = await get(`SELECT id, full_name, email, phone_number, created_at, avatar_url, email_verified_at,
        email_high_risk_enabled, email_weekly_summary_enabled FROM users WHERE id = ?`, [req.user.id]);
    if (!profile) throw httpError(404, 'User not found.');
    const v = await get('SELECT verification_status FROM identity_verifications WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 1', [req.user.id]);
    profile.verification_status = v ? v.verification_status : 'Not Submitted';
    res.json(profile);
});

router.post('/user/resend-verification',
    rateLimit({ name: 'verify-resend', windowMs: 60 * 60 * 1000, max: 3, keyFn: req => `u${req.user.id}`, message: 'Too many confirmation e-mails. Try again later.' }),
    async (req, res) => {
        const user = await get('SELECT id, full_name, email, email_verified_at FROM users WHERE id = ?', [req.user.id]);
        if (user.email_verified_at) return res.json({ message: 'Your e-mail address is already confirmed.' });
        await issueVerification(user, req);
        res.json({ message: 'Confirmation e-mail sent. Check your inbox.' });
    });

router.put('/user/profile', validate({
    fullName: { type: 'string', required: true, min: 2, max: 120, label: 'Full name' },
    phone: { type: 'string', max: 20, pattern: /^\+?[\d\s()-]{6,20}$/, patternMessage: 'Enter a valid phone number.' },
}), async (req, res) => {
    await run('UPDATE users SET full_name = ?, phone_number = ? WHERE id = ?', [req.valid.fullName, req.valid.phone || null, req.user.id]);
    res.json({ message: 'Profile updated.' });
});

router.put('/user/preferences', validate({
    emailHighRisk: { type: 'boolean', required: true },
    emailWeeklySummary: { type: 'boolean', required: true },
}), async (req, res) => {
    await run('UPDATE users SET email_high_risk_enabled = ?, email_weekly_summary_enabled = ? WHERE id = ?',
        [+req.valid.emailHighRisk, +req.valid.emailWeeklySummary, req.user.id]);
    res.json({ message: 'Notification preferences saved.' });
});

router.post('/user/change-password', validate({
    currentPassword: { type: 'string', trim: false, required: true, max: 256 },
    newPassword: { ...PASSWORD, required: true, label: 'New password' },
}), async (req, res) => {
    const row = await get('SELECT password_hash FROM user_credentials WHERE user_id = ?', [req.user.id]);
    if (!row || !(await bcrypt.compare(req.valid.currentPassword, row.password_hash))) {
        log.security('auth.password_change_failed', { rid: req.id, uid: req.user.id });
        throw httpError(400, 'Current password is incorrect.');
    }
    await run('UPDATE user_credentials SET password_hash = ? WHERE user_id = ?', [await bcrypt.hash(req.valid.newPassword, BCRYPT_COST), req.user.id]);
    await revokeAllForUser(req.user.id, req.session.id);
    log.security('auth.password_changed', { rid: req.id, uid: req.user.id });
    res.json({ message: 'Password changed. Other sessions were signed out.' });
});

router.get('/user/sessions', async (req, res) => {
    const rows = await all(`SELECT id, created_at, last_seen_at, expires_at, ip, user_agent FROM sessions
                            WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY last_seen_at DESC`,
        [req.user.id, new Date().toISOString()]);
    res.json(rows.map(r => ({ ...r, current: r.id === req.session.id })));
});

router.delete('/user/sessions/:id', async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) throw httpError(400, 'Invalid session.');
    const { changes } = await run(`UPDATE sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                                  WHERE id = ? AND user_id = ? AND revoked_at IS NULL`, [id, req.user.id]);
    if (!changes) throw httpError(404, 'Session not found.');
    log.security('auth.session_revoked', { rid: req.id, uid: req.user.id, level: 'info' });
    res.json({ message: 'Session signed out.' });
});

router.post('/user/upload-picture', (req, res, next) => avatarUpload.single('avatar')(req, res, err => {
    if (err) return next(httpError(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400, err.code === 'LIMIT_FILE_SIZE' ? 'Image must be under 2 MB.' : 'Upload rejected.'));
    next();
}), async (req, res) => {
    if (!req.file) throw httpError(400, 'Upload a PNG, JPEG, WebP or GIF image under 2 MB.');
    let info;
    try {
        info = await inspectImage(req.file.path, ['png', 'jpeg', 'webp', 'gif']);
    } catch (err) {
        // eslint-disable-next-line security/detect-non-literal-fs-filename -- path is server-generated (config dir + multer/regex-validated name), never user input
        await fs.promises.unlink(req.file.path).catch(() => {});
        log.security('upload.rejected', { rid: req.id, uid: req.user.id, kind: 'avatar', reason: err.message });
        throw err;
    }
    // nosemgrep: ajinabraham.njsscan.traversal.resolve_path_traversal.join_resolve_path_traversal -- reviewed: file name is server-generated by multer (u<id>-<random>), extension from magic-byte sniffing
    const finalName = req.file.filename.replace(/\.upload$/, info.ext);
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- path is server-generated (config dir + multer/regex-validated name), never user input
    await fs.promises.rename(req.file.path, path.join(AVATAR_DIR, finalName));
    const avatarUrl = `/uploads/avatars/${finalName}`;
    const old = await get('SELECT avatar_url FROM users WHERE id = ?', [req.user.id]);
    await run('UPDATE users SET avatar_url = ? WHERE id = ?', [avatarUrl, req.user.id]);
    removeAvatarFile(old?.avatar_url);
    res.json({ message: 'Profile picture updated.', avatarUrl });
});

router.delete('/user/remove-picture', async (req, res) => {
    const old = await get('SELECT avatar_url FROM users WHERE id = ?', [req.user.id]);
    await run('UPDATE users SET avatar_url = NULL WHERE id = ?', [req.user.id]);
    removeAvatarFile(old?.avatar_url);
    res.json({ message: 'Profile picture removed.' });
});

const DOC_PATTERNS = {
    Aadhaar: /^\d{12}$/,
    PAN: /^[A-Z]{5}\d{4}[A-Z]$/,
    DL: /^[A-Z0-9 -]{8,20}$/,
    Passport: /^[A-Z]\d{7}$/,
};
router.post('/user/verify-identity', validate({
    fullNameOnDoc: { type: 'string', required: true, min: 2, max: 120 },
    dob: { type: 'string', required: true, pattern: /^\d{4}-\d{2}-\d{2}$/ },
    docType: { type: 'string', required: true, enum: Object.keys(DOC_PATTERNS) },
    docNumber: { type: 'string', required: true, max: 20 },
}), async (req, res) => {
    const { fullNameOnDoc, dob, docType } = req.valid;
    const docNumber = req.valid.docNumber.toUpperCase();
    if (!DOC_PATTERNS[docType].test(docNumber)) throw httpError(400, `That is not a valid ${docType} number.`);
    const born = new Date(`${dob}T00:00:00Z`);
    const age = (Date.now() - born) / (365.25 * 86400000);
    if (Number.isNaN(born.getTime()) || age < 13 || age > 120) throw httpError(400, 'Enter a valid date of birth.');

    const existing = await get("SELECT id FROM identity_verifications WHERE user_id = ? AND verification_status IN ('Pending','Approved')", [req.user.id]);
    if (existing) throw httpError(409, 'You already have an active verification request.');
    await run(`INSERT INTO identity_verifications (user_id, document_type, document_number_hash, full_name_on_doc, dob_on_doc)
               VALUES (?, ?, ?, ?, ?)`, [req.user.id, docType, await bcrypt.hash(docNumber, BCRYPT_COST), fullNameOnDoc, dob]);
    log.security('account.identity_submitted', { rid: req.id, uid: req.user.id, level: 'info' });
    res.json({ message: 'Verification submitted for review.' });
});

router.delete('/user/account', validate({ password: { type: 'string', trim: false, required: true, max: 256 } }), async (req, res) => {
    const row = await get('SELECT password_hash FROM user_credentials WHERE user_id = ?', [req.user.id]);
    if (!row || !(await bcrypt.compare(req.valid.password, row.password_hash))) {
        log.security('account.delete_failed', { rid: req.id, uid: req.user.id });
        throw httpError(400, 'Password is incorrect.');
    }
    await require('../integrations/gmail').stopWatcher(req.user.id);
    const avatar = await get('SELECT avatar_url FROM users WHERE id = ?', [req.user.id]);
    // ON DELETE CASCADE removes credentials, sessions, detections, Gmail secret, devices, resets.
    await run('DELETE FROM users WHERE id = ?', [req.user.id]);
    removeAvatarFile(avatar?.avatar_url);
    clearCookie(res);
    log.security('account.deleted', { rid: req.id, uid: req.user.id });
    res.json({ message: 'Your account and all associated data were deleted.' });
});

// ---------------------------------------------------------------- support
router.post('/support', rateLimit({ name: 'support-ip', windowMs: 60 * 60 * 1000, max: 10, keyFn: ipKey, perIp: true }), validate({
    name: { type: 'string', required: true, min: 2, max: 120 },
    email: { ...EMAIL, required: true },
    phone: { type: 'string', max: 20, pattern: /^\+?[\d\s()-]{6,20}$/, patternMessage: 'Enter a valid phone number.' },
    problem: { type: 'string', required: true, min: 10, max: 5000, label: 'Description' },
}), async (req, res) => {
    const session = await loadSession(req);
    const { name, email, phone, problem } = req.valid;
    await run('INSERT INTO support_tickets (user_id, name, email, phone_number, issue_description) VALUES (?, ?, ?, ?, ?)',
        [session?.user_id ?? null, name, email, phone || null, problem]);
    res.json({ message: 'Support ticket submitted.' });
});

module.exports = router;
module.exports.DOC_PATTERNS = DOC_PATTERNS;
