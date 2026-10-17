// tests/security-evidence.test.js
// Machine-verifiable evidence for every "PASS" claim in SECURITY_AUDIT_REPORT.md.
// Covers gaps not already in csrf-and-authz, auth, engine, exposure-and-headers:
//   • Gmail IDOR (user B cannot touch user A's Gmail integration)
//   • Exhaustive unauthenticated-access matrix (every protected route → 401)
//   • Analyzer output is always application/json (XSS via response content-type)
//   • AES-256-GCM: unique IVs per call, tamper detection, length-pinning

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startServer, Client, uniqueEmail, db } = require('./helpers');
const { encrypt, decrypt } = require('../lib/secrets');

let srv;
before(async () => { srv = await startServer(); });
after(async () => { await srv?.stop(); });

// ---------------------------------------------------------------------------
// 1. IDOR — Gmail integration is always scoped to req.user.id
// ---------------------------------------------------------------------------

test('Gmail IDOR: user B cannot read, toggle or delete user A\'s Gmail account', async () => {
    const aEmail = uniqueEmail('gmailowner');
    const bEmail = uniqueEmail('gmailattacker');
    const a  = await new Client(srv.base).signup(aEmail);
    const b  = await new Client(srv.base).signup(bEmail);
    const aId = (await db.get('SELECT id FROM users WHERE email = ?', [aEmail])).id;

    // Seed a Gmail account for A directly (real IMAP auth is out of scope).
    await db.run(
        `INSERT INTO gmail_accounts (user_id, email, secret, enabled, status)
         VALUES (?, ?, ?, 1, 'active')`,
        [aId, 'victim@gmail.com', 'v1:AAAA:BBBB:CCCC']
    );

    // User B's integrations list must not expose user A's Gmail row.
    const bList = await b.get('/api/integrations');
    assert.equal(bList.status, 200);
    assert.equal(bList.json.gmail, null, 'user B must not see user A\'s Gmail');

    // User B's toggle attempt hits no row for B → 404 (no data of A's leaked/changed).
    assert.equal(
        (await b.patch('/api/integrations/gmail', { enabled: false })).status, 404,
        'toggle with no Gmail for B'
    );

    // User B's delete is idempotent on their own absent row; A's row must survive.
    assert.equal((await b.del('/api/integrations/gmail')).status, 200);
    const aRow = await db.get('SELECT email FROM gmail_accounts WHERE user_id = ?', [aId]);
    assert.ok(aRow, 'user A\'s row must not be deleted by user B');
    assert.equal(aRow.email, 'victim@gmail.com');

    // User A can still read and manage their own integration.
    const aList = await a.get('/api/integrations');
    assert.ok(aList.json.gmail, 'user A can still see their Gmail');
});

// ---------------------------------------------------------------------------
// 2. Exhaustive unauthenticated-access matrix — every protected route → 401
// ---------------------------------------------------------------------------

test('every protected route returns 401 without a session', async () => {
    const anon = new Client(srv.base); // no cookies, no CSRF

    // [method, path, body | null]
    const cases = [
        ['GET',    '/api/session',                      null],
        ['POST',   '/api/logout',                       {}],
        ['GET',    '/api/user/profile',                 null],
        ['PUT',    '/api/user/profile',                 { fullName: 'x' }],
        ['PUT',    '/api/user/preferences',             { emailHighRisk: true }],
        ['POST',   '/api/user/change-password',         { currentPassword: 'x', newPassword: 'Correct-Horse-9' }],
        ['GET',    '/api/user/sessions',                null],
        ['DELETE', '/api/user/sessions/1',              null],
        ['POST',   '/api/user/upload-picture',          null],   // multipart; auth check fires before body parse
        ['DELETE', '/api/user/remove-picture',          null],
        ['POST',   '/api/user/resend-verification',     {}],
        ['POST',   '/api/user/verify-identity',         { documentType: 'PAN', documentNumber: 'ABCDE1234F', fullName: 'x', dob: '2000-01-01' }],
        ['DELETE', '/api/user/account',                 { password: 'x' }],
        ['GET',    '/api/stream',                       null],
        ['POST',   '/api/analyze/url',                  { url: 'https://example.com' }],
        ['POST',   '/api/analyze/message',              { text: 'test' }],
        ['GET',    '/api/detections',                   null],
        ['GET',    '/api/detections/1',                 null],
        ['PATCH',  '/api/detections/1',                 { status: 'resolved' }],
        ['GET',    '/api/overview',                     null],
        ['GET',    '/api/report',                       null],
        ['GET',    '/api/user/summary',                 null],
        ['GET',    '/api/integrations',                 null],
        ['POST',   '/api/integrations/gmail',           { email: 'x@gmail.com', appPassword: 'abcdefghijklmnop' }],
        ['PATCH',  '/api/integrations/gmail',           { enabled: false }],
        ['DELETE', '/api/integrations/gmail',           null],
        ['POST',   '/api/integrations/devices',         { name: 'Phone' }],
        ['DELETE', '/api/integrations/devices/1',       null],
    ];

    for (const [method, path, body] of cases) {
        const r = method === 'GET'    ? await anon.get(path)
                : method === 'POST'   ? await anon.post(path, body ?? {})
                : method === 'PUT'    ? await anon.put(path, body)
                : method === 'PATCH'  ? await anon.patch(path, body)
                : await anon.del(path, body ?? undefined);
        assert.equal(r.status, 401, `${method} ${path} must require auth`);
    }
});

// ---------------------------------------------------------------------------
// 3. XSS via response content-type — analyzer always returns application/json
// ---------------------------------------------------------------------------

test('analyzer responses are always application/json regardless of payload content', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('xssanalyzer'));
    const payloads = [
        { text: '<script>alert(document.cookie)</script>' },
        { text: '"><svg/onload=alert(1)>' },
        { text: "'; SELECT * FROM users; --" },
        { text: '\x00\x01\x1f' }, // control characters
        { text: 'normal text with no links, just words' },
    ];
    for (const body of payloads) {
        const r = await c.post('/api/analyze/message', body);
        assert.equal(r.status, 200, `expected 200 for ${JSON.stringify(body.text.slice(0, 30))}`);
        assert.match(r.headers.get('content-type'), /application\/json/i, 'must be JSON');
        assert.ok(r.json && typeof r.json === 'object', 'response must parse as JSON');
        // The browser never interprets this as HTML.
        assert.doesNotMatch(r.headers.get('content-type') ?? '', /text\/html/i, 'must not be HTML');
    }
});

// ---------------------------------------------------------------------------
// 4. AES-256-GCM: unique IVs, auth-tag tamper detection, length pinning
// ---------------------------------------------------------------------------

test('AES-256-GCM: unique IVs per call, tamper detection, and IV/tag length pinning', () => {
    const plain = 'test-gmail-app-password';
    const blob1 = encrypt(plain);
    const blob2 = encrypt(plain);

    // Format: v1:<iv_b64>:<tag_b64>:<data_b64>
    const [, iv1] = blob1.split(':');
    const [, iv2] = blob2.split(':');
    assert.notEqual(iv1, iv2, 'IVs must differ across calls (random nonce)');

    // Both blobs decrypt correctly to the original plaintext.
    assert.equal(decrypt(blob1), plain, 'decrypt(blob1)');
    assert.equal(decrypt(blob2), plain, 'decrypt(blob2)');

    // Flip one bit in the ciphertext — the GCM authentication tag must reject it.
    const parts = blob1.split(':');
    const dataBuf = Buffer.from(parts[3], 'base64');
    dataBuf[0] ^= 0x01;
    const tampered = [parts[0], parts[1], parts[2], dataBuf.toString('base64')].join(':');
    assert.throws(
        () => decrypt(tampered),
        err => /Unsupported state|unable to authenticate data|bad decrypt/i.test(err.message),
        'tampered ciphertext must be rejected'
    );

    // Truncated IV (8 bytes instead of 12) must be rejected before decryption.
    const shortIvBlob = [parts[0], Buffer.alloc(8).toString('base64'), parts[2], parts[3]].join(':');
    assert.throws(() => decrypt(shortIvBlob), /Malformed secret/, 'short IV rejected');

    // Truncated tag (8 bytes instead of 16) must be rejected before decryption.
    const shortTagBlob = [parts[0], parts[1], Buffer.alloc(8).toString('base64'), parts[3]].join(':');
    assert.throws(() => decrypt(shortTagBlob), /Malformed secret/, 'short auth tag rejected');

    // Unknown version string must be rejected.
    const unknownVer = ['v9', parts[1], parts[2], parts[3]].join(':');
    assert.throws(() => decrypt(unknownVer), /Unknown secret format/, 'unknown version rejected');
});

// ---------------------------------------------------------------------------
// 5. Account deletion: cascades to all user-linked tables
// ---------------------------------------------------------------------------

test('account deletion cascades to detections, sessions, Gmail, devices and credentials', async () => {
    const email = uniqueEmail('delcascade');
    const password = 'Correct-Horse-9';
    const c = await new Client(srv.base).signup(email, password);

    // Verify the user exists.
    const userId = (await db.get('SELECT id FROM users WHERE email = ?', [email])).id;
    assert.ok(userId, 'user must exist before deletion');

    // Seed rows that must be cascade-deleted.
    await db.run(
        `INSERT INTO detections (user_id, source, kind, target, risk, verdict, confidence, summary, report)
         VALUES (?, 'manual', 'url', 'https://evil.example/', 95, 'malicious', 90, 'seed', '{"kind":"url","signals":[]}')`,
        [userId],
    );
    await db.run(
        `INSERT INTO gmail_accounts (user_id, email, secret, enabled, status)
         VALUES (?, ?, ?, 1, 'active')`,
        [userId, 'victim@gmail.com', 'v1:AAAA:BBBB:CCCC'],
    );
    await db.run(
        `INSERT INTO devices (user_id, name, token_hash, platform, last_seen_at)
         VALUES (?, 'Test Phone', 'cascadetest', 'android', strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
        [userId],
    );

    // Confirm seeded rows exist.
    assert.ok(await db.get('SELECT user_id FROM detections WHERE user_id = ?', [userId]), 'detection must exist');
    assert.ok(await db.get('SELECT user_id FROM gmail_accounts WHERE user_id = ?', [userId]), 'Gmail row must exist');
    assert.ok(await db.get('SELECT user_id FROM devices WHERE user_id = ?', [userId]), 'device must exist');
    assert.ok(await db.get('SELECT user_id FROM sessions WHERE user_id = ?', [userId]), 'session must exist');
    assert.ok(await db.get('SELECT user_id FROM user_credentials WHERE user_id = ?', [userId]), 'credentials must exist');

    // Delete the account via the API (requires password confirmation).
    const r = await c.del('/api/user/account', { password });
    assert.equal(r.status, 200, `expected 200, got ${r.status}: ${r.text}`);

    // The user row itself is gone.
    assert.equal(await db.get('SELECT id FROM users WHERE id = ?', [userId]), undefined, 'user row must be deleted');

    // All cascaded tables must be empty for this user.
    const tables = ['detections', 'gmail_accounts', 'devices', 'sessions', 'user_credentials'];
    for (const t of tables) {
        const row = await db.get(`SELECT COUNT(*) n FROM ${t} WHERE user_id = ?`, [userId]);
        assert.equal(row.n, 0, `${t} must have 0 rows for the deleted user`);
    }
});

// ---------------------------------------------------------------------------
// 6. Production config requires Turnstile keys (CAPTCHA cannot be skipped)
// ---------------------------------------------------------------------------

test('production config validation fails without TURNSTILE keys', () => {
    const saved = {};
    const override = {
        NODE_ENV: 'production',
        PUBLIC_BASE_URL: 'https://example.fraudshield.app',
        TRUST_PROXY: '1',
        DATA_ENCRYPTION_KEY: require('crypto').randomBytes(32).toString('hex'),
        MAIL_TRANSPORT: 'gmail',
        EMAIL_USER: 'alerts@example.com',
        EMAIL_APP_PASSWORD: 'abcdefghijklmnop',
    };
    const clear = ['TURNSTILE_SITE_KEY', 'TURNSTILE_SECRET_KEY'];
    try {
        for (const k of [...Object.keys(override), ...clear]) saved[k] = process.env[k];
        for (const [k, v] of Object.entries(override)) process.env[k] = v;
        for (const k of clear) delete process.env[k];

        const { errors } = require('../lib/config').reload();
        assert.ok(
            errors.some(e => /TURNSTILE/i.test(e)),
            `expected a TURNSTILE error in production, got: ${JSON.stringify(errors)}`,
        );
    } finally {
        for (const [k, v] of Object.entries(saved)) {
            if (v === undefined) delete process.env[k];
            else process.env[k] = v;
        }
    }
});

// ---------------------------------------------------------------------------
// 7. Profile response omits the removed weekly-summary field
// ---------------------------------------------------------------------------

test('GET /user/profile does not expose email_weekly_summary_enabled', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('proffields'));
    const r = await c.get('/api/user/profile');
    assert.equal(r.status, 200);
    // Removed ghost field must not be returned
    assert.equal(r.json.email_weekly_summary_enabled, undefined, 'removed field must be absent from profile response');
    // Active preference field must still be present
    assert.ok('email_high_risk_enabled' in r.json, 'email_high_risk_enabled must still be present');
    assert.ok('email' in r.json, 'email must be present');
    assert.ok('id' in r.json, 'id must be present');
});

// ---------------------------------------------------------------------------
// 8. NUL bytes in user input must never reach the database (Postgres rejects \u0000)
// ---------------------------------------------------------------------------

test('NUL bytes in user input are stripped before DB write (no 500 on Postgres)', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('nulbytes'));

    // Analyze message — covered by test 3 but also checked here for completeness
    const r1 = await c.post('/api/analyze/message', { text: 'hello\x00world' });
    assert.notEqual(r1.status, 500, `analyze/message with NUL must not 500 (got ${r1.status})`);

    // Analyze URL — url field goes through validate() then into the DB
    const r2 = await c.post('/api/analyze/url', { url: 'https://example.com/\x00path' });
    assert.notEqual(r2.status, 500, `analyze/url with NUL must not 500 (got ${r2.status})`);

    // Profile update — fullName field is a free-text string stored in users table
    const r3 = await c.put('/api/user/profile', { fullName: 'Test\x00User' });
    assert.notEqual(r3.status, 500, `profile update with NUL must not 500 (got ${r3.status})`);
    assert.equal(r3.status, 200, `profile update with NUL after stripping must succeed`);

    // Verify the profile stored the sanitized (NUL-stripped) value, not the raw input
    const profile = await c.get('/api/user/profile');
    assert.ok(!profile.json.full_name.includes('\x00'), 'stored full_name must not contain NUL');
});

// ---------------------------------------------------------------------------
// 9. NUL bytes in Gmail-ingested data (subject, sender, body) reach no DB column
// ---------------------------------------------------------------------------

test('NUL bytes in Gmail-ingested email fields are stripped before DB write', async () => {
    const { analyzeMessage } = require('../engine');
    const { recordDetection } = require('../lib/detections');
    const email = uniqueEmail('gmailnul');
    await new Client(srv.base).signup(email);
    const { id: uid } = await db.get('SELECT id FROM users WHERE email = ?', [email]);

    // Mimic what integrations/gmail.js does after parsing a real e-mail whose
    // headers and body contain NUL bytes (some spam tools embed them).
    const report = await analyzeMessage({
        text: 'Win\x00 a prize click here http://phishing.example.com/',
        html: '',
        meta: { fromName: 'Evil\x00Sender', fromAddress: 'evil\x00@spam.example', replyTo: null, authResults: '' },
    });

    const row = await recordDetection(uid, {
        source: 'gmail',
        sender: 'Evil\x00Sender <evil\x00@spam.example>',
        subject: 'Win\x00 a prize',
        target: 'http://phishing.example.com/\x00',
        report,
    });
    assert.ok(row && row.id, 'detection row must be stored without error');

    const stored = await db.get(
        'SELECT sender, subject, target, summary FROM detections WHERE id = ?', [row.id]);
    assert.ok(!stored.sender.includes('\x00'), 'sender in DB must not contain NUL');
    assert.ok(!stored.subject.includes('\x00'), 'subject in DB must not contain NUL');
    assert.ok(!stored.target.includes('\x00'), 'target in DB must not contain NUL');
});
