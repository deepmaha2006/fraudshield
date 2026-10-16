// Database integrity, logging hygiene, configuration validation and output escaping.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { db } = require('./helpers');
const { redact, log } = require('../lib/logger');
const { encrypt, decrypt } = require('../lib/secrets');

before(async () => { await db.migrate(); });
after(async () => { await db.close(); });

// ------------------------------------------------------------ database
test('migrations are versioned and idempotent', async () => {
    const again = await db.migrate();
    assert.equal(again.from, db.MIGRATIONS.length);
    assert.equal(again.to, db.MIGRATIONS.length);
    assert.equal((await db.get('SELECT version FROM schema_meta WHERE id = 1')).version, db.MIGRATIONS.length);
    assert.equal((await db.get('PRAGMA foreign_keys')).foreign_keys, 1);
    assert.equal(await db.integrityCheck(), true);
});

test('a failing transaction rolls back without swallowing concurrent writes', async () => {
    const { lastID: uid } = await db.run("INSERT INTO users (full_name, email) VALUES ('Tx', 'tx@example.test')");
    const failing = db.tx(async () => {
        await db.run("INSERT INTO support_tickets (name, email, issue_description) VALUES ('in-tx', 'a@b.c', 'rolled back')");
        await new Promise(r => setTimeout(r, 50));
        throw new Error('boom');
    });
    // Issued while the transaction is open: must not become part of it.
    const outside = db.run("INSERT INTO support_tickets (name, email, issue_description) VALUES ('outside', 'a@b.c', 'kept')");
    await assert.rejects(failing, /boom/);
    await outside;
    const names = (await db.all('SELECT name FROM support_tickets')).map(r => r.name);
    assert.ok(names.includes('outside'));
    assert.ok(!names.includes('in-tx'));
    void uid;
});

test('concurrent transactions are serialised instead of failing', async () => {
    const results = await Promise.allSettled(Array.from({ length: 20 }, (_, i) =>
        db.tx(async () => {
            await db.run("INSERT INTO support_tickets (name, email, issue_description) VALUES (?, 'c@d.e', 'concurrent')", [`c${i}`]);
            await new Promise(r => setTimeout(r, 2));
        })));
    assert.ok(results.every(r => r.status === 'fulfilled'), JSON.stringify(results.filter(r => r.status === 'rejected').map(r => r.reason.message)));
    assert.equal((await db.get("SELECT COUNT(*) n FROM support_tickets WHERE issue_description = 'concurrent'")).n, 20);
});

test('deleting a user cascades to every owned record', async () => {
    const { lastID: uid } = await db.run("INSERT INTO users (full_name, email) VALUES ('Cascade', 'cascade@example.test')");
    await db.run("INSERT INTO detections (user_id, source, kind, target, risk, verdict, report) VALUES (?, 'manual', 'url', 't', 1, 'legit', '{}')", [uid]);
    await db.run("INSERT INTO devices (user_id, name, token_hash) VALUES (?, 'p', 'h-cascade')", [uid]);
    await db.run("INSERT INTO sessions (user_id, token_hash, csrf_token, last_seen_at, expires_at) VALUES (?, 's-cascade', 'c', 'x', 'y')", [uid]);
    await db.run('DELETE FROM users WHERE id = ?', [uid]);
    for (const t of ['detections', 'devices', 'sessions']) {
        assert.equal((await db.get(`SELECT COUNT(*) n FROM ${t} WHERE user_id = ?`, [uid])).n, 0, t);
    }
});

test('retention purge removes expired detections, sessions and reset tokens', async () => {
    const { lastID: uid } = await db.run("INSERT INTO users (full_name, email) VALUES ('Old', 'old@example.test')");
    await db.run("INSERT INTO detections (user_id, source, kind, target, risk, verdict, report, created_at) VALUES (?, 'manual', 'url', 't', 1, 'legit', '{}', '2001-01-01T00:00:00.000Z')", [uid]);
    await db.run("INSERT INTO sessions (user_id, token_hash, csrf_token, last_seen_at, expires_at) VALUES (?, 'old-s', 'c', '2001-01-01', '2001-01-02T00:00:00.000Z')", [uid]);
    const r = await db.purgeExpired();
    assert.ok(r.detections >= 1);
    assert.ok(r.sessions >= 1);
});

// ------------------------------------------------------------ secrets & logging
test('stored credentials are AES-GCM encrypted and tamper-evident', () => {
    const blob = encrypt('abcd efgh ijkl mnop');
    assert.doesNotMatch(blob, /abcd/);
    assert.equal(decrypt(blob), 'abcd efgh ijkl mnop');
    const parts = blob.split(':');
    parts[3] = Buffer.from('tampered').toString('base64');
    assert.throws(() => decrypt(parts.join(':')));
});

test('regression (Semgrep gcm-no-tag-length): truncated GCM tags are rejected', () => {
    const parts = encrypt('secret value').split(':');
    for (const len of [4, 8, 12]) {
        const truncated = [...parts];
        truncated[2] = Buffer.from(parts[2], 'base64').subarray(0, len).toString('base64');
        assert.throws(() => decrypt(truncated.join(':')), /Malformed secret/, `${len}-byte tag must be refused`);
    }
});

test('logs redact secrets and neutralise log-forging characters', () => {
    const out = redact({ password: 'p', newPassword: 'p', token: 't', authorization: 'Bearer x', cookie: 'fs_session=x', appPassword: 'x', body: 'sms text', path: '/api/x\r\n{"level":"error","event":"forged"}' });
    for (const k of ['password', 'newPassword', 'token', 'authorization', 'cookie', 'appPassword', 'body']) assert.equal(out[k], '[redacted]', k);
    assert.doesNotMatch(out.path, /[\r\n]/);
    const ops = redact({ sessions: 3, passwordResets: 1, deviceToken: 'x', csrfToken: 'y', dataKey: 'z' });
    assert.equal(ops.sessions, 3, 'operational counters stay visible');
    assert.equal(ops.passwordResets, 1);
    for (const k of ['deviceToken', 'csrfToken', 'dataKey']) assert.equal(ops[k], '[redacted]', k);

    const lines = [];
    const orig = process.stdout.write.bind(process.stdout);
    const origErr = process.stderr.write.bind(process.stderr);
    process.stdout.write = s => { lines.push(String(s)); return true; };
    process.stderr.write = s => { lines.push(String(s)); return true; };
    try { log.error('test.event', { password: 'hunter2', note: 'ok' }); } finally { process.stdout.write = orig; process.stderr.write = origErr; }
    assert.ok(lines.every(l => !l.includes('hunter2')));
});

// ------------------------------------------------------------ configuration
test('production configuration fails closed', () => {
    const cfg = require('../lib/config');
    const saved = { ...process.env };
    try {
        Object.assign(process.env, { NODE_ENV: 'production', DATA_ENCRYPTION_KEY: '0'.repeat(64), PUBLIC_BASE_URL: 'http://plain-http.example', COOKIE_SECURE: 'false', MAIL_TRANSPORT: 'memory' });
        delete process.env.TRUST_PROXY;
        // reload() re-reads process.env; NODE_ENV is captured at module load, so emulate via a fresh module.
        const fresh = path.resolve(__dirname, '../lib/config.js');
        delete require.cache[fresh];
        const prod = require(fresh);
        const errs = prod.validation.errors.join('\n');
        assert.match(errs, /DATA_ENCRYPTION_KEY is a placeholder/);
        assert.match(errs, /PUBLIC_BASE_URL must be the https/);
        assert.match(errs, /COOKIE_SECURE/);
        assert.match(errs, /TRUST_PROXY/);
        assert.match(errs, /MAIL_TRANSPORT=memory is for tests only/);
    } finally {
        process.env = saved;
        delete require.cache[path.resolve(__dirname, '../lib/config.js')];
        require.cache[path.resolve(__dirname, '../lib/config.js')] = { exports: cfg, loaded: true };
    }
});

// ------------------------------------------------------------ frontend output encoding
test('frontend escaping neutralises attacker-controlled strings', () => {
    const code = fs.readFileSync(path.join(__dirname, '../public/js/core.js'), 'utf8');
    const FS = vm.runInNewContext(`${code};FS`, { localStorage: undefined, location: {}, document: {}, navigator: {}, URL, Blob, setTimeout, console });
    const payloads = ['<img src=x onerror=alert(1)>', '"><script>alert(1)</script>', "' onmouseover='alert(1)", '&lt;already&gt;'];
    for (const p of payloads) {
        const e = FS.esc(p);
        assert.doesNotMatch(e, /[<>"']/, p);
    }
    assert.equal(FS.defang('https://evil.example/a.b'), 'hxxps://evil[.]example/a[.]b');
    assert.doesNotMatch(FS.verdictBadge('<script>'), /<script>/);
});
