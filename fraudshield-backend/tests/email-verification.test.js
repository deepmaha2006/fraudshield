// Regression: alert e-mails must not be deliverable to addresses the account holder does not control.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startServer, Client, uniqueEmail, db, outbox } = require('./helpers');
const { recordDetection } = require('../lib/detections');

let srv;
before(async () => { srv = await startServer(); });
after(async () => { await srv.stop(); });

const tokenFrom = msg => /#token=([\w-]+)/.exec(msg.text)[1];
const maliciousReport = { kind: 'url', risk: 95, verdict: 'malicious', confidence: 100, summary: 'test', signals: [] };
const settle = () => new Promise(r => setTimeout(r, 100));

test('registration sends a single-use confirmation link (token in the fragment)', async () => {
    const email = uniqueEmail('verify');
    const before = outbox.length;
    await new Client(srv.base).register(email);
    assert.equal(outbox.length, before + 1);
    const mail = outbox.at(-1);
    assert.equal(mail.to, email);
    assert.match(mail.text, /\/verify-email\.html#token=[\w-]{40,}/);

    const token = tokenFrom(mail);
    assert.equal((await new Client(srv.base).post('/api/email/verify', { token })).status, 200);
    assert.equal((await new Client(srv.base).post('/api/email/verify', { token })).status, 400, 'single use');
    const u = await db.get('SELECT email_verified_at FROM users WHERE email = ?', [email]);
    assert.ok(u.email_verified_at);
});

test('duplicate registration does not e-mail the existing owner a new link', async () => {
    const email = uniqueEmail('dupverify');
    await new Client(srv.base).register(email);
    const n = outbox.length;
    await new Client(srv.base).register(email);
    assert.equal(outbox.length, n);
});

test('high-risk alerts are NOT sent to unverified addresses (anti mail-relay)', async () => {
    const victim = uniqueEmail('victim');
    const c = await new Client(srv.base).signup(victim); // attacker registers someone else's address
    const uid = (await db.get('SELECT id FROM users WHERE email = ?', [victim])).id;
    const n = outbox.length;
    await recordDetection(uid, { source: 'manual', target: 'https://x.example/', report: maliciousReport });
    await settle();
    assert.equal(outbox.length, n, 'no alert to an unverified address');

    await db.run("UPDATE users SET email_verified_at = '2026-01-01T00:00:00.000Z' WHERE id = ?", [uid]);
    await recordDetection(uid, { source: 'manual', target: 'https://x.example/', report: maliciousReport });
    await settle();
    assert.equal(outbox.length, n + 1, 'alert delivered once verified');
    assert.equal(outbox.at(-1).headers['X-FraudShield-Alert'], '1');
    void c;
});

test('resend is rate limited and expired links are refused', async () => {
    const email = uniqueEmail('resend');
    const c = await new Client(srv.base).signup(email);
    const statuses = [];
    for (let i = 0; i < 4; i++) statuses.push((await c.post('/api/user/resend-verification', {})).status);
    assert.deepEqual(statuses, [200, 200, 200, 429]);
    const token = tokenFrom(outbox.at(-1));
    await db.run("UPDATE email_verifications SET expires_at = '2000-01-01T00:00:00.000Z'");
    assert.equal((await new Client(srv.base).post('/api/email/verify', { token })).status, 400);
});
