const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startServer, Client, uniqueEmail, db, outbox } = require('./helpers');

let srv;
before(async () => { srv = await startServer(); });
after(async () => { await srv?.stop(); });

const tokenFromMail = msg => /#token=([\w-]+)/.exec(msg.text)[1];

test('forgot-password gives the same answer for unknown and known accounts', async () => {
    const known = uniqueEmail('known');
    await new Client(srv.base).register(known);
    const sentBefore = outbox.length;
    const u = await new Client(srv.base).post('/api/password/forgot', { email: uniqueEmail('unknown') });
    assert.equal(outbox.length, sentBefore, 'no mail for unknown accounts');
    const k = await new Client(srv.base).post('/api/password/forgot', { email: known });
    assert.equal(u.status, 200);
    assert.equal(k.status, 200);
    assert.deepEqual(u.json, k.json);
    assert.equal(outbox.length, sentBefore + 1);
    const mail = outbox.at(-1);
    assert.equal(mail.to, known);
    assert.match(mail.text, /\/reset-password\.html#token=[\w-]{40,}/, 'token travels in the URL fragment');
});

test('reset token works once, revokes sessions, and the old password stops working', async () => {
    const email = uniqueEmail('reset');
    const session = await new Client(srv.base).signup(email);
    await new Client(srv.base).post('/api/password/forgot', { email });
    const token = tokenFromMail(outbox.at(-1));

    const ok = await new Client(srv.base).post('/api/password/reset', { token, newPassword: 'Brand-New-Pass-1' });
    assert.equal(ok.status, 200);
    assert.equal((await session.get('/api/session')).status, 401, 'existing sessions revoked');
    assert.equal((await new Client(srv.base).login(email, 'Correct-Horse-9')).status, 401);
    assert.equal((await new Client(srv.base).login(email, 'Brand-New-Pass-1')).status, 200);

    const reuse = await new Client(srv.base).post('/api/password/reset', { token, newPassword: 'Another-Pass-22' });
    assert.equal(reuse.status, 400, 'single use');
});

test('expired, forged and superseded reset tokens are rejected', async () => {
    const email = uniqueEmail('expired');
    await new Client(srv.base).register(email);
    await new Client(srv.base).post('/api/password/forgot', { email });
    const first = tokenFromMail(outbox.at(-1));
    await new Client(srv.base).post('/api/password/forgot', { email });
    const second = tokenFromMail(outbox.at(-1));

    assert.equal((await new Client(srv.base).post('/api/password/reset', { token: first, newPassword: 'Another-Pass-22' })).status, 400, 'older link invalidated');
    assert.equal((await new Client(srv.base).post('/api/password/reset', { token: 'A'.repeat(43), newPassword: 'Another-Pass-22' })).status, 400, 'forged');

    await db.run("UPDATE password_resets SET expires_at = '2000-01-01T00:00:00.000Z' WHERE used_at IS NULL");
    assert.equal((await new Client(srv.base).post('/api/password/reset', { token: second, newPassword: 'Another-Pass-22' })).status, 400, 'expired');
});

test('reset tokens are stored hashed, never in clear', async () => {
    const email = uniqueEmail('hashed');
    await new Client(srv.base).register(email);
    await new Client(srv.base).post('/api/password/forgot', { email });
    const token = tokenFromMail(outbox.at(-1));
    const rows = await db.all('SELECT token_hash FROM password_resets');
    assert.ok(rows.every(r => r.token_hash !== token && /^[0-9a-f]{64}$/.test(r.token_hash)));
});

test('recovery e-mails are rate limited per address', async () => {
    const email = uniqueEmail('flood');
    await new Client(srv.base).register(email);
    const statuses = [];
    for (let i = 0; i < 5; i++) statuses.push((await new Client(srv.base).post('/api/password/forgot', { email })).status);
    assert.deepEqual(statuses.slice(0, 3), [200, 200, 200]);
    assert.equal(statuses[3], 429);
});
