const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const { startServer, Client, uniqueEmail, db } = require('./helpers');
const { loginThrottle } = require('../lib/http');

let srv;
before(async () => { srv = await startServer(); });
after(async () => { await srv?.stop(); });

test('registration does not reveal whether an e-mail exists', async () => {
    const c = new Client(srv.base);
    const email = uniqueEmail('enum');
    const first = await c.register(email);
    const second = await c.register(email);
    assert.equal(first.status, 201);
    assert.equal(second.status, 201);
    assert.deepEqual(first.json, second.json);
});

test('login: generic error for wrong password and for unknown account', async () => {
    const email = uniqueEmail('generic');
    const c = await new Client(srv.base).signup(email);
    const wrong = await new Client(srv.base).login(email, 'Wrong-Password-1');
    const unknown = await new Client(srv.base).login(uniqueEmail('nobody'), 'Wrong-Password-1');
    assert.equal(wrong.status, 401);
    assert.equal(unknown.status, 401);
    assert.equal(wrong.json.message, unknown.json.message);
    assert.ok(c.csrf);
});

test('session cookie is HttpOnly + SameSite=Strict and no token is exposed to scripts', async () => {
    const email = uniqueEmail('cookie');
    const c = new Client(srv.base);
    await c.register(email);
    const r = await c.post('/api/login', { email, password: 'Correct-Horse-9' });
    assert.equal(r.status, 200);
    const cookie = r.setCookie.find(s => s.startsWith('fs_session='));
    assert.ok(cookie, 'session cookie set');
    assert.match(cookie, /HttpOnly/i);
    assert.match(cookie, /SameSite=Strict/i);
    assert.match(cookie, /Path=\//);
    assert.equal(r.json.token, undefined, 'no bearer token in the response body');
});

test('protected routes deny missing, tampered and forged sessions', async () => {
    for (const cookie of [undefined, 'fs_session=forged-token-value', 'fs_session=' + 'a'.repeat(43), 'fs_session=' + 'x'.repeat(500)]) {
        const r = await fetch(`${srv.base}/api/overview`, { headers: cookie ? { cookie } : {} });
        assert.equal(r.status, 401, `cookie=${cookie}`);
    }
    // Legacy bearer tokens are no longer accepted at all.
    const r = await fetch(`${srv.base}/api/overview`, { headers: { authorization: 'Bearer eyJhbGciOiJub25lIn0.eyJpZCI6MX0.' } });
    assert.equal(r.status, 401);
});

test('logout revokes the session server-side (a copied cookie stops working)', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('logout'));
    const stolen = c.cookieHeader();
    assert.equal((await c.post('/api/logout')).status, 200);
    const r = await fetch(`${srv.base}/api/session`, { headers: { cookie: stolen } });
    assert.equal(r.status, 401);
});

test('session fixation: a cookie presented at login is revoked and replaced', async () => {
    const email = uniqueEmail('fixation');
    const c = await new Client(srv.base).signup(email);
    const before = c.cookieHeader();
    await c.login(email);
    assert.notEqual(c.cookieHeader(), before);
    assert.equal((await fetch(`${srv.base}/api/session`, { headers: { cookie: before } })).status, 401);
    assert.equal((await c.get('/api/session')).status, 200);
});

test('expired and idle sessions are rejected', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('expiry'));
    await db.run("UPDATE sessions SET expires_at = '2000-01-01T00:00:00.000Z' WHERE revoked_at IS NULL AND id = (SELECT MAX(id) FROM sessions)");
    assert.equal((await c.get('/api/session')).status, 401);

    const d = await new Client(srv.base).signup(uniqueEmail('idle'));
    await db.run("UPDATE sessions SET last_seen_at = '2000-01-01T00:00:00.000Z' WHERE id = (SELECT MAX(id) FROM sessions)");
    assert.equal((await d.get('/api/session')).status, 401);
});

test('password policy: too short and over 72 bytes are rejected', async () => {
    const c = new Client(srv.base);
    assert.equal((await c.register(uniqueEmail('short'), 'Abc12!')).status, 400);
    assert.equal((await c.register(uniqueEmail('long'), 'é'.repeat(40))).status, 400); // 80 bytes
});

test('per-account login throttling engages after repeated failures', async () => {
    loginThrottle.reset();
    const email = uniqueEmail('throttle');
    await new Client(srv.base).signup(email);
    const c = new Client(srv.base);
    for (let i = 0; i < 5; i++) assert.equal((await c.login(email, 'Bad-Guess-' + i)).status, 401);
    const locked = await c.login(email, 'Correct-Horse-9'); // even the right password is refused while locked
    assert.equal(locked.status, 429);
    assert.ok(Number(locked.headers.get('retry-after')) > 0);
    loginThrottle.reset();
});

test('changing the password revokes all other sessions', async () => {
    const email = uniqueEmail('pwchange');
    const a = await new Client(srv.base).signup(email);
    const b = await new Client(srv.base).login(email).then(() => null);
    const other = new Client(srv.base);
    await other.login(email);
    const r = await a.post('/api/user/change-password', { currentPassword: 'Correct-Horse-9', newPassword: 'New-Password-77' });
    assert.equal(r.status, 200);
    assert.equal((await other.get('/api/session')).status, 401, 'other session revoked');
    assert.equal((await a.get('/api/session')).status, 200, 'current session kept');
    assert.equal((await new Client(srv.base).login(email, 'Correct-Horse-9')).status, 401);
    assert.equal((await new Client(srv.base).login(email, 'New-Password-77')).status, 200);
    void b;
});

test('users can list and revoke their own sessions only', async () => {
    const email = uniqueEmail('sessions');
    const a = await new Client(srv.base).signup(email);
    const a2 = new Client(srv.base);
    await a2.login(email);
    const list = await a.get('/api/user/sessions');
    assert.equal(list.status, 200);
    assert.equal(list.json.filter(s => s.current).length, 1);
    const other = list.json.find(s => !s.current);
    assert.equal((await a.del(`/api/user/sessions/${other.id}`)).status, 200);
    assert.equal((await a2.get('/api/session')).status, 401);

    const intruder = await new Client(srv.base).signup(uniqueEmail('intruder'));
    const mine = list.json.find(s => s.current);
    assert.equal((await intruder.del(`/api/user/sessions/${mine.id}`)).status, 404);
    assert.equal((await a.get('/api/session')).status, 200);
});

test('legacy bcrypt cost-10 hashes are upgraded on successful login', async () => {
    const email = uniqueEmail('legacy');
    await new Client(srv.base).register(email);
    const user = await db.get('SELECT id FROM users WHERE email = ?', [email]);
    await db.run('UPDATE user_credentials SET password_hash = ? WHERE user_id = ?', [bcrypt.hashSync('Correct-Horse-9', 10), user.id]);
    assert.equal((await new Client(srv.base).login(email)).status, 200);
    const row = await db.get('SELECT password_hash FROM user_credentials WHERE user_id = ?', [user.id]);
    assert.equal(bcrypt.getRounds(row.password_hash), 12);
});

test('account deletion requires the password and removes all data', async () => {
    const email = uniqueEmail('delete');
    const c = await new Client(srv.base).signup(email);
    assert.equal((await c.del('/api/user/account', { password: 'wrong-password' })).status, 400);
    assert.equal((await c.del('/api/user/account', { password: 'Correct-Horse-9' })).status, 200);
    assert.equal(await db.get('SELECT id FROM users WHERE email = ?', [email]), undefined);
    assert.equal((await c.get('/api/session')).status, 401);
});
