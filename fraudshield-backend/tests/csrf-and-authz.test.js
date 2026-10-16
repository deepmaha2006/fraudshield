const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startServer, Client, uniqueEmail, db } = require('./helpers');

let srv;
before(async () => { srv = await startServer(); });
after(async () => { await srv.stop(); });

async function seedDetection(userId, extra = {}) {
    const { lastID } = await db.run(`INSERT INTO detections (user_id, source, kind, target, risk, verdict, confidence, summary, report)
        VALUES (?, 'manual', 'url', ?, 80, 'malicious', 90, 'seed', '{"kind":"url","signals":[]}')`, [userId, extra.target || 'https://seed.example/']);
    return lastID;
}
const uid = async email => (await db.get('SELECT id FROM users WHERE email = ?', [email])).id;

// ------------------------------------------------------------ CSRF
test('state-changing requests without the CSRF token are rejected', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('csrf'));
    const missing = await c.put('/api/user/preferences', { emailHighRisk: false, emailWeeklySummary: false }, { csrf: false });
    assert.equal(missing.status, 403);
    const wrong = await c.put('/api/user/preferences', { emailHighRisk: false, emailWeeklySummary: false }, { headers: { 'x-csrf-token': 'x'.repeat(32) } });
    assert.equal(wrong.status, 403);
    const ok = await c.put('/api/user/preferences', { emailHighRisk: false, emailWeeklySummary: false });
    assert.equal(ok.status, 200);
});

test('cross-origin requests are rejected even with valid cookies and token', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('origin'));
    const r = await c.put('/api/user/preferences', { emailHighRisk: true, emailWeeklySummary: true }, { origin: 'https://evil.example' });
    assert.equal(r.status, 403);
    const site = await c.req('PUT', '/api/user/preferences', { body: { emailHighRisk: true, emailWeeklySummary: true }, origin: null, headers: { 'sec-fetch-site': 'cross-site' } });
    assert.equal(site.status, 403);
});

test('login CSRF: a cross-site login POST is refused', async () => {
    const email = uniqueEmail('logincsrf');
    await new Client(srv.base).register(email);
    const r = await new Client(srv.base).post('/api/login', { email, password: 'Correct-Horse-9' }, { origin: 'https://evil.example' });
    assert.equal(r.status, 403);
});

// ------------------------------------------------------------ object-level authorization
test('a user cannot read, modify or enumerate another user\'s detections', async () => {
    const aEmail = uniqueEmail('owner');
    const a = await new Client(srv.base).signup(aEmail);
    const b = await new Client(srv.base).signup(uniqueEmail('attacker'));
    const id = await seedDetection(await uid(aEmail));

    assert.equal((await a.get(`/api/detections/${id}`)).status, 200);
    assert.equal((await b.get(`/api/detections/${id}`)).status, 404);
    assert.equal((await b.patch(`/api/detections/${id}`, { status: 'resolved' })).status, 404);
    const row = await db.get('SELECT status FROM detections WHERE id = ?', [id]);
    assert.equal(row.status, 'open', 'status unchanged');
    const list = await b.get('/api/detections?limit=200');
    assert.equal(list.json.items.some(d => d.id === id), false);
    const report = await b.get('/api/report?days=90');
    assert.equal(report.json.total, 0);
});

test('dashboard trend has 12 days and counts only the caller\'s detections', async () => {
    const email = uniqueEmail('trend');
    const c = await new Client(srv.base).signup(email);
    const id = await uid(email);
    await seedDetection(id);
    await seedDetection(id);
    const other = uniqueEmail('trendother');
    await new Client(srv.base).signup(other);
    await seedDetection(await uid(other));

    const r = await c.get('/api/overview');
    assert.equal(r.status, 200);
    assert.equal(r.json.trend.length, 12);
    assert.equal(r.json.trend.at(-1).day, new Date().toISOString().slice(0, 10));
    assert.equal(r.json.trend.reduce((s, d) => s + d.total, 0), 2);
});

test('a user cannot revoke another user\'s device', async () => {
    const a = await new Client(srv.base).signup(uniqueEmail('devowner'));
    const b = await new Client(srv.base).signup(uniqueEmail('devattacker'));
    const pair = await a.post('/api/integrations/devices', { name: 'Phone A' });
    assert.equal(pair.status, 201);
    assert.equal((await b.del(`/api/integrations/devices/${pair.json.id}`)).status, 404);
    assert.ok(await db.get('SELECT id FROM devices WHERE id = ?', [pair.json.id]));
});

test('unknown fields are rejected (no mass assignment)', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('mass'));
    const r = await c.put('/api/user/profile', { fullName: 'Name Here', id: 1, email: 'admin@example.test', email_high_risk_enabled: 0 });
    assert.equal(r.status, 400);
    const proto = await c.req('PUT', '/api/user/profile', { raw: '{"fullName":"Name Here","__proto__":{"admin":true}}', headers: { 'content-type': 'application/json' } });
    assert.equal(proto.status, 400);
    assert.equal({}.admin, undefined);
});

test('wrong types are rejected', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('types'));
    assert.equal((await c.put('/api/user/preferences', { emailHighRisk: 'true', emailWeeklySummary: 1 })).status, 400);
    assert.equal((await c.post('/api/analyze/url', { url: ['https://a.example', 'https://b.example'] })).status, 400);
    assert.equal((await c.post('/api/analyze/message', { text: { $gt: '' } })).status, 400);
});

test('pagination cannot be abused to return unbounded rows (negative LIMIT)', async () => {
    const email = uniqueEmail('limit');
    const c = await new Client(srv.base).signup(email);
    const id = await uid(email);
    for (let i = 0; i < 3; i++) await seedDetection(id);
    const r = await c.get('/api/detections?limit=-1');
    assert.equal(r.status, 200);
    assert.equal(r.json.items.length, 1);
    const big = await c.get('/api/detections?limit=100000');
    assert.ok(big.json.items.length <= 200);
});

test('search input is treated as data (SQL injection)', async () => {
    const email = uniqueEmail('sqli');
    const c = await new Client(srv.base).signup(email);
    await seedDetection(await uid(email));
    for (const q of ["' OR 1=1 --", '%', '_', "x') UNION SELECT password_hash FROM user_credentials --"]) {
        const r = await c.get(`/api/detections?q=${encodeURIComponent(q)}`);
        assert.equal(r.status, 200);
        assert.equal(r.json.items.length, 0, `q=${q}`);
    }
    // Other users' rows remain unreachable regardless of the search string.
    assert.ok((await db.get('SELECT COUNT(*) n FROM detections')).n > 1);
});

test('stored XSS payloads are returned as inert data with JSON content type', async () => {
    const email = uniqueEmail('xss');
    const c = await new Client(srv.base).signup(email);
    const payload = '<img src=x onerror=alert(1)>';
    assert.equal((await c.put('/api/user/profile', { fullName: payload })).status, 200);
    const r = await c.get('/api/user/profile');
    assert.match(r.headers.get('content-type'), /application\/json/);
    assert.equal(r.json.full_name, payload); // escaping is the renderer's job (FS.esc); see tests/frontend-escape.test.js
});
