const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('zlib');
const { startServer, Client, uniqueEmail, db } = require('./helpers');

let srv;
before(async () => { srv = await startServer(); });
after(async () => { await srv.stop(); });

// ------------------------------------------------------------ device ingest
async function pairedDevice() {
    const c = await new Client(srv.base).signup(uniqueEmail('device'));
    const r = await c.post('/api/integrations/devices', { name: 'Test phone' });
    return { c, token: r.json.token, id: r.json.id };
}
const ingest = (token, body, headers = {}) => fetch(`${srv.base}/api/ingest/sms`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Device ${token}` } : {}), ...headers },
    body: JSON.stringify(body),
});

test('ingest requires a valid device token', async () => {
    assert.equal((await ingest(null, { sender: 'X', body: 'hello' })).status, 401);
    assert.equal((await ingest('fsd_not-a-real-token', { sender: 'X', body: 'hello' })).status, 401);
});

test('a paired device can submit an SMS and gets a verdict (no network needed)', async () => {
    const { token } = await pairedDevice();
    const r = await ingest(token, { sender: 'AD-ELECTR', body: 'URGENT: electricity will be disconnected today. Install AnyDesk immediately to avoid penalty.' });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.ok(['malicious', 'suspicious'].includes(j.verdict));
    assert.ok(j.risk >= 30);
});

test('device tokens are stored hashed and stop working once revoked', async () => {
    const { c, token, id } = await pairedDevice();
    const row = await db.get('SELECT token_hash FROM devices WHERE id = ?', [id]);
    assert.notEqual(row.token_hash, token);
    assert.equal((await c.del(`/api/integrations/devices/${id}`)).status, 200);
    assert.equal((await ingest(token, { body: 'hello there' })).status, 401);
});

test('ingest ignores non-scalar fields and caps sizes', async () => {
    const { token } = await pairedDevice();
    const r = await ingest(token, { sender: { $ne: 1 }, body: ['a', 'b'] });
    assert.equal(r.status, 400, 'array body is not accepted as text');
    const ok = await ingest(token, { sender: 'S'.repeat(500), body: 'plain note ' + 'x'.repeat(10000), receivedAt: 'not-a-date' });
    assert.equal(ok.status, 200);
    const det = await db.get('SELECT sender, report FROM detections ORDER BY id DESC LIMIT 1');
    assert.ok(det.sender.length <= 64);
    assert.equal(JSON.parse(det.report).channel.receivedAt, null);
});

test('ingest is reachable cross-origin (token auth) but console APIs are not', async () => {
    const { token } = await pairedDevice();
    const r = await ingest(token, { body: 'hello there' }, { origin: 'https://some-forwarder.example' });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('access-control-allow-credentials'), null);
    const api = await fetch(`${srv.base}/api/overview`, { headers: { origin: 'https://evil.example' } });
    assert.equal(api.headers.get('access-control-allow-origin'), null);
});

// ------------------------------------------------------------ uploads
const PNG_1x1 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64');
function pngWithSize(w, h) {
    const b = Buffer.from(PNG_1x1);
    b.writeUInt32BE(w, 16);
    b.writeUInt32BE(h, 20);
    return b;
}
async function upload(client, path, field, buf, type, filename = 'a.png') {
    const form = new FormData();
    form.append(field, new Blob([buf], { type }), filename);
    return fetch(client.base + path, { method: 'POST', body: form, headers: { cookie: client.cookieHeader(), origin: client.base, 'x-csrf-token': client.csrf } });
}

test('avatar: content is verified, not the declared type (MIME spoofing)', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('avatar'));
    const html = Buffer.from('<html><script>alert(document.cookie)</script></html>');
    const spoofed = await upload(c, '/api/user/upload-picture', 'avatar', html, 'image/png', 'evil.html');
    assert.equal(spoofed.status, 415);

    const ok = await upload(c, '/api/user/upload-picture', 'avatar', PNG_1x1, 'image/png', '../../../etc/passwd.png');
    assert.equal(ok.status, 200);
    const { avatarUrl } = await ok.json();
    assert.match(avatarUrl, /^\/uploads\/avatars\/u\d+-[\w-]+\.png$/, 'server-chosen file name');
    const served = await fetch(srv.base + avatarUrl);
    assert.equal(served.status, 200);
    assert.equal(served.headers.get('content-type'), 'image/png');
    assert.equal(served.headers.get('x-content-type-options'), 'nosniff');
});

test('screenshot: decompression-bomb dimensions are refused before OCR', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('bomb'));
    const r = await upload(c, '/api/analyze/screenshot', 'screenshot', pngWithSize(60000, 60000), 'image/png');
    assert.equal(r.status, 413);
    const notImage = await upload(c, '/api/analyze/screenshot', 'screenshot', Buffer.from('%PDF-1.7 not an image'), 'image/png');
    assert.equal(notImage.status, 415);
});

test('oversized JSON bodies are rejected', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('bigjson'));
    const r = await c.post('/api/analyze/message', { text: 'x'.repeat(300 * 1024) });
    assert.equal(r.status, 413);
    void zlib;
});
