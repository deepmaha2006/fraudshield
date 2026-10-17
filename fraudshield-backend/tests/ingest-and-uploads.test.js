const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { execFileSync } = require('child_process');
const zlib = require('zlib');
const sharp = require('sharp');
const { startServer, Client, uniqueEmail, db } = require('./helpers');

let srv;
before(async () => { srv = await startServer(); });
after(async () => { await srv?.stop(); });

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
    assert.match(avatarUrl, /^\/uploads\/avatars\/[A-Za-z0-9_-]{22}\.png$/, 'avatar name must be exactly 22-char random ID');
    assert.doesNotMatch(avatarUrl, /\/u\d+-/, 'avatar name must not embed a user ID');
    const served = await fetch(srv.base + avatarUrl);
    assert.equal(served.status, 200);
    assert.equal(served.headers.get('content-type'), 'image/png');
    assert.equal(served.headers.get('x-content-type-options'), 'nosniff');

    // Stored in the database (no disk needed): a new picture retires the old URL; removing clears it.
    const again = await upload(c, '/api/user/upload-picture', 'avatar', PNG_1x1, 'image/png', 'b.png');
    const { avatarUrl: second } = await again.json();
    assert.notEqual(second, avatarUrl);
    assert.equal((await fetch(srv.base + avatarUrl)).status, 404);
    assert.equal((await fetch(srv.base + second)).status, 200);
    assert.equal((await c.del('/api/user/remove-picture')).status, 200);
    assert.equal((await fetch(srv.base + second)).status, 404);
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

test('avatar: EXIF metadata is stripped and image is re-encoded on upload', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('avexif'));

    // Create a 2x2 JPEG with a real EXIF Make tag embedded.
    const base = await sharp({ create: { width: 2, height: 2, channels: 3, background: { r: 255, g: 0, b: 0 } } })
        .png().toBuffer();
    const jpegWithExif = await sharp(base)
        .withMetadata({ exif: { IFD0: { Make: 'TestCamera' } } })
        .jpeg().toBuffer();
    // Sanity-check: the test image really does have EXIF before upload.
    const inputMeta = await sharp(jpegWithExif).metadata();
    assert.ok(inputMeta.exif, 'test JPEG must carry EXIF before upload');

    const r = await upload(c, '/api/user/upload-picture', 'avatar', jpegWithExif, 'image/jpeg', 'photo.jpg');
    const body = await r.json();
    assert.equal(r.status, 200, `upload failed: ${JSON.stringify(body)}`);
    const { avatarUrl } = body;

    // Fetch the stored image and verify EXIF is gone.
    const served = await fetch(srv.base + avatarUrl);
    assert.equal(served.status, 200);
    const stored = Buffer.from(await served.arrayBuffer());
    const outputMeta = await sharp(stored).metadata();
    assert.equal(outputMeta.exif, undefined, 'EXIF must be stripped from the stored image');

    // The bytes must differ from the original (image was re-encoded, not stored as-is).
    assert.notDeepEqual(stored, jpegWithExif, 'image must be re-encoded, not stored as-is');
});

// ------------------------------------------------------------ avatar-name migration
const LEGACY_NAME = /^u\d+-[\w-]+\.(png|jpg|webp|gif)$/;
const NEW_NAME    = /^[A-Za-z0-9_-]{22}\.(png|jpg|webp|gif)$/;

test('avatar name migration: renames legacy u<id>-* rows and updates user references, --dry-run writes nothing', async () => {
    // Seed a legacy avatar row directly, bypassing the upload handler.
    const email = uniqueEmail('avmigrate');
    const reg = await new Client(srv.base).signup(email);
    const { id: userId } = await db.get('SELECT id FROM users WHERE email = ?', [email]);

    const legacyName = `u${userId}-abc123xyz.png`;
    const legacyUrl  = '/uploads/avatars/' + legacyName;
    const fakeBlob   = Buffer.from([0x89, 0x50, 0x4e, 0x47]); // PNG magic (4 bytes, just a stub)
    await db.run('INSERT INTO avatars (name, user_id, mime, data) VALUES (?, ?, ?, ?)', [legacyName, userId, 'image/png', fakeBlob]);
    await db.run('UPDATE users SET avatar_url = ? WHERE id = ?', [legacyUrl, userId]);

    // --dry-run must not change anything.
    const dryOut = execFileSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'migrate-avatar-names.js'), '--dry-run'], { env: process.env, encoding: 'utf8' });
    assert.match(dryOut, /dry.run/i, '--dry-run output must say so');
    assert.ok(await db.get('SELECT 1 FROM avatars WHERE name = ?', [legacyName]), 'legacy row must still exist after --dry-run');
    assert.ok((await db.get('SELECT avatar_url FROM users WHERE id = ?', [userId])).avatar_url === legacyUrl, 'user.avatar_url unchanged after --dry-run');

    // Real migration.
    const out = execFileSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'migrate-avatar-names.js')], { env: process.env, encoding: 'utf8' });
    assert.match(out, /Migrated \d+ avatar/i, 'migration must report success');

    // Legacy row is gone; a new row exists with a random name.
    assert.equal(await db.get('SELECT 1 FROM avatars WHERE name = ?', [legacyName]), undefined, 'legacy row must be deleted');
    const newRow = await db.get('SELECT name FROM avatars WHERE user_id = ?', [userId]);
    assert.ok(newRow, 'new avatar row must exist');
    assert.doesNotMatch(newRow.name, LEGACY_NAME, 'new name must not be legacy format');
    assert.match(newRow.name, NEW_NAME, 'new name must match random format');

    // user.avatar_url is updated to the new URL.
    const { avatar_url } = await db.get('SELECT avatar_url FROM users WHERE id = ?', [userId]);
    assert.ok(avatar_url, 'avatar_url must not be null');
    assert.doesNotMatch(avatar_url, /\/u\d+-/, 'user.avatar_url must not embed a user ID after migration');
    assert.match(avatar_url, /^\/uploads\/avatars\/[A-Za-z0-9_-]{22}\.(png|jpg|webp|gif)$/, 'user.avatar_url must match new 22-char format');

    // Running the migration again is a no-op (idempotent).
    const out2 = execFileSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'migrate-avatar-names.js')], { env: process.env, encoding: 'utf8' });
    assert.match(out2, /Nothing to migrate/i, 'second run must be a no-op');
});

test('avatar: legacy u<id>-* names are rejected by isAvatarName() and return 404', async () => {
    const email = uniqueEmail('av404');
    await new Client(srv.base).signup(email);
    const { id: userId } = await db.get('SELECT id FROM users WHERE email = ?', [email]);

    const legacyName = `u${userId}-shouldnotwork.png`;
    // Seed a row with the legacy name to confirm the NAME regex rejects it, not a DB absence.
    await db.run('INSERT INTO avatars (name, user_id, mime, data) VALUES (?, ?, ?, ?)',
        [legacyName, userId, 'image/png', Buffer.from([0x89, 0x50, 0x4e, 0x47])]);

    const r = await fetch(srv.base + '/uploads/avatars/' + legacyName);
    assert.equal(r.status, 404, 'legacy u<id>-* URL must return 404 after regex tightening');
});
