// tests/helpers.js — isolated test environment.
// Must be required before any application module: it points the app at a
// temporary database, an in-memory mail outbox, and a random encryption key,
// and prevents the real .env from being loaded.

const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');
const { once } = require('events');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fraudshield-test-'));
Object.assign(process.env, {
    NODE_ENV: 'test',
    DOTENV_PATH: path.join(dir, 'does-not-exist.env'),
    DB_FILE: path.join(dir, 'test.db'),
    UPLOAD_DIR: path.join(dir, 'uploads'),
    DATA_ENCRYPTION_KEY: crypto.randomBytes(32).toString('hex'),
    MAIL_TRANSPORT: 'memory',
    LOG_LEVEL: process.env.TEST_LOG_LEVEL || 'silent',
    // Every test client is 127.0.0.1; scale per-IP limits (ratelimit.test.js runs at the real scale of 1).
    RATE_LIMIT_SCALE: process.env.RATE_LIMIT_SCALE || '100',
});
for (const k of ['EMAIL_USER', 'EMAIL_APP_PASSWORD', 'SMTP_HOST', 'PUBLIC_BASE_URL', 'TRUST_PROXY']) delete process.env[k];

const db = require('../db');
const { createApp } = require('../app');
const mailer = require('../mailer');

// libSQL releases its file handle when the native connection is garbage-collected; Windows
// refuses to rename/delete an open file, so collect before touching the database files.
async function releaseDbFiles() {
    if (process.platform !== 'win32' || !global.gc) return;
    global.gc();
    await new Promise(r => setTimeout(r, 50)); // native finalizers run after the collection
}

async function startServer() {
    await db.migrate();
    const server = createApp().listen(0, '127.0.0.1');
    await once(server, 'listening');
    const base = `http://127.0.0.1:${server.address().port}`;
    return {
        base,
        async stop() {
            server.closeAllConnections?.();
            await new Promise(r => server.close(r));
            await db.close();
            await releaseDbFiles();
            fs.rmSync(dir, { recursive: true, force: true });
        },
    };
}

/** Browser-like client: keeps cookies, sends Origin and the CSRF token on writes. */
class Client {
    constructor(base) {
        this.base = base;
        this.cookies = new Map();
        this.csrf = null;
    }

    cookieHeader() {
        return [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    }

    async req(method, p, { body, headers = {}, origin = this.base, csrf = true, raw } = {}) {
        const h = { ...headers };
        if (this.cookies.size) h.cookie = this.cookieHeader();
        if (origin && method !== 'GET') h.origin = origin;
        if (csrf && this.csrf && method !== 'GET' && !('x-csrf-token' in h)) h['x-csrf-token'] = this.csrf;
        let payload = raw;
        if (body !== undefined) { h['content-type'] = 'application/json'; payload = JSON.stringify(body); }
        const res = await fetch(this.base + p, { method, headers: h, body: payload, redirect: 'manual' });
        for (const c of res.headers.getSetCookie()) {
            const [pair] = c.split(';');
            const i = pair.indexOf('=');
            const name = pair.slice(0, i);
            const value = pair.slice(i + 1);
            if (/Max-Age=0/i.test(c) || value === '') this.cookies.delete(name); else this.cookies.set(name, value);
        }
        const text = await res.text();
        let json = null;
        try { json = JSON.parse(text); } catch { /* not JSON */ }
        return { status: res.status, headers: res.headers, json, text, setCookie: res.headers.getSetCookie() };
    }

    get(p, o) { return this.req('GET', p, o); }
    post(p, body, o = {}) { return this.req('POST', p, { ...o, body }); }
    put(p, body, o = {}) { return this.req('PUT', p, { ...o, body }); }
    patch(p, body, o = {}) { return this.req('PATCH', p, { ...o, body }); }
    del(p, body, o = {}) { return this.req('DELETE', p, { ...o, body }); }

    async register(email, password = 'Correct-Horse-9', fullName = 'Test Analyst') {
        return this.post('/api/register', { fullName, email, password });
    }

    async login(email, password = 'Correct-Horse-9') {
        const r = await this.post('/api/login', { email, password });
        if (r.status === 200) this.csrf = r.json.csrf;
        return r;
    }

    async signup(email, password) {
        await this.register(email, password);
        const r = await this.login(email, password);
        if (r.status !== 200) throw new Error(`login failed: ${r.status} ${r.text}`);
        return this;
    }
}

let counter = 0;
const uniqueEmail = (tag = 'user') => `${tag}.${process.pid}.${++counter}@example.test`;

module.exports = { startServer, Client, uniqueEmail, db, outbox: mailer.outbox, tmpDir: dir, releaseDbFiles };
