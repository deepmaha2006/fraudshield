const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const net = require('net');
const { startServer, Client, uniqueEmail } = require('./helpers');

let srv;
before(async () => { srv = await startServer(); });
after(async () => { await srv.stop(); });

// Send a raw request line so the client does not normalise "../" away.
function rawGet(pathname) {
    const { port } = new URL(srv.base);
    return new Promise((resolve, reject) => {
        const sock = net.connect(port, '127.0.0.1', () => sock.write(`GET ${pathname} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`));
        let data = '';
        sock.on('data', d => { data += d; });
        sock.on('end', () => resolve({ status: Number(data.split(' ')[1]), body: data }));
        sock.on('error', reject);
    });
}

test('database, secrets and source files are not served', async () => {
    const paths = [
        '/fraudshield.db', '/test.db', '/.env', '/.env.example', '/db.js', '/app.js', '/server.js', '/package.json',
        '/lib/config.js', '/engine/index.js', '/../.env', '/..%2f.env', '/%2e%2e/.env', '/uploads/../../.env',
        '/uploads/..%2f..%2f.env', '/js/../../db.js', '/.git/config', '/node_modules/express/package.json',
    ];
    for (const p of paths) {
        const r = await rawGet(p);
        assert.ok([400, 403, 404].includes(r.status), `${p} -> ${r.status}`);
        assert.doesNotMatch(r.body, /DATA_ENCRYPTION_KEY|SQLite format|require\(/, `${p} leaked content`);
    }
});

test('security headers are present on pages and API responses', async () => {
    const page = await fetch(`${srv.base}/index.html`);
    const csp = page.headers.get('content-security-policy');
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /script-src 'self' https:\/\/cdnjs\.cloudflare\.com(;|$)/, 'no unsafe-inline / unsafe-eval scripts');
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /object-src 'none'/);
    assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(page.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(page.headers.get('x-powered-by'), null);
    assert.ok(page.headers.get('permissions-policy'));

    const api = await fetch(`${srv.base}/api/session`);
    assert.equal(api.headers.get('cache-control'), 'no-store');
    assert.ok(api.headers.get('x-request-id'));
});

test('errors are generic: no stack traces, SQL or paths', async () => {
    const c = await new Client(srv.base).signup(uniqueEmail('errors'));
    const malformed = await c.req('POST', '/api/analyze/message', { raw: '{"text": "unterminated', headers: { 'content-type': 'application/json' } });
    assert.equal(malformed.status, 400);
    assert.equal(malformed.json.message, 'Malformed JSON.');
    for (const r of [malformed, await c.get('/api/does-not-exist'), await c.get('/api/detections/abc')]) {
        assert.doesNotMatch(r.text, /at \w+ \(|node_modules|SQLITE|\\fraudshield|\/home\//i);
    }
});

test('health endpoints expose no internals', async () => {
    const h = await fetch(`${srv.base}/healthz`);
    assert.deepEqual(await h.json(), { status: 'ok' });
    const r = await fetch(`${srv.base}/readyz`);
    assert.deepEqual(await r.json(), { status: 'ready' });
});

test('unknown pages get the 404 page with a real 404 status; APIs and non-browsers do not', async () => {
    const page = await fetch(`${srv.base}/no-such-page`, { headers: { accept: 'text/html,application/xhtml+xml' } });
    assert.equal(page.status, 404);
    assert.match(page.headers.get('content-type'), /text\/html/);
    const html = await page.text();
    assert.match(html, /data-variant="notfound"/);
    assert.match(page.headers.get('content-security-policy'), /default-src 'self'/, 'CSP also covers the 404 page');

    // Unauthenticated API probes get 401 (deny by default, endpoint existence not revealed); never the HTML page.
    const api = await fetch(`${srv.base}/api/no-such-endpoint`, { headers: { accept: 'text/html' } });
    assert.ok([401, 404].includes(api.status), `status ${api.status}`);
    assert.match(api.headers.get('content-type'), /application\/json/);

    const cli = await fetch(`${srv.base}/no-such-page`, { headers: { accept: '*/*' } });
    assert.equal(cli.status, 404);
    assert.match(cli.headers.get('content-type'), /text\/plain/);
});

test('status pages are self-contained so they render with no network', async () => {
    for (const p of ['/404.html', '/offline.html', '/500.html']) {
        const html = await (await fetch(srv.base + p)).text();
        assert.doesNotMatch(html, /(src|href)=["']https?:\/\//i, `${p} must not load third-party resources`);
        assert.doesNotMatch(html, /<script>[^<]/i, `${p} must not use inline scripts`);
    }
    const js = await (await fetch(`${srv.base}/js/not-found.js`)).text();
    assert.doesNotMatch(js, /https?:\/\/(?!www\.w3\.org)/, 'no third-party URLs in the status page script');
});

test('service worker never caches API traffic and is always revalidated', async () => {
    const res = await fetch(`${srv.base}/sw.js`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /javascript/);
    assert.equal(res.headers.get('cache-control'), 'no-cache');
    const code = await res.text();
    assert.match(code, /startsWith\('\/api\/'\)\) return/, 'API requests bypass the worker');
    assert.match(code, /url\.origin !== self\.location\.origin\) return/, 'third-party requests bypass the worker');
    assert.doesNotMatch(code, /dashboard|detections|profile/, 'no private pages are pre-cached');
});

test('the live stream requires a session and carries no token in the URL', async () => {
    assert.equal((await fetch(`${srv.base}/api/stream`)).status, 401);
    assert.equal((await fetch(`${srv.base}/api/stream?token=anything`)).status, 401);
});
