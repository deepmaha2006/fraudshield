// Access/security logs are emitted, carry request ids, and never contain credentials.
process.env.TEST_LOG_LEVEL = 'info';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startServer, Client, uniqueEmail } = require('./helpers');

let srv;
const lines = [];
const origOut = process.stdout.write.bind(process.stdout);
const origErr = process.stderr.write.bind(process.stderr);

before(async () => {
    srv = await startServer();
    const capture = orig => (chunk, ...rest) => {
        const s = String(chunk);
        if (s.startsWith('{"ts"')) { lines.push(s); return true; }
        return orig(chunk, ...rest);
    };
    process.stdout.write = capture(origOut);
    process.stderr.write = capture(origErr);
});
after(async () => {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
    await srv.stop();
});

test('access and security events are logged without secrets', async () => {
    const email = uniqueEmail('logs');
    const password = 'Super-Secret-Pass-77';
    const c = await new Client(srv.base).signup(email, password);
    await new Client(srv.base).login(email, 'Wrong-Password-00');
    await c.get('/api/overview');
    await fetch(`${srv.base}/api/overview`, { headers: { cookie: 'fs_session=forged' } });

    const events = lines.map(l => JSON.parse(l));
    const http = events.filter(e => e.event === 'http');
    assert.ok(http.some(e => e.path === '/api/overview' && e.status === 200 && e.rid), 'access log with request id');
    assert.ok(events.some(e => e.event === 'auth.login_failed' && e.security), 'failed login recorded');
    assert.ok(events.some(e => e.event === 'auth.session_rejected'), 'forged session recorded');

    const all = lines.join('\n');
    for (const secret of [password, 'Wrong-Password-00', c.csrf, ...c.cookies.values()]) {
        assert.ok(!all.includes(secret), 'secret leaked into logs');
    }
    assert.ok(!all.includes(email), 'e-mail addresses are not logged');
});
