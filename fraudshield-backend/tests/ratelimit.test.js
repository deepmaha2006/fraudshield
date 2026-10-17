// Runs with the production per-IP limits (scale 1).
process.env.RATE_LIMIT_SCALE = '1';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startServer, Client, uniqueEmail } = require('./helpers');

let srv;
before(async () => { srv = await startServer(); });
after(async () => { await srv?.stop(); });

test('per-IP authentication limit blocks credential stuffing across many accounts', async () => {
    const c = new Client(srv.base);
    const statuses = [];
    for (let i = 0; i < 32; i++) statuses.push((await c.login(uniqueEmail('stuff'), 'Guess-Password-1')).status);
    assert.ok(statuses.slice(0, 30).every(s => s === 401), statuses.join(','));
    assert.equal(statuses[30], 429);
    assert.equal(statuses[31], 429);
});

test('support form is rate limited per IP', async () => {
    const c = new Client(srv.base);
    const body = { name: 'Someone', email: 'someone@example.test', problem: 'Spam spam spam spam spam' };
    const statuses = [];
    for (let i = 0; i < 11; i++) statuses.push((await c.post('/api/support', body)).status);
    assert.deepEqual(statuses.slice(0, 10), Array(10).fill(200));
    assert.equal(statuses[10], 429);
});
