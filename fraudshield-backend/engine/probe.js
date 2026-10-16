// engine/probe.js
// Live network probes against the target: DNS, TLS certificate, and an HTTP
// walk of the redirect chain. All connections go through netguard.

const dns = require('dns');
const tls = require('tls');
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const { parse: parseDomain } = require('tldts');
const { resolvePublic, pinnedLookup } = require('./netguard');

const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';
const MAX_BODY = 1.5 * 1024 * 1024;
const MAX_HOPS = 8;

function withTimeout(promise, ms, label) {
    let t;
    return Promise.race([
        promise,
        new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`${label} timed out after ${ms}ms`)), ms); }),
    ]).finally(() => clearTimeout(t));
}

const settle = p => p.then(v => v, () => null);

// ---------------------------------------------------------------- DNS
// Pick a resolver that can actually answer record queries: the system's own
// servers first, public resolvers if those refuse direct queries.
let workingResolver = null;
async function getResolver() {
    if (workingResolver) return workingResolver;
    for (const servers of [dns.getServers(), ['1.1.1.1', '8.8.8.8']]) {
        const r = new dns.promises.Resolver({ timeout: 2500, tries: 1 });
        try {
            r.setServers(servers);
            await r.resolveNs('iana.org');
            workingResolver = r;
            return r;
        } catch { /* try next set */ }
    }
    return null;
}

async function probeDns(host, registrable) {
    // "Does it resolve" must match what the victim's browser sees: use the OS resolver.
    let addresses = [];
    let nxdomain = false;
    try {
        addresses = await dns.promises.lookup(host, { all: true, verbatim: true });
    } catch (e) {
        nxdomain = e.code === 'ENOTFOUND' || e.code === 'ENODATA';
        if (!nxdomain && e.code === 'EAI_AGAIN') {
            // Windows reports some non-existent names as "try again"; ask DNS directly.
            const r = await getResolver();
            if (r) {
                try { await r.resolve4(host); } catch (e2) { nxdomain = e2.code === 'ENOTFOUND' || e2.code === 'ENODATA'; }
            }
        }
        if (!nxdomain) throw e;
    }

    const resolver = await getResolver();
    const q = fn => resolver ? settle(fn(resolver)) : Promise.resolve(null);
    const [a, mx, ns, txt, dmarcTxt] = await Promise.all([
        q(r => r.resolve4(host, { ttl: true })),
        q(r => r.resolveMx(registrable)),
        q(r => r.resolveNs(registrable)),
        q(r => r.resolveTxt(registrable)),
        q(r => r.resolveTxt(`_dmarc.${registrable}`)),
    ]);

    const spf = (txt || []).map(r => r.join('')).find(r => r.toLowerCase().startsWith('v=spf1')) || null;
    const dmarc = (dmarcTxt || []).map(r => r.join('')).find(r => r.toLowerCase().startsWith('v=dmarc1')) || null;
    const ttlByIp = new Map((a || []).map(r => [r.address, r.ttl]));

    return {
        a: addresses.filter(r => r.family === 4).map(r => ({ address: r.address, ttl: ttlByIp.get(r.address) ?? null })),
        aaaa: addresses.filter(r => r.family === 6).map(r => r.address),
        recordQueries: Boolean(resolver),
        mx: (mx || []).sort((x, y) => x.priority - y.priority).map(r => `${r.priority} ${r.exchange}`),
        ns: ns || [],
        spf,
        dmarc,
        resolves: addresses.length > 0,
        nxdomain,
    };
}

// ---------------------------------------------------------------- TLS
async function probeTls(host, port = 443) {
    assertWebPort(new URL(`https://x:${port}`));
    const [target] = await resolvePublic(host);
    return withTimeout(new Promise((resolve, reject) => {
        // Reviewed (SECURITY_AUDIT.md F-INFO-1): certificate validity of an untrusted site is the
        // evidence being measured; no credentials or user data are sent on this socket.
        // nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
        const socket = tls.connect({
            host: target.address,
            // nosemgrep: ajinabraham.njsscan.dos.regex_dos.regex_dos -- reviewed: trivial anchored pattern on a hostname
            servername: /^[\d.]+$|:/.test(host) ? undefined : host,
            port,
            // Deliberate: we inspect certificates of untrusted sites, so an invalid
            // chain is evidence to record (authorizationError), not a reason to abort.
            // No credentials or user data are ever sent over this socket.
            rejectUnauthorized: false,
            lookup: pinnedLookup(target.address, target.family),
        }, () => {
            const cert = socket.getPeerCertificate(true);
            const result = {
                authorized: socket.authorized,
                authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
                protocol: socket.getProtocol(),
                subject: cert.subject || {},
                issuer: cert.issuer || {},
                validFrom: cert.valid_from ? new Date(cert.valid_from).toISOString() : null,
                validTo: cert.valid_to ? new Date(cert.valid_to).toISOString() : null,
                sans: (cert.subjectaltname || '').split(',').map(s => s.trim().replace(/^DNS:/, '')).filter(Boolean).slice(0, 25),
                fingerprint256: cert.fingerprint256 || null,
                selfSigned: Boolean(cert.issuerCertificate && cert.issuerCertificate.fingerprint256 === cert.fingerprint256),
            };
            socket.end();
            resolve(result);
        });
        socket.on('error', reject);
    }), 7000, 'TLS handshake');
}

// ---------------------------------------------------------------- HTTP
// Decompressed output is capped: a 1.5 MB gzip/brotli "bomb" can otherwise
// inflate to gigabytes and exhaust memory.
const MAX_DECODED = 3 * 1024 * 1024;
function decodeBody(buf, encoding) {
    const opts = { maxOutputLength: MAX_DECODED, finishFlush: zlib.constants.Z_SYNC_FLUSH };
    try {
        if (encoding === 'gzip') return zlib.gunzipSync(buf, opts);
        if (encoding === 'deflate') return zlib.inflateSync(buf, opts);
        if (encoding === 'br') return zlib.brotliDecompressSync(buf, { maxOutputLength: MAX_DECODED, finishFlush: zlib.constants.BROTLI_OPERATION_FLUSH });
    } catch {
        return Buffer.alloc(0); // over the cap or corrupt: analyse without a body
    }
    return buf;
}

// Only web ports. Anything else would let a submitted link turn the prober into
// a port scanner or a client for other protocols (SMTP, Redis…) on third-party hosts.
const ALLOWED_PORTS = new Set([80, 443, 8000, 8008, 8080, 8443, 8888]);
function assertWebPort(url) {
    const port = Number(url.port) || (url.protocol === 'https:' ? 443 : 80);
    if (!ALLOWED_PORTS.has(port)) {
        throw Object.assign(new Error(`Refused to connect to non-web port ${port}`), { code: 'EBLOCKEDPORT' });
    }
    return port;
}

async function fetchOnce(url) {
    // Classify the address first (an internal target is the more important finding), then the port.
    const [target] = await resolvePublic(url.hostname.replace(/^\[|\]$/g, ''));
    assertWebPort(url);
    const mod = url.protocol === 'https:' ? https : http;
    const started = Date.now();

    return withTimeout(new Promise((resolve, reject) => {
        // Reviewed (SECURITY_AUDIT.md F-INFO-1): read-only GET of an untrusted page; nothing secret is sent.
        // nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
        const req = mod.request({
            protocol: url.protocol,
            hostname: url.hostname,
            port: url.port || undefined,
            path: url.pathname + url.search,
            method: 'GET',
            lookup: pinnedLookup(target.address, target.family),
            // Deliberate (read-only probe): certificate validity is scored by probeTls.
            rejectUnauthorized: false,
            headers: {
                'User-Agent': BROWSER_UA,
                'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
                'Accept-Language': 'en-IN,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
            },
        }, res => {
            const chunks = [];
            let size = 0;
            const type = String(res.headers['content-type'] || '');
            const wantBody = res.statusCode < 300 || res.statusCode >= 400;
            res.on('data', c => {
                if (!wantBody) return;
                size += c.length;
                if (size > MAX_BODY) { res.destroy(); return; }
                chunks.push(c);
            });
            const finish = () => {
                const raw = decodeBody(Buffer.concat(chunks), res.headers['content-encoding']);
                resolve({
                    url: url.href,
                    ip: target.address,
                    status: res.statusCode,
                    headers: res.headers,
                    contentType: type,
                    body: /html|text\/plain|xml/i.test(type) ? raw.toString('utf8') : '',
                    bytes: size,
                    truncated: size > MAX_BODY,
                    timeMs: Date.now() - started,
                });
            };
            res.on('end', finish);
            res.on('close', finish);
        });
        req.on('error', reject);
        req.end();
    }), 9000, `HTTP request to ${url.host}`);
}

async function probeHttp(startUrl) {
    const chain = [];
    let current = startUrl;
    for (let hop = 0; hop <= MAX_HOPS; hop++) {
        const res = await fetchOnce(current);
        const location = res.headers.location;
        chain.push({
            url: res.url,
            status: res.status,
            ip: res.ip,
            timeMs: res.timeMs,
            server: res.headers.server || null,
            registrableDomain: parseDomain(res.url).domain || current.hostname,
        });
        if (res.status >= 300 && res.status < 400 && location) {
            current = new URL(location, current);
            if (!['http:', 'https:'].includes(current.protocol)) break;
            continue;
        }
        return { chain, final: res };
    }
    return { chain, final: null, tooManyRedirects: true };
}

module.exports = { probeDns, probeTls, probeHttp, withTimeout, decodeBody, assertWebPort, MAX_DECODED };
