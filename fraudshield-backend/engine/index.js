// engine/index.js
// Real-time detection pipeline. A link is not looked up in a list; it is
// resolved, connected to, fetched and inspected, and every observation becomes
// a weighted signal. The verdict is computed from those signals.

const { parse: parseDomain } = require('tldts');
const { analyseLexical, normaliseUrl } = require('./lexical');
const { probeDns, probeTls, probeHttp, withTimeout } = require('./probe');
const { analyseContent } = require('./content');
const { lookupRdap, analyseRdap } = require('./rdap');

const VERDICT_MALICIOUS = 65;
const VERDICT_SUSPICIOUS = 30;

// ------------------------------------------------------------- scoring model
// Risk signals are combined as independent probabilities (noisy-OR), so many
// weak indicators add up while no single weak one dominates. Trust signals
// scale the result down, but cannot push it below the combined weight of the
// critical indicators: an old domain hosting a credential-stealing form is
// still malicious.
function scoreSignals(signals) {
    const risk = signals.filter(s => s.weight > 0);
    const trust = signals.filter(s => s.weight < 0);
    const noisyOr = list => 1 - list.reduce((acc, s) => acc * (1 - s.weight), 1);
    const raw = noisyOr(risk);
    const trustFactor = trust.reduce((acc, s) => acc * (1 + s.weight), 1);
    const criticalFloor = noisyOr(risk.filter(s => s.severity === 'critical'));
    return Math.round(Math.max(raw * trustFactor, criticalFloor) * 100);
}

const verdictFor = risk => risk >= VERDICT_MALICIOUS ? 'malicious' : risk >= VERDICT_SUSPICIOUS ? 'suspicious' : 'legit';

const sortSignals = signals => [...signals].sort((a, b) => b.weight - a.weight);

function summarise(verdict, signals, stages = []) {
    const failedStages = stages.filter(s => s.status === 'failed').map(s => s.name);
    if (verdict === 'legit' && failedStages.length) {
        return `Low risk on partial evidence — ${failedStages.join(', ')} did not complete. Re-run before trusting this link.`;
    }
    const top = signals.filter(s => s.weight > 0.1).slice(0, 3).map(s => s.label);
    if (verdict === 'legit') {
        const trust = signals.filter(s => s.weight < 0).map(s => s.label.toLowerCase());
        return trust.length ? `No significant risk indicators; ${trust.slice(0, 2).join(', ')}.` : 'No significant risk indicators observed.';
    }
    return top.join(' · ') || 'Multiple weak indicators.';
}

// ------------------------------------------------------------- small helpers
const cache = new Map();
const CACHE_TTL = 10 * 60 * 1000;

let active = 0;
const waiting = [];
const MAX_WAITING = 40;
async function limited(fn) {
    if (active >= 6) {
        // Bounded queue: shed load instead of accumulating unbounded work and sockets.
        if (waiting.length >= MAX_WAITING) throw Object.assign(new Error('Analysis capacity exceeded. Retry shortly.'), { status: 503, expose: true });
        await new Promise(r => waiting.push(r));
    }
    active++;
    try { return await fn(); } finally { active--; waiting.shift()?.(); }
}

async function stage(stages, name, fn, timeoutMs) {
    const started = Date.now();
    try {
        const value = await withTimeout(Promise.resolve().then(fn), timeoutMs, name);
        stages.push({ name, status: 'ok', ms: Date.now() - started });
        return value;
    } catch (err) {
        stages.push({ name, status: 'failed', ms: Date.now() - started, error: err.message, code: err.code });
        return { __error: err };
    }
}
const failed = v => v && v.__error;

// ------------------------------------------------------------- DNS / TLS / HTTP signal derivation
function dnsSignals(dnsInfo, host) {
    const out = [];
    const add = (id, label, detail, weight, severity) => out.push({ id, category: 'DNS', label, detail, weight, severity });
    if (!dnsInfo.resolves) {
        add('no-resolve', 'Domain does not resolve',
            dnsInfo.nxdomain ? `${host} has no DNS records (NXDOMAIN) — taken down or never set up.` : `${host} returned no address records.`,
            0.45, 'high');
        return out;
    }
    const ttls = dnsInfo.a.map(r => r.ttl).filter(t => t != null);
    if (ttls.length >= 5 && Math.min(...ttls) < 300) {
        add('fast-flux', 'Fast-flux DNS pattern', `${dnsInfo.a.length} A records with TTL ${Math.min(...ttls)}s.`, 0.25, 'medium');
    }
    if (!dnsInfo.recordQueries) return out; // record lookups unavailable — don't infer absence
    if (dnsInfo.mx.length && dnsInfo.spf && dnsInfo.dmarc) {
        add('mail-auth', 'Domain publishes MX, SPF and DMARC', 'Indicates an operated organisational domain.', -0.12, 'trust');
    } else if (!dnsInfo.mx.length && !dnsInfo.spf) {
        add('no-mail', 'No mail infrastructure', 'No MX or SPF records — common for disposable domains.', 0.08, 'low');
    }
    return out;
}

function tlsSignals(tlsInfo) {
    const out = [];
    const add = (id, label, detail, weight, severity) => out.push({ id, category: 'TLS certificate', label, detail, weight, severity });
    const err = tlsInfo.authorizationError || '';
    if (!tlsInfo.authorized) {
        // Browsers hard-block these; an old domain does not make them safe to type into.
        if (/EXPIRED/i.test(err)) add('cert-expired', 'Expired certificate', err, 0.45, 'critical');
        else if (/SELF_SIGNED|self.signed/i.test(err) || tlsInfo.selfSigned) add('cert-self-signed', 'Self-signed certificate', err || 'Not issued by a trusted authority.', 0.5, 'critical');
        else if (/ALTNAME|hostname|IP: /i.test(err)) add('cert-mismatch', 'Certificate issued for a different host', `${err} (covers ${tlsInfo.sans.slice(0, 3).join(', ')})`, 0.5, 'critical');
        else add('cert-untrusted', 'Untrusted certificate chain', err, 0.35, 'medium');
    }
    if (tlsInfo.validFrom) {
        const ageDays = Math.floor((Date.now() - new Date(tlsInfo.validFrom)) / 86400000);
        tlsInfo.ageDays = ageDays;
        if (ageDays <= 3) add('cert-brand-new', 'Certificate issued in the last 72 hours', `Issued ${tlsInfo.validFrom.slice(0, 10)}.`, 0.25, 'medium');
    }
    if (tlsInfo.authorized && tlsInfo.subject && tlsInfo.subject.O) {
        add('cert-ov', 'Organisation-validated certificate', `Issued to "${tlsInfo.subject.O}" by ${tlsInfo.issuer.O || tlsInfo.issuer.CN}.`, -0.2, 'trust');
    } else if (tlsInfo.authorized) {
        add('cert-valid', 'Valid TLS certificate', `Issued by ${tlsInfo.issuer.O || tlsInfo.issuer.CN}.`, -0.04, 'trust');
    }
    return out;
}

function httpSignals(httpInfo, startUrl) {
    const out = [];
    const add = (id, label, detail, weight, severity) => out.push({ id, category: 'Redirects & hosting', label, detail, weight, severity });
    const chain = httpInfo.chain;
    const domains = [...new Set(chain.map(h => h.registrableDomain))];
    if (domains.length > 1) {
        add('cross-redirect', `Redirects across ${domains.length} different domains`,
            domains.join(' → '), Math.min(0.15 + 0.1 * (domains.length - 2), 0.45), domains.length > 2 ? 'high' : 'medium');
    }
    if (chain.some((h, i) => i > 0 && chain[i - 1].url.startsWith('https:') && h.url.startsWith('http:'))) {
        add('downgrade', 'Redirect downgrades HTTPS to HTTP', 'Connection is stripped of encryption mid-chain.', 0.3, 'high');
    }
    if (httpInfo.tooManyRedirects) add('redirect-loop', 'Excessive redirects', `More than ${chain.length - 1} hops.`, 0.3, 'medium');
    const final = httpInfo.final;
    if (final && [404, 410, 451].includes(final.status)) {
        add('gone', `Destination returns HTTP ${final.status}`, 'Page removed — frequently a taken-down phishing page.', 0.1, 'low');
    }
    return out;
}

// ------------------------------------------------------------- URL pipeline
async function analyzeUrlUncached(input) {
    const started = Date.now();
    const stages = [];
    const url = normaliseUrl(input);
    const lex = analyseLexical(url);
    let signals = [...lex.signals];
    const evidence = { url: lex.facts };

    // 1. DNS on the submitted host
    const host = lex.facts.host;
    const dnsInfo = lex.facts.isIp ? null : await stage(stages, 'DNS resolution', () => probeDns(host, lex.facts.registrableDomain), 8000);
    if (dnsInfo && !failed(dnsInfo)) { evidence.dns = dnsInfo; signals.push(...dnsSignals(dnsInfo, host)); }

    // 2. Live HTTP fetch, following the full redirect chain
    let finalUrl = url;
    let finalBody = '';
    const reachable = lex.facts.isIp || (dnsInfo && !failed(dnsInfo) && dnsInfo.resolves);
    if (reachable) {
        const httpInfo = await stage(stages, 'HTTP fetch & redirects', () => probeHttp(url), 30000);
        if (failed(httpInfo)) {
            const e = httpInfo.__error;
            if (e.code === 'EBLOCKED') {
                signals.push({ id: 'internal-ip', category: 'DNS', label: 'Public link points to an internal network address', detail: e.message, weight: 0.7, severity: 'critical' });
            } else if (e.code === 'EBLOCKEDPORT') {
                signals.push({ id: 'non-web-port', category: 'Redirects & hosting', label: 'Link targets a non-web service port', detail: `${e.message}; not fetched.`, weight: 0.35, severity: 'medium' });
            } else {
                signals.push({ id: 'unreachable', category: 'Redirects & hosting', label: 'Site did not respond', detail: e.message, weight: 0.1, severity: 'low' });
            }
        } else {
            evidence.http = {
                chain: httpInfo.chain,
                finalStatus: httpInfo.final?.status ?? null,
                contentType: httpInfo.final?.contentType ?? null,
                bytes: httpInfo.final?.bytes ?? 0,
                server: httpInfo.final?.headers?.server ?? null,
            };
            signals.push(...httpSignals(httpInfo, url));
            const last = httpInfo.chain[httpInfo.chain.length - 1];
            if (last) finalUrl = new URL(last.url);
            finalBody = httpInfo.final?.body || '';
        }
    } else if (dnsInfo && !failed(dnsInfo)) {
        stages.push({ name: 'HTTP fetch & redirects', status: 'skipped', ms: 0, error: 'Host does not resolve' });
    }

    // 3. If the chain ended somewhere else, the destination is what matters
    const finalLex = analyseLexical(finalUrl);
    const movedDomain = finalLex.facts.registrableDomain !== lex.facts.registrableDomain;
    if (movedDomain) {
        evidence.finalUrl = finalLex.facts;
        signals.push(...finalLex.signals.map(s => ({ ...s, id: `dest-${s.id}`, label: `${s.label} (final destination)` })));
    }

    // 4. TLS certificate + domain registration, in parallel
    const regDomain = finalLex.facts.isIp ? null : finalLex.facts.registrableDomain;
    const [tlsInfo, rdapFinal, rdapStart] = await Promise.all([
        finalUrl.protocol === 'https:' && reachable
            ? stage(stages, 'TLS certificate', () => probeTls(finalLex.facts.host, Number(finalUrl.port) || 443), 9000)
            : null,
        regDomain ? stage(stages, 'Domain registration (RDAP)', () => lookupRdap(regDomain), 9000) : null,
        movedDomain && !lex.facts.isIp ? stage(stages, 'Origin domain registration', () => lookupRdap(lex.facts.registrableDomain), 9000) : null,
    ]);

    if (tlsInfo && !failed(tlsInfo)) {
        evidence.tls = tlsInfo;
        signals.push(...tlsSignals(tlsInfo));
    } else if (tlsInfo && failed(tlsInfo)) {
        signals.push({ id: 'tls-fail', category: 'TLS certificate', label: 'TLS handshake failed', detail: tlsInfo.__error.message, weight: 0.3, severity: 'medium' });
    }

    let domainAgeDays = null;
    if (rdapFinal && !failed(rdapFinal)) {
        const r = analyseRdap(rdapFinal, regDomain);
        domainAgeDays = r.ageDays;
        evidence.registration = { domain: regDomain, ageDays: r.ageDays, ...rdapFinal };
        signals.push(...r.signals);
    }
    if (rdapStart && !failed(rdapStart)) {
        // A freshly registered redirector is itself an attacker asset; its trust is irrelevant.
        const r = analyseRdap(rdapStart, lex.facts.registrableDomain);
        evidence.originRegistration = { domain: lex.facts.registrableDomain, ageDays: r.ageDays, ...rdapStart };
        signals.push(...r.signals.filter(s => s.weight > 0).map(s => ({ ...s, id: `origin-${s.id}`, label: `${s.label} (redirector)` })));
    }

    // 5. What the landing page actually does
    if (finalBody) {
        const content = await stage(stages, 'Page content analysis', () => analyseContent(finalBody, finalUrl.href, { domainAgeDays }), 5000);
        if (!failed(content)) { evidence.content = content.facts; signals.push(...content.signals); }
    }

    signals = sortSignals(signals);
    const risk = scoreSignals(signals);
    const verdict = verdictFor(risk);
    const attempted = stages.filter(s => s.status !== 'skipped').length + 1; // +1 lexical
    const succeeded = stages.filter(s => s.status === 'ok').length + 1;

    return {
        kind: 'url',
        input: String(input),
        url: url.href,
        finalUrl: finalUrl.href,
        verdict,
        risk,
        confidence: Math.round(succeeded / Math.max(attempted, 1) * 100),
        summary: summarise(verdict, signals, stages),
        signals,
        evidence,
        stages: [{ name: 'URL structure', status: 'ok', ms: 0 }, ...stages],
        durationMs: Date.now() - started,
        analyzedAt: new Date().toISOString(),
    };
}

async function analyzeUrl(input) {
    const key = String(input).trim().toLowerCase();
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_TTL) return { ...hit.value, cached: true };
    const value = await limited(() => analyzeUrlUncached(input));
    // Don't pin a partial result in the cache; a retry may get through.
    if (value.stages.every(s => s.status !== 'failed')) cache.set(key, { at: Date.now(), value });
    if (cache.size > 500) cache.delete(cache.keys().next().value);
    return value;
}

// ------------------------------------------------------------- message pipeline
const URL_RE = /\bhttps?:\/\/[^\s<>"'`)\]]+/gi;
// eslint-disable-next-line security/detect-unsafe-regex -- reviewed: anchored/lookbehind-bounded, linear on adversarial input (tests/engine.test.js ReDoS case)
const BARE_RE = /(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?:\/[^\s<>"'`)\]]*)?/gi;

function extractUrls(text) {
    const found = new Set();
    for (const m of String(text || '').matchAll(URL_RE)) found.add(m[0].replace(/[.,;:!?]+$/, ''));
    const withoutFull = String(text || '').replace(URL_RE, ' ');
    for (const m of withoutFull.matchAll(BARE_RE)) {
        const candidate = m[0].replace(/[.,;:!?]+$/, '');
        const info = parseDomain(candidate);
        // eslint-disable-next-line security/detect-unsafe-regex -- reviewed: anchored/lookbehind-bounded, linear on adversarial input (tests/engine.test.js ReDoS case)
        if (info.domain && info.isIcann && !/^\d+(\.\d+)+$/.test(candidate)) found.add(candidate);
    }
    return [...found];
}

function extractAnchors(html) {
    const anchors = [];
    // Bounded quantifiers: an unbounded lazy body is quadratic on many unclosed <a> tags (ReDoS).
    for (const m of String(html || '').matchAll(/<a\b[^>]{0,1000}?href\s*=\s*["']([^"']{1,2048})["'][^>]{0,1000}>([\s\S]{0,1000}?)<\/a>/gi)) {
        if (anchors.length >= 500) break;
        const href = m[1].trim();
        if (!/^https?:/i.test(href)) continue;
        const text = m[2].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
        anchors.push({ href, text });
    }
    return anchors;
}

const LANGUAGE = {
    urgency: /\b(urgent(ly)?|immediately|within \d+\s*(hours?|hrs|minutes?|mins)|today only|last (chance|warning|reminder|date)|expir(e|es|ed|ing)|suspend(ed)?|blocked|deactivat\w*|turant|jaldi|abhi\b|band ho)/i,
    credentials: /\b(otp|one[- ]time password|password|passcode|cvv|card (number|details)|kyc|aadha+r|pan card|upi pin|net ?banking|verify (your )?(account|identity|details)|update (your )?(details|kyc|pan))\b/i,
    money: /(\bwon\b|winner|prize|lottery|reward|cashback|refund|bonus|free gift|lucky draw|\binvest(ment)?\b|guaranteed returns?|\bcrypto|₹\s?\d|\brs\.?\s?\d|\binr\s?\d|\$\s?\d)/i,
    threat: /\b(legal action|police|arrest(ed)?|court|penalty|\bfine\b|\bfir\b|cyber ?cell|disconnect(ed|ion)?|electricity (will be|supply)|customs)/i,
    remoteAccess: /\b(anydesk|teamviewer|quick ?support|rustdesk|screen ?shar\w*)\b/i,
};

function languageSignals(text) {
    const out = [];
    const add = (id, label, detail, weight, severity) => out.push({ id, category: 'Message content', label, detail, weight, severity });
    const hits = Object.fromEntries(Object.entries(LANGUAGE).map(([k, re]) => [k, (String(text).match(re) || [])[0] || null]));
    const q = k => `"${hits[k]}"`;

    if (hits.remoteAccess) add('remote-access', 'Asks to install a remote-access tool', `Mentions ${q('remoteAccess')} — used to take over victims' devices.`, 0.55, 'high');
    if (hits.credentials && hits.urgency) add('cred-urgency', 'Urgent request for credentials or verification', `${q('urgency')} combined with ${q('credentials')}.`, 0.4, 'high');
    else if (hits.credentials) add('cred-request', 'Requests credentials / identity data', q('credentials'), 0.15, 'low');
    if (hits.threat && hits.urgency) add('threat-urgency', 'Coercive threat with a deadline', `${q('threat')} + ${q('urgency')}.`, 0.35, 'high');
    else if (hits.threat) add('threat', 'Threatening language', q('threat'), 0.12, 'low');
    if (hits.money && (hits.urgency || hits.credentials)) add('money-pressure', 'Financial lure under pressure', `${q('money')} with ${q(hits.urgency ? 'urgency' : 'credentials')}.`, 0.3, 'medium');
    else if (hits.money) add('money', 'Financial lure', q('money'), 0.08, 'low');

    const letters = String(text).replace(/[^a-z]/gi, '');
    if (letters.length > 40 && (letters.match(/[A-Z]/g) || []).length / letters.length > 0.5) {
        add('shouting', 'Mostly upper-case text', 'Pressure styling typical of scam broadcasts.', 0.08, 'low');
    }
    return out;
}

function emailHeaderSignals(meta) {
    const out = [];
    const add = (id, label, detail, weight, severity) => out.push({ id, category: 'Sender authentication', label, detail, weight, severity });
    const auth = String(meta.authResults || '').toLowerCase();
    // eslint-disable-next-line security/detect-non-literal-regexp -- pattern built from a constant key in this file, not user input
    const res = key => (auth.match(new RegExp(`\\b${key}=(\\w+)`)) || [])[1] || null;
    const spf = res('spf'), dkim = res('dkim'), dmarc = res('dmarc');
    const authInfo = { spf, dkim, dmarc };

    if (dmarc === 'fail') add('dmarc-fail', 'DMARC failed', 'The sender is not authorised to send mail as this domain.', 0.55, 'critical');
    if (spf === 'fail' || spf === 'softfail') add('spf-fail', `SPF ${spf}`, 'Sending server is not listed by the claimed domain.', 0.3, 'high');
    if (dkim === 'fail') add('dkim-fail', 'DKIM signature failed', 'Message was altered or the signature was forged.', 0.25, 'medium');
    if (dmarc === 'pass' && dkim === 'pass') add('auth-pass', 'Sender authenticated (DKIM + DMARC pass)', `Mail genuinely originates from ${meta.fromDomain}.`, -0.25, 'trust');

    const fromDomain = meta.fromDomain;
    const nameDomain = (String(meta.fromName || '').match(/[a-z0-9-]+\.(com|in|net|org|co\.in|gov\.in|bank)/i) || [])[0];
    if (nameDomain && fromDomain && parseDomain(nameDomain).domain !== fromDomain) {
        add('display-spoof', 'Display name impersonates another domain', `Shows "${meta.fromName}" but sent from ${fromDomain}.`, 0.4, 'high');
    }
    if (meta.replyToDomain && fromDomain && meta.replyToDomain !== fromDomain) {
        add('reply-divert', 'Replies are diverted to another domain', `From ${fromDomain}, Reply-To ${meta.replyToDomain}.`, 0.25, 'medium');
    }
    return { signals: out, auth: authInfo };
}

/**
 * Analyse an email or SMS. `meta` (email only) may contain fromName, fromAddress,
 * replyTo, authResults.
 */
async function analyzeMessage({ text = '', html = '', meta = {} } = {}) {
    const started = Date.now();
    // Hard caps before any regex runs over attacker-supplied content.
    text = String(text || '').slice(0, 50000);
    html = String(html || '').slice(0, 500000);
    const plain = text || html.replace(/<style[^>]{0,500}>[\s\S]{0,200000}?<\/style>|<script[^>]{0,500}>[\s\S]{0,200000}?<\/script>/gi, ' ').replace(/<[^>]{0,5000}>/g, ' ').slice(0, 50000);
    let signals = languageSignals(plain);
    const evidence = {};

    if (meta.fromAddress) {
        meta.fromDomain = parseDomain(meta.fromAddress.split('@')[1] || '').domain;
        meta.replyToDomain = meta.replyTo ? parseDomain(meta.replyTo.split('@')[1] || '').domain : null;
        const h = emailHeaderSignals(meta);
        signals.push(...h.signals);
        evidence.sender = { name: meta.fromName || null, address: meta.fromAddress, domain: meta.fromDomain, replyTo: meta.replyTo || null, auth: h.auth };
    }

    // Links: deceptive anchors first, then everything else, unique per domain.
    const anchors = extractAnchors(html);
    const deceptive = anchors.filter(a => {
        const shown = extractUrls(a.text)[0];
        if (!shown) return false;
        const shownDomain = parseDomain(shown).domain;
        return shownDomain && shownDomain !== parseDomain(a.href).domain;
    });
    for (const a of deceptive.slice(0, 3)) {
        signals.push({ id: 'anchor-mismatch', category: 'Message content', label: 'Link text shows a different address than its target',
            detail: `Displays "${a.text.slice(0, 80)}" but opens ${a.href.slice(0, 120)}`, weight: 0.55, severity: 'critical' });
    }

    const candidates = [...deceptive.map(a => a.href), ...anchors.map(a => a.href), ...extractUrls(plain)];
    const perDomain = new Map();
    for (const u of candidates) {
        try {
            const d = parseDomain(normaliseUrl(u).href).domain || u;
            if (!perDomain.has(d) && !(meta.fromDomain && d === meta.fromDomain && perDomain.size >= 1)) perDomain.set(d, u);
        } catch { /* unparsable — ignore */ }
    }
    const urls = [...perDomain.values()].slice(0, 5);
    evidence.urlsFound = [...new Set(candidates)].length;

    const links = await Promise.all(urls.map(u => analyzeUrl(u).catch(err => ({
        kind: 'url', input: u, url: u, verdict: 'suspicious', risk: 40, confidence: 0, summary: `Could not analyse: ${err.message}`, signals: [], stages: [],
    }))));

    for (const l of links) {
        if (l.risk >= VERDICT_SUSPICIOUS) {
            signals.push({
                id: `link-${l.url}`, category: 'Embedded links',
                label: `${l.verdict === 'malicious' ? 'Malicious' : 'Suspicious'} link: ${(() => { try { return new URL(l.finalUrl || l.url).hostname; } catch { return l.url; } })()}`,
                detail: `${l.risk}/100 — ${l.summary}`,
                weight: Math.min(l.risk / 100, 0.95),
                severity: l.verdict === 'malicious' ? 'critical' : 'medium',
            });
        }
    }

    signals = sortSignals(signals);
    const risk = scoreSignals(signals);
    const verdict = verdictFor(risk);
    const confidence = links.length ? Math.round(links.reduce((s, l) => s + (l.confidence || 0), 0) / links.length) : 70;

    return {
        kind: 'message',
        verdict,
        risk,
        confidence,
        summary: summarise(verdict, signals),
        signals,
        links: links.map(l => ({ url: l.url, finalUrl: l.finalUrl, verdict: l.verdict, risk: l.risk, summary: l.summary, report: l })),
        evidence,
        preview: plain.replace(/\s+/g, ' ').trim().slice(0, 600),
        durationMs: Date.now() - started,
        analyzedAt: new Date().toISOString(),
    };
}

module.exports = { analyzeUrl, analyzeMessage, extractUrls, extractAnchors, scoreSignals, verdictFor, VERDICT_MALICIOUS, VERDICT_SUSPICIOUS };
