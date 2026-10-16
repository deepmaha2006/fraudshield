// engine/lexical.js
// Structural analysis of the URL string itself. Everything here is computed
// from the URL — no lookup lists of "good" or "bad" domains.

const { parse: parseDomain } = require('tldts');
const { domainToUnicode } = require('url');

function shannonEntropy(str) {
    if (!str) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    return Object.values(freq).reduce((h, c) => {
        const p = c / str.length;
        return h - p * Math.log2(p);
    }, 0);
}

// Unicode script of a single character, enough to spot mixed-script homographs.
function scriptOf(ch) {
    const cp = ch.codePointAt(0);
    if (cp < 0x80) return /[a-z]/i.test(ch) ? 'Latin' : 'Common';
    if (cp >= 0x0400 && cp <= 0x052f) return 'Cyrillic';
    if (cp >= 0x0370 && cp <= 0x03ff) return 'Greek';
    if (cp >= 0x0530 && cp <= 0x058f) return 'Armenian';
    if (cp >= 0x0900 && cp <= 0x097f) return 'Devanagari';
    if (cp >= 0x00c0 && cp <= 0x024f) return 'Latin';
    if (cp >= 0x4e00 && cp <= 0x9fff) return 'Han';
    if (cp >= 0x0600 && cp <= 0x06ff) return 'Arabic';
    return 'Other';
}

/** Normalise user input into a URL object. Bare domains default to https. */
function normaliseUrl(input) {
    let raw = String(input || '').trim();
    // Accept defanged IOCs such as hxxps://evil[.]com
    raw = raw.replace(/^hxxp/i, 'http').replace(/\[\.\]/g, '.').replace(/\[:\]/g, ':');
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = 'https://' + raw;
    const url = new URL(raw);
    if (!['http:', 'https:'].includes(url.protocol)) {
        throw new Error(`Unsupported scheme ${url.protocol}`);
    }
    return url;
}

// Decode the various numeric host notations attackers use to hide an IP.
function numericHostToIp(host) {
    if (/^\d+$/.test(host)) {
        const n = Number(host);
        if (n <= 0xffffffff) return [24, 16, 8, 0].map(s => (n >>> s) & 255).join('.');
    }
    if (/^0x[0-9a-f]+$/i.test(host)) {
        const n = parseInt(host, 16);
        if (n <= 0xffffffff) return [24, 16, 8, 0].map(s => (n >>> s) & 255).join('.');
    }
    return null;
}

function analyseLexical(url) {
    const signals = [];
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const info = parseDomain(url.href, { allowPrivateDomains: true });
    const unicodeHost = domainToUnicode(host) || host;
    const registrable = info.domain || host;
    const subdomain = info.subdomain || '';
    const label = info.domainWithoutSuffix || registrable;

    const facts = {
        scheme: url.protocol.replace(':', ''),
        host,
        unicodeHost,
        registrableDomain: registrable,
        subdomain,
        publicSuffix: info.publicSuffix,
        isIp: Boolean(info.isIp),
        port: url.port || null,
        path: url.pathname,
        query: url.search,
        length: url.href.length,
        hostEntropy: Number(shannonEntropy(label).toFixed(2)),
    };

    const add = (id, label, detail, weight, severity) =>
        signals.push({ id, category: 'URL structure', label, detail, weight, severity });

    const hiddenIp = numericHostToIp(host);
    if (info.isIp || hiddenIp) {
        add('ip-host', 'Raw IP address instead of a domain name',
            `Host ${host}${hiddenIp ? ` (decodes to ${hiddenIp})` : ''} — legitimate services publish named domains.`,
            hiddenIp ? 0.7 : 0.55, hiddenIp ? 'critical' : 'high');
    }

    if (url.username || url.password) {
        add('userinfo', 'Credentials / "@" trick in URL',
            `Everything before "@" is ignored by the browser; the real destination is ${host}.`, 0.6, 'high');
    }

    if (host.includes('xn--')) {
        const scripts = new Set([...unicodeHost.replace(/[.\-0-9]/g, '')].map(scriptOf).filter(s => s !== 'Common'));
        if (scripts.size > 1) {
            add('homograph', 'Mixed-script homograph domain',
                `${host} renders as "${unicodeHost}" mixing ${[...scripts].join(' + ')} characters to imitate another name.`, 0.8, 'critical');
        } else {
            add('idn', 'Internationalised (punycode) domain',
                `${host} renders as "${unicodeHost}".`, 0.2, 'medium');
        }
    }

    if (!info.isIp && !hiddenIp && !info.isIcann && !info.isPrivate) {
        add('unknown-suffix', 'Unrecognised public suffix',
            `"${info.publicSuffix || host}" is not a delegated ICANN top-level domain.`, 0.35, 'medium');
    }

    // A domain-like token inside the subdomain: paypal.com.account-check.xyz
    const embedded = subdomain.split('.').some(l => /^(com|net|org|gov|edu|co|in|io|info)$/i.test(l));
    if (embedded) {
        add('embedded-domain', 'Another domain name embedded in the subdomain',
            `"${subdomain}" is only a prefix — the site actually belongs to ${registrable}.`, 0.55, 'high');
    }

    const depth = subdomain ? subdomain.split('.').length : 0;
    if (depth >= 3) {
        add('deep-subdomain', 'Unusually deep subdomain chain',
            `${depth} subdomain levels before ${registrable}.`, 0.2, 'medium');
    }

    const hyphens = (label.match(/-/g) || []).length;
    if (hyphens >= 2) {
        add('hyphenated', 'Heavily hyphenated domain label',
            `"${label}" contains ${hyphens} hyphens, typical of keyword-stuffed throwaway domains.`, 0.15 + Math.min(hyphens - 2, 3) * 0.05, 'low');
    }

    const digits = (label.match(/\d/g) || []).length;
    if (label.length >= 8 && digits / label.length > 0.3) {
        add('digit-heavy', 'Digit-heavy domain label',
            `${Math.round(digits / label.length * 100)}% of "${label}" is numeric.`, 0.2, 'low');
    }

    const letters = label.replace(/[^a-z]/gi, '');
    const vowelRatio = letters ? (letters.match(/[aeiou]/gi) || []).length / letters.length : 0;
    if (label.length >= 12 && facts.hostEntropy >= 3.5 && vowelRatio < 0.25) {
        add('high-entropy', 'Random-looking (algorithmically generated) domain',
            `Shannon entropy ${facts.hostEntropy} bits/char with little pronounceable structure.`, 0.3, 'medium');
    }

    if (url.port && !['80', '443'].includes(url.port)) {
        add('odd-port', 'Non-standard port', `Service exposed on port ${url.port}.`, 0.25, 'medium');
    }

    if (url.protocol === 'http:') {
        add('no-tls', 'Unencrypted HTTP link', 'Anything typed on this page travels in clear text.', 0.2, 'medium');
    }

    if (facts.length > 200) {
        add('very-long', 'Extremely long URL', `${facts.length} characters — often used to push the real host out of view.`, 0.2, 'low');
    } else if (facts.length > 110) {
        add('long', 'Long URL', `${facts.length} characters.`, 0.08, 'low');
    }

    if (/\/\//.test(url.pathname)) {
        add('path-double-slash', 'Double slash inside the path', 'Common in open-redirect and path-confusion tricks.', 0.15, 'low');
    }

    const embeddedUrl = decodeURIComponent(url.search).match(/=(https?:\/\/[^&]+)/i);
    if (embeddedUrl) {
        add('redirect-param', 'URL carries another URL as a parameter',
            `Possible open redirect towards ${embeddedUrl[1].slice(0, 80)}.`, 0.2, 'medium');
    }

    const ext = url.pathname.toLowerCase().match(/\.(apk|exe|scr|msi|bat|cmd|vbs|js|jar|ps1|hta|iso|img|zip|rar|7z)$/);
    if (ext) {
        add('executable', 'Direct download of an executable / archive',
            `Path ends in .${ext[1]} — links in messages should not deliver installers.`, ext[1] === 'apk' ? 0.6 : 0.45, 'high');
    }

    if ((url.href.match(/%[0-9a-f]{2}/gi) || []).length > 10) {
        add('heavy-encoding', 'Heavily percent-encoded URL', 'Obfuscates the visible path or parameters.', 0.12, 'low');
    }

    return { facts, signals };
}

module.exports = { analyseLexical, normaliseUrl, shannonEntropy };
