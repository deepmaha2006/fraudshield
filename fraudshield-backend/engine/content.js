// engine/content.js
// Behavioural analysis of the landing page HTML: what does the page actually
// try to do? Collect credentials, impersonate another site, hide its code?

const { parse: parseDomain } = require('tldts');

const decodeEntities = s => s
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&nbsp;/g, ' ');

const attr = (tag, name) => {
    // eslint-disable-next-line security/detect-non-literal-regexp -- pattern built from a constant key in this file, not user input
    const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
    return m ? decodeEntities(m[2] ?? m[3] ?? m[4] ?? '') : null;
};

const brandKey = s => String(s || '').toLowerCase().normalize('NFKD').replace(/[^a-z0-9]/g, '');

function domainOf(ref, base) {
    try {
        const u = new URL(ref, base);
        if (!/^https?:$/.test(u.protocol)) return null;
        return parseDomain(u.href).domain || u.hostname;
    } catch { return null; }
}

/**
 * Figure out which brand the page claims to be. og:site_name is the most
 * deliberate statement; the <title> is the fallback.
 */
function claimedBrand(html) {
    const og = html.match(/<meta[^>]{1,1500}property\s*=\s*["']og:site_name["'][^>]{0,1500}>/i);
    const ogName = og ? attr(og[0], 'content') : null;
    const titleMatch = html.match(/<title[^>]{0,1500}>([\s\S]{0,1000}?)<\/title>/i);
    const title = titleMatch ? decodeEntities(titleMatch[1]).replace(/\s+/g, ' ').trim() : '';
    let brand = ogName;
    if (!brand && title) {
        // "Sign in – Contoso Bank" / "Contoso | Login": take the most brand-like segment
        const parts = title.split(/\s[|\-–—:·•]\s|\s[|–—·•]\s?/).map(p => p.trim()).filter(Boolean);
        const generic = /^(log\s?in|sign\s?in|login|account|verify|home|welcome|secure|update|online|official|portal)/i;
        brand = parts.find(p => !generic.test(p) && p.length <= 40) || parts[0] || null;
    }
    return { title, brand: brand ? brand.slice(0, 60) : null };
}

function analyseContent(html, pageUrl, ctx = {}) {
    // nosemgrep: ajinabraham.njsscan.dos.regex_dos.regex_dos -- reviewed: bounded/linear regex, measured in tests/engine.test.js ReDoS case
    html = String(html).slice(0, 600000); // bound regex work on attacker-controlled pages
    const signals = [];
    const add = (id, label, detail, weight, severity) =>
        signals.push({ id, category: 'Page behaviour', label, detail, weight, severity });

    const pageDomain = parseDomain(pageUrl).domain || new URL(pageUrl).hostname;
    const pageKey = brandKey(parseDomain(pageUrl).domainWithoutSuffix || pageDomain);
    const lower = html.toLowerCase();

    // ---- forms & credential collection
    const forms = [...html.matchAll(/<form\b[^>]{0,1500}>/gi)].map(m => m[0]);
    const inputs = [...html.matchAll(/<input\b[^>]{0,1500}>/gi)].map(m => m[0]);
    const passwordFields = inputs.filter(i => /type\s*=\s*["']?password/i.test(i)).length;
    const sensitiveRe = /(card.?num|cc.?num|cvv|cvc|expiry|exp.?date|otp|one.?time|upi.?pin|\bpin\b|aadha+r|\bpan\b|ssn|social.?security|account.?num|ifsc|mother.?s.?maiden|net.?banking)/i;
    const sensitiveFields = inputs
        .map(i => [attr(i, 'name'), attr(i, 'id'), attr(i, 'placeholder'), attr(i, 'autocomplete')].filter(Boolean).join(' '))
        .filter(desc => sensitiveRe.test(desc));

    const formTargets = forms.map(f => attr(f, 'action')).filter(a => a !== null && a !== '' && a !== '#');
    const externalActions = [...new Set(formTargets.map(a => domainOf(a, pageUrl)).filter(d => d && d !== pageDomain))];
    const insecureActions = formTargets.filter(a => /^http:\/\//i.test(a));
    const mailtoOrPhp = formTargets.filter(a => /^mailto:|\.php(\?|$)/i.test(a));

    const collectsCredentials = passwordFields > 0 || sensitiveFields.length > 0;
    const young = ctx.domainAgeDays != null && ctx.domainAgeDays < 90;

    if (passwordFields > 0) {
        add('password-form', 'Page asks for a password',
            `${passwordFields} password field(s) on ${pageDomain}.`, young ? 0.55 : 0.08, young ? 'high' : 'info');
    }
    if (sensitiveFields.length) {
        add('sensitive-fields', 'Collects payment / identity data',
            `Fields: ${[...new Set(sensitiveFields)].slice(0, 5).join('; ')}`, young ? 0.6 : 0.3, young ? 'critical' : 'medium');
    }
    if (collectsCredentials && externalActions.length) {
        add('form-exfil', 'Form submits to a different domain',
            `Data typed here is posted to ${externalActions.join(', ')}, not ${pageDomain}.`, 0.6, 'critical');
    }
    if (collectsCredentials && insecureActions.length) {
        add('form-http', 'Credentials submitted over plain HTTP', insecureActions[0], 0.45, 'high');
    }
    if (collectsCredentials && mailtoOrPhp.length && young) {
        add('kit-handler', 'Form handled by a bare PHP / mailto script',
            `${mailtoOrPhp[0]} — typical of phishing-kit collectors.`, 0.25, 'medium');
    }

    // ---- brand claimed vs. domain that actually hosts it
    // <title>/<meta> belong in the head: scanning only the first 100 KB bounds regex work.
    const head = html.slice(0, 100000);
    const { title, brand } = claimedBrand(head);
    const brandK = brandKey(brand);
    const brandMatches = !brandK || brandK.length < 3 || pageKey.includes(brandK) || brandK.includes(pageKey);
    if (collectsCredentials && !brandMatches) {
        add('brand-mismatch', 'Page claims a brand that does not own this domain',
            `Presents itself as "${brand}" but is hosted on ${pageDomain}.`, 0.6, 'critical');
    }

    // ---- where page resources come from (cloned pages hot-link the original)
    const refs = [...html.matchAll(/\b(?:src|href)\s*=\s*["']([^"']+)["']/gi)].map(m => m[1]);
    const refDomains = refs.map(r => domainOf(r, pageUrl)).filter(Boolean);
    const external = refDomains.filter(d => d !== pageDomain);
    const tally = external.reduce((t, d) => (t[d] = (t[d] || 0) + 1, t), {});
    const [topDomain, topCount] = Object.entries(tally).sort((a, b) => b[1] - a[1])[0] || [];
    // Legit sites load from their own CDNs, so this only counts when the page
    // claims a brand it does not own and pulls that brand's assets.
    const topKey = topDomain ? brandKey(parseDomain(topDomain).domainWithoutSuffix) : '';
    if (collectsCredentials && !brandMatches && topDomain && refDomains.length >= 8 &&
        topCount / refDomains.length > 0.3 && (topKey.includes(brandK) || brandK.includes(topKey))) {
        add('cloned-assets', 'Login page hot-links the impersonated brand\'s assets',
            `${Math.round(topCount / refDomains.length * 100)}% of resources load from ${topDomain} while the page lives on ${pageDomain} — a cloned login page.`, 0.5, 'critical');
    }

    const anchors = [...html.matchAll(/<a\b[^>]{0,1500}href\s*=\s*["']([^"']*)["']/gi)].map(m => m[1].trim());
    const deadLinks = anchors.filter(h => h === '#' || h === '' || /^javascript:\s*(void|;)/i.test(h)).length;
    if (anchors.length >= 8 && deadLinks / anchors.length > 0.5) {
        add('dead-links', 'Most links on the page lead nowhere',
            `${deadLinks}/${anchors.length} anchors are "#" or javascript:void — a facade page.`, 0.2, 'medium');
    }

    // ---- client-side tricks
    const meta = head.match(/<meta[^>]{1,1500}http-equiv\s*=\s*["']?refresh[^>]{0,1500}>/i);
    if (meta) {
        const target = (attr(meta[0], 'content') || '').split(/url\s*=/i)[1];
        const td = target ? domainOf(target.replace(/['"]/g, '').trim(), pageUrl) : null;
        add('meta-refresh', 'Automatic meta-refresh redirect',
            td ? `Bounces the visitor to ${td}.` : 'Page reloads itself automatically.', td && td !== pageDomain ? 0.3 : 0.08, td && td !== pageDomain ? 'medium' : 'low');
    }
    // nosemgrep: ajinabraham.njsscan.dos.regex_dos.regex_dos -- reviewed: bounded/linear regex, measured in tests/engine.test.js ReDoS case
    if (/(window|document|top)\.location(\.href)?\s*=|location\.replace\(/i.test(html) && html.length < 4000) {
        add('js-redirect', 'Script-driven redirect on a near-empty page',
            'Content is a thin wrapper that forwards the visitor elsewhere.', 0.2, 'medium');
    }

    const obfuscation = [
        [/\beval\s*\(/g, 'eval()'], [/\batob\s*\(/g, 'atob()'], [/\bunescape\s*\(/g, 'unescape()'],
        [/String\.fromCharCode\s*\(/g, 'String.fromCharCode()'], [/document\.write\s*\(/g, 'document.write()'],
    ].map(([re, name]) => [name, (html.match(re) || []).length]).filter(([, n]) => n > 0);
    // nosemgrep: ajinabraham.njsscan.dos.regex_dos.regex_dos -- reviewed: bounded/linear regex, measured in tests/engine.test.js ReDoS case
    const bigBlob = /["'][A-Za-z0-9+/=]{3000,}["']/.test(html);
    const obfScore = obfuscation.reduce((s, [, n]) => s + n, 0);
    if (bigBlob || obfScore >= 4) {
        add('obfuscated-js', 'Obfuscated JavaScript',
            `${obfuscation.map(([n, c]) => `${n}×${c}`).join(', ')}${bigBlob ? ', large encoded payload' : ''}.`, bigBlob ? 0.35 : 0.2, 'medium');
    }

    // nosemgrep: ajinabraham.njsscan.dos.regex_dos.regex_dos -- reviewed: bounded/linear regex, measured in tests/engine.test.js ReDoS case
    if (/<iframe[^>]{1,1500}(width\s*=\s*["']?0|height\s*=\s*["']?0|display\s*:\s*none|visibility\s*:\s*hidden)/i.test(html)) {
        add('hidden-iframe', 'Hidden iframe', 'Invisible frame loads third-party content silently.', 0.3, 'medium');
    }
    // Bounded whitespace: `\s*["']?\s*` was quadratic on long whitespace runs (ReDoS, see tests/engine.test.js).
    // nosemgrep: ajinabraham.njsscan.dos.regex_dos.regex_dos -- reviewed: bounded/linear regex, measured in tests/engine.test.js ReDoS case
    if (/oncontextmenu\s{0,10}=\s{0,10}["']?\s{0,10}return\s{1,10}false/i.test(lower) || /addEventListener\(\s*["']contextmenu["'][\s\S]{0,80}preventDefault/i.test(html)) {
        add('no-right-click', 'Right-click / inspect disabled', 'Page tries to stop visitors from inspecting it.', 0.15, 'low');
    }
    // nosemgrep: ajinabraham.njsscan.dos.regex_dos.regex_dos -- reviewed: bounded/linear regex, measured in tests/engine.test.js ReDoS case
    if (/\.apk["'\s>]/i.test(html) && /download|install/i.test(lower)) {
        add('apk-lure', 'Page pushes an Android APK download',
            'Sideloaded APKs are the main delivery method for banking trojans in SMS scams.', 0.45, 'high');
    }

    const facts = {
        title: title.slice(0, 200),
        claimedBrand: brand,
        forms: forms.length,
        passwordFields,
        sensitiveFields: [...new Set(sensitiveFields)].slice(0, 10),
        formTargets: [...new Set(formTargets)].slice(0, 10),
        externalResourceDomains: Object.entries(tally).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([d, n]) => ({ domain: d, count: n })),
        links: anchors.length,
        bytes: html.length,
    };
    return { facts, signals };
}

module.exports = { analyseContent };
