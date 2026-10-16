// engine/rdap.js
// Live domain registration lookup over RDAP (the IETF successor to WHOIS).
// The IANA bootstrap file maps each TLD to its authoritative registry, and the
// registry is queried directly for every domain.

const cache = new Map(); // domain -> { at, value }
const TTL = 60 * 60 * 1000;
const HEADERS = { Accept: 'application/rdap+json, application/json', 'User-Agent': 'FraudShield-SOC/2.0 (+rdap lookup)' };

let bootstrap = null; // { at, services: Map<tld, baseUrl> }
async function registryFor(domain) {
    if (!bootstrap || Date.now() - bootstrap.at > 24 * TTL) {
        const res = await fetch('https://data.iana.org/rdap/dns.json', { headers: HEADERS });
        if (!res.ok) throw new Error(`IANA bootstrap HTTP ${res.status}`);
        const data = await res.json();
        const services = new Map();
        for (const [tlds, urls] of data.services) {
            const base = urls.find(u => u.startsWith('https://')) || urls[0];
            for (const tld of tlds) services.set(tld.toLowerCase(), base.endsWith('/') ? base : base + '/');
        }
        bootstrap = { at: Date.now(), services };
    }
    const labels = domain.toLowerCase().split('.');
    for (let i = 1; i < labels.length; i++) {
        const base = bootstrap.services.get(labels.slice(i).join('.'));
        if (base) return base;
    }
    return null;
}

async function lookupRdap(domain) {
    const hit = cache.get(domain);
    if (hit && Date.now() - hit.at < TTL) return hit.value;

    const base = await registryFor(domain);
    if (!base) throw new Error(`No RDAP service published for .${domain.split('.').slice(1).join('.')}`);

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 7000);
    try {
        const res = await fetch(`${base}domain/${encodeURIComponent(domain)}`, {
            headers: HEADERS,
            redirect: 'follow',
            signal: ctrl.signal,
        });
        if (res.status === 404) {
            const value = { found: false };
            cache.set(domain, { at: Date.now(), value });
            return value;
        }
        if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
        const data = await res.json();

        const event = action => (data.events || []).find(e => e.eventAction === action)?.eventDate || null;
        const registrarEntity = (data.entities || []).find(e => (e.roles || []).includes('registrar'));
        const registrar = registrarEntity?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || registrarEntity?.handle || null;

        const value = {
            found: true,
            registered: event('registration'),
            expires: event('expiration'),
            lastChanged: event('last changed'),
            registrar,
            status: data.status || [],
            nameservers: (data.nameservers || []).map(n => (n.ldhName || '').toLowerCase()).filter(Boolean),
        };
        cache.set(domain, { at: Date.now(), value });
        return value;
    } finally {
        clearTimeout(timer);
    }
}

function analyseRdap(rdap, domain) {
    const signals = [];
    const add = (id, label, detail, weight, severity) =>
        signals.push({ id, category: 'Domain registration', label, detail, weight, severity });

    if (!rdap) return { ageDays: null, signals };
    if (!rdap.found) {
        add('unregistered', 'Domain is not registered',
            `The registry has no record of ${domain}; the link cannot belong to a real organisation.`, 0.5, 'high');
        return { ageDays: null, signals };
    }

    let ageDays = null;
    if (rdap.registered) {
        ageDays = Math.floor((Date.now() - new Date(rdap.registered).getTime()) / 86400000);
        if (ageDays < 7) add('age-days', 'Domain registered days ago', `${domain} is ${ageDays} day(s) old.`, 0.7, 'critical');
        else if (ageDays < 30) add('age-weeks', 'Newly registered domain', `${domain} is ${ageDays} days old.`, 0.5, 'high');
        else if (ageDays < 180) add('age-months', 'Young domain', `${domain} is ${ageDays} days old.`, 0.2, 'medium');
        else if (ageDays > 5 * 365) add('age-established', 'Long-established domain', `Registered ${Math.floor(ageDays / 365)} years ago.`, -0.45, 'trust');
        else if (ageDays > 2 * 365) add('age-mature', 'Mature domain', `Registered ${Math.floor(ageDays / 365)} years ago.`, -0.3, 'trust');
    }

    if (rdap.registered && rdap.expires) {
        const termDays = (new Date(rdap.expires) - new Date(rdap.registered)) / 86400000;
        if (ageDays !== null && ageDays < 365 && termDays <= 370) {
            add('short-term', 'Minimum one-year registration', 'Throwaway domains are rarely registered for longer than the minimum term.', 0.1, 'low');
        }
    }

    const holds = rdap.status.filter(s => /hold|suspend|redemption|pending delete/i.test(s));
    if (holds.length) {
        add('registry-hold', 'Registry has suspended this domain',
            `Status: ${holds.join(', ')} — registries apply holds after abuse reports.`, 0.55, 'high');
    }
    return { ageDays, signals };
}

module.exports = { lookupRdap, analyseRdap };
