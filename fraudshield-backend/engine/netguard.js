// engine/netguard.js
// Guards outbound connections made while probing untrusted URLs.
// Every hostname is resolved once, every resolved address is checked, and the
// socket is pinned to the vetted address so DNS rebinding cannot redirect us
// to internal infrastructure (SSRF protection).

const dns = require('dns');
const net = require('net');

const dnsp = dns.promises;

function ipv4ToInt(ip) {
    return ip.split('.').reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
}

const V4_BLOCKS = [
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
    ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
    ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
    ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([base, bits]) => [ipv4ToInt(base), bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0]);

function isPrivateIp(ip) {
    if (net.isIPv4(ip)) {
        const n = ipv4ToInt(ip);
        return V4_BLOCKS.some(([base, mask]) => ((n & mask) >>> 0) === base);
    }
    if (net.isIPv6(ip)) {
        const lower = ip.toLowerCase();
        const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
        if (mapped) return isPrivateIp(mapped[1]);
        return lower === '::' || lower === '::1' ||
            /^f[cd]/.test(lower) ||          // fc00::/7 unique local
            /^fe[89ab]/.test(lower) ||       // fe80::/10 link local
            /^ff/.test(lower) ||             // multicast
            lower.startsWith('2001:db8') ||  // documentation
            lower.startsWith('64:ff9b');     // NAT64
    }
    return true;
}

class BlockedAddressError extends Error {
    constructor(host, ip) {
        super(`Refused to connect: ${host} resolves to non-public address ${ip}`);
        this.code = 'EBLOCKED';
        this.ip = ip;
    }
}

/** Resolve a hostname to public addresses only. Throws if any address is internal. */
async function resolvePublic(hostname) {
    if (net.isIP(hostname)) {
        if (isPrivateIp(hostname)) throw new BlockedAddressError(hostname, hostname);
        return [{ address: hostname, family: net.isIPv6(hostname) ? 6 : 4 }];
    }
    const records = await dnsp.lookup(hostname, { all: true, verbatim: true });
    for (const r of records) {
        if (isPrivateIp(r.address)) throw new BlockedAddressError(hostname, r.address);
    }
    return records;
}

/** A `lookup` implementation for http/https/tls that only ever yields a pre-vetted address. */
function pinnedLookup(address, family) {
    return (_hostname, options, cb) => {
        if (typeof options === 'function') cb = options;
        if (options && options.all) return cb(null, [{ address, family }]);
        cb(null, address, family);
    };
}

module.exports = { isPrivateIp, resolvePublic, pinnedLookup, BlockedAddressError };
