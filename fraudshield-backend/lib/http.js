// lib/http.js — authentication, CSRF/origin enforcement, rate limiting,
// request validation and error helpers.

const config = require('./config');
const { log } = require('./logger');
const { loadSession, csrfValid, parseCookies, COOKIE } = require('./sessions');

const httpError = (status, message, extra = {}) => Object.assign(new Error(message), { status, expose: true, ...extra });

// ------------------------------------------------------------ authentication
/** Require a valid browser session. Deny by default. */
async function authenticate(req, res, next) {
    const session = await loadSession(req);
    if (!session) {
        // Only worth recording when our own session cookie was presented and refused.
        if (parseCookies(req.headers.cookie)[COOKIE]) log.security('auth.session_rejected', { rid: req.id, ip: req.ip, path: req.path, level: 'info' });
        return res.status(401).json({ message: 'Authentication required.' });
    }
    req.session = session;
    req.user = { id: session.user_id, name: session.full_name, email: session.email };
    next();
}

// ------------------------------------------------------------ CSRF / cross-origin
const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

function expectedOrigin(req) {
    return config.publicBaseUrl || `${req.protocol}://${req.get('host')}`;
}

/**
 * Reject cross-site state-changing requests. Applies to every unsafe /api
 * request except device ingest (token-authenticated, no cookies involved).
 */
function originGuard(req, res, next) {
    if (SAFE.has(req.method) || req.path.startsWith('/ingest/')) return next();
    const origin = req.get('origin');
    const site = req.get('sec-fetch-site');
    const ok = origin ? origin === expectedOrigin(req) : (!site || site === 'same-origin' || site === 'none');
    if (!ok) {
        log.security('csrf.origin_rejected', { rid: req.id, ip: req.ip, path: req.path, origin, site });
        return res.status(403).json({ message: 'Cross-origin request rejected.' });
    }
    next();
}

/** For authenticated unsafe requests, require the session's CSRF token in X-CSRF-Token. */
function requireCsrf(req, res, next) {
    if (SAFE.has(req.method)) return next();
    if (!csrfValid(req.session, req.get('x-csrf-token'))) {
        log.security('csrf.token_rejected', { rid: req.id, ip: req.ip, uid: req.user?.id, path: req.path });
        return res.status(403).json({ message: 'Missing or invalid CSRF token. Reload the page.' });
    }
    next();
}

// ------------------------------------------------------------ rate limiting
/**
 * Fixed-window in-memory limiter. Single-instance by design (see
 * SECURE_DEPLOYMENT.md for multi-instance deployments).
 */
function rateLimit({ name, windowMs, max, keyFn, perIp = false, message = 'Too many requests, slow down.' }) {
    if (perIp) max *= config.rateLimitScale;
    const hits = new Map();
    setInterval(() => {
        const now = Date.now();
        for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
    }, windowMs).unref();
    return (req, res, next) => {
        const key = keyFn(req);
        const now = Date.now();
        let entry = hits.get(key);
        if (!entry || entry.reset < now) { entry = { count: 0, reset: now + windowMs }; hits.set(key, entry); }
        entry.count++;
        res.setHeader('RateLimit-Remaining', Math.max(0, max - entry.count));
        if (entry.count > max) {
            if (entry.count === max + 1) log.security('ratelimit.triggered', { rid: req.id, ip: req.ip, uid: req.user?.id, limiter: name, path: req.path });
            res.setHeader('Retry-After', Math.ceil((entry.reset - now) / 1000));
            return res.status(429).json({ message });
        }
        next();
    };
}

/**
 * Per-account login throttling with exponential back-off, independent of the
 * caller's IP (defeats distributed guessing against one account).
 */
const loginFailures = new Map(); // emailKey -> { count, until, last }
const LOCK_THRESHOLD = 5;
setInterval(() => { // forget stale entries so address-spraying cannot grow memory unboundedly
    const cutoff = Date.now() - 60 * 60 * 1000;
    for (const [k, f] of loginFailures) if (f.last < cutoff && f.until < Date.now()) loginFailures.delete(k);
}, 10 * 60 * 1000).unref();
const loginThrottle = {
    check(emailKey) {
        const f = loginFailures.get(emailKey);
        if (f && f.until > Date.now()) return Math.ceil((f.until - Date.now()) / 1000);
        return 0;
    },
    fail(emailKey) {
        const f = loginFailures.get(emailKey) || { count: 0, until: 0, last: 0 };
        f.count++;
        f.last = Date.now();
        if (f.count >= LOCK_THRESHOLD) f.until = Date.now() + Math.min(2 ** (f.count - LOCK_THRESHOLD) * 30, 3600) * 1000;
        loginFailures.set(emailKey, f);
        return f.count;
    },
    succeed(emailKey) { loginFailures.delete(emailKey); },
    reset() { loginFailures.clear(); },
};

// ------------------------------------------------------------ validation
/**
 * Minimal strict schema validation. Unknown keys and wrong types are rejected.
 * spec: { field: { type: 'string'|'boolean'|'integer', required, min, max, pattern, enum, trim, lower } }
 */
function validate(spec, source = 'body') {
    return (req, res, next) => {
        const input = req[source] ?? {};
        if (typeof input !== 'object' || Array.isArray(input)) return next(httpError(400, 'Invalid request.'));
        const out = {};
        for (const key of Object.keys(input)) {
            if (!Object.prototype.hasOwnProperty.call(spec, key)) {
                log.security('validation.unknown_field', { rid: req.id, path: req.path, field: key, level: 'info' });
                return next(httpError(400, `Unexpected field "${String(key).slice(0, 40)}".`));
            }
        }
        for (const [key, rule] of Object.entries(spec)) {
            let v = input[key];
            if (v === undefined || v === null || v === '') {
                if (rule.required) return next(httpError(400, `${rule.label || key} is required.`));
                continue;
            }
            if (rule.type === 'boolean') {
                if (typeof v !== 'boolean') return next(httpError(400, `${rule.label || key} must be true or false.`));
            } else if (rule.type === 'integer') {
                v = typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : v;
                if (!Number.isInteger(v) || (rule.min != null && v < rule.min) || (rule.max != null && v > rule.max)) {
                    return next(httpError(400, `${rule.label || key} is out of range.`));
                }
            } else {
                if (typeof v !== 'string') return next(httpError(400, `${rule.label || key} must be text.`));
                if (rule.trim !== false) v = v.trim();
                if (rule.lower) v = v.toLowerCase();
                if (rule.min != null && v.length < rule.min) return next(httpError(400, `${rule.label || key} must be at least ${rule.min} characters.`));
                if (rule.max != null && v.length > rule.max) return next(httpError(400, `${rule.label || key} must be at most ${rule.max} characters.`));
                if (rule.maxBytes != null && Buffer.byteLength(v) > rule.maxBytes) return next(httpError(400, `${rule.label || key} is too long.`));
                if (rule.pattern && !rule.pattern.test(v)) return next(httpError(400, rule.patternMessage || `${rule.label || key} has an invalid format.`));
                if (rule.enum && !rule.enum.includes(v)) return next(httpError(400, `${rule.label || key} is not an allowed value.`));
            }
            out[key] = v;
        }
        req.valid = out;
        next();
    };
}

const EMAIL = { type: 'string', max: 254, lower: true, pattern: /^[^\s@<>"',;]+@[^\s@<>"',;]+\.[^\s@<>"',;]{2,}$/, patternMessage: 'Enter a valid email address.' };
// bcrypt only uses the first 72 bytes; refuse longer passwords instead of silently truncating.
const PASSWORD = { type: 'string', trim: false, min: 8, maxBytes: 72, label: 'Password' };

module.exports = { authenticate, originGuard, requireCsrf, rateLimit, loginThrottle, validate, httpError, EMAIL, PASSWORD };
