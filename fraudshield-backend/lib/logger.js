// lib/logger.js — structured JSON-lines logging to stdout/stderr.
// Rotation and retention belong to the process supervisor (systemd-journald,
// Docker log driver) — see SECURE_DEPLOYMENT.md.
//
// Never log: passwords, cookies, Authorization headers, device tokens, reset
// tokens, App Passwords, message bodies. `redact()` enforces this for any
// object passed in, by key name.

const config = require('./config');

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 99 };
const threshold = LEVELS[config.logLevel] ?? LEVELS.info;

// Matched against object keys. Anchored so counters like "sessions" or "passwordResets" stay visible.
const SENSITIVE = /^(.*password|pass|secret|.*token|cookie|set-cookie|authorization|csrf.*|.*key|body|text|html|preview|source)$/i;

function clean(value) {
    // Neutralise CR/LF and other control characters (log forging).
    // eslint-disable-next-line no-control-regex -- deliberately strips control characters (log/header injection defence)
    return typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 500) : value;
}

function redact(obj, depth = 0) {
    if (obj === null || typeof obj !== 'object') return clean(obj);
    if (depth > 4) return '[depth]';
    if (obj instanceof Error) return { name: obj.name, message: clean(obj.message), code: obj.code, stack: config.isProd ? undefined : clean(obj.stack) };
    const out = Array.isArray(obj) ? [] : {};
    for (const [k, v] of Object.entries(obj)) out[k] = SENSITIVE.test(k) ? '[redacted]' : redact(v, depth + 1);
    return out;
}

function write(level, event, fields = {}) {
    if (LEVELS[level] < threshold) return;
    const line = JSON.stringify({ ts: new Date().toISOString(), level, event, ...redact(fields) });
    (LEVELS[level] >= LEVELS.warn ? process.stderr : process.stdout).write(line + '\n');
}

const log = {
    debug: (e, f) => write('debug', e, f),
    info: (e, f) => write('info', e, f),
    warn: (e, f) => write('warn', e, f),
    error: (e, f) => write('error', e, f),
    /** Security-relevant event; always carries `security: true` for alert routing. */
    security: (e, f = {}) => write(f.level || 'warn', e, { security: true, ...f, level: undefined }),
};

/** Express middleware: request id + one access-log line per request (no query strings, no bodies). */
function requestLogger(req, res, next) {
    const started = process.hrtime.bigint();
    const incoming = req.get('x-request-id');
    req.id = incoming && /^[\w-]{8,64}$/.test(incoming) ? incoming : require('crypto').randomUUID();
    res.setHeader('X-Request-Id', req.id);
    // Captured now: routers rewrite req.path (strip mount points) before the response finishes.
    const reqPath = req.path;
    res.on('finish', () => {
        if (!reqPath.startsWith('/api') || reqPath === '/api/stream') return;
        log.info('http', {
            rid: req.id, method: req.method, path: reqPath, status: res.statusCode,
            ms: Number((process.hrtime.bigint() - started) / 1000000n), ip: req.ip, uid: req.user?.id,
        });
    });
    next();
}

module.exports = { log, redact, requestLogger };
