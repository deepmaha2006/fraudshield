// lib/config.js — single source of configuration, validated at startup.
// Production fails closed: missing or unsafe settings stop the process.

require('dotenv').config({ quiet: true, path: process.env.DOTENV_PATH || require('path').join(__dirname, '..', '.env') });

const env = process.env;

// nosemgrep: ajinabraham.njsscan.dos.regex_dos.regex_dos -- reviewed: anchored alternation on an env value
const bool = (v, dflt) => v === undefined || v === '' ? dflt : /^(1|true|yes|on)$/i.test(v);
const int = (v, dflt, min, max) => {
    const n = v === undefined || v === '' ? dflt : Number(v);
    if (!Number.isInteger(n) || n < min || n > max) throw new Error(`expected integer ${min}-${max}, got "${v}"`);
    return n;
};

function load() {
    // Re-read on every call so reload() in tests can override NODE_ENV.
    const NODE_ENV = env.NODE_ENV || 'development';
    const isProd = NODE_ENV === 'production';
    const isTest = NODE_ENV === 'test';

    const errors = [];
    const warnings = [];
    const check = (name, fn) => { try { return fn(); } catch (e) { errors.push(`${name}: ${e.message}`); return undefined; } };

    const mailDefault = isTest ? 'memory' : (env.EMAIL_USER && env.EMAIL_APP_PASSWORD ? 'gmail' : env.SMTP_HOST ? 'smtp' : 'disabled');
    const cfg = {
        env: NODE_ENV,
        isProd,
        isTest,
        port: check('PORT', () => int(env.PORT, 3000, 0, 65535)),
        // Production sits behind a TLS reverse proxy, so bind to loopback unless told otherwise.
        host: env.HOST || (isProd ? '127.0.0.1' : '0.0.0.0'),
        dbFile: env.DB_FILE || 'fraudshield.db',
        // Remote database for hosts without a persistent disk; when set, DB_FILE is ignored.
        // postgres://… (e.g. Supabase) or libsql://… (e.g. Turso, with DATABASE_AUTH_TOKEN).
        dbUrl: env.DATABASE_URL || '',
        dbAuthToken: env.DATABASE_AUTH_TOKEN || '',
        dbCaFile: env.DATABASE_CA_FILE || '',
        dbSchema: env.DATABASE_SCHEMA || 'fraudshield', // PostgreSQL only
        dbPoolSize: check('DATABASE_POOL_SIZE', () => int(env.DATABASE_POOL_SIZE, 5, 1, 100)),
        // User uploads live outside the code tree and outside public/ (read-only images, writable data dir).
        uploadDir: require('path').resolve(__dirname, '..', env.UPLOAD_DIR || 'data/uploads'),
        dataKey: env.DATA_ENCRYPTION_KEY || '',
        publicBaseUrl: (env.PUBLIC_BASE_URL || '').replace(/\/$/, ''),
        // A hop count ("1") for platform load balancers with changing addresses, or proxy IPs / names.
        trustProxy: /^\d+$/.test(env.TRUST_PROXY || '') ? Number(env.TRUST_PROXY) : env.TRUST_PROXY || (isProd ? '' : 'loopback'),
        cookieSecure: bool(env.COOKIE_SECURE, isProd),
        sessionTtlHours: check('SESSION_TTL_HOURS', () => int(env.SESSION_TTL_HOURS, 12, 1, 168)),
        sessionIdleMinutes: check('SESSION_IDLE_MINUTES', () => int(env.SESSION_IDLE_MINUTES, 120, 5, 1440)),
        allowRegistration: bool(env.ALLOW_REGISTRATION, true),
        retentionDays: check('DETECTION_RETENTION_DAYS', () => int(env.DETECTION_RETENTION_DAYS, 180, 1, 3650)),
        // Multiplier for per-IP limits only (per-account / per-e-mail limits never scale).
        // Lets a deployment behind carrier-grade NAT raise them; tests raise it because every client is 127.0.0.1.
        rateLimitScale: check('RATE_LIMIT_SCALE', () => int(env.RATE_LIMIT_SCALE, 1, 1, 1000)),
        mail: {
            transport: env.MAIL_TRANSPORT || mailDefault,
            from: env.MAIL_FROM || env.EMAIL_USER || '',
            gmailUser: env.EMAIL_USER || '',
            gmailPass: env.EMAIL_APP_PASSWORD || '',
            smtpHost: env.SMTP_HOST || '',
            smtpPort: check('SMTP_PORT', () => int(env.SMTP_PORT, 465, 1, 65535)),
            smtpUser: env.SMTP_USER || '',
            smtpPass: env.SMTP_PASS || '',
        },
        logLevel: env.LOG_LEVEL || (isTest ? 'silent' : 'info'),
        turnstileSiteKey: env.TURNSTILE_SITE_KEY || '',
        turnstileSecretKey: env.TURNSTILE_SECRET_KEY || '',
    };

    // ---- always required
    if (!/^[0-9a-f]{64}$/i.test(cfg.dataKey)) errors.push('DATA_ENCRYPTION_KEY must be 64 hex characters (32 random bytes).');
    else if (/^(.)\1+$/.test(cfg.dataKey) || /^(0123456789abcdef)+$/i.test(cfg.dataKey)) errors.push('DATA_ENCRYPTION_KEY is a placeholder value; generate a random key.');
    const pgUrl = /^postgres(ql)?:\/\//i.test(cfg.dbUrl);
    if (cfg.dbUrl && !pgUrl && !/^(libsql|https|wss):\/\/[^\s/]+/i.test(cfg.dbUrl)) errors.push('DATABASE_URL must be a postgres://, libsql://, https:// or wss:// URL.');
    if (cfg.dbUrl && !pgUrl && !cfg.dbAuthToken) errors.push('DATABASE_URL is set but DATABASE_AUTH_TOKEN is missing.');
    if (!/^[a-z_][a-z0-9_]{0,62}$/.test(cfg.dbSchema)) errors.push('DATABASE_SCHEMA must be a lower-case SQL identifier.');
    if (pgUrl) check('DATABASE_URL', () => { if (!new URL(cfg.dbUrl).password) throw new Error('must include the database password.'); });
    if (!['gmail', 'smtp', 'memory', 'disabled'].includes(cfg.mail.transport)) errors.push('MAIL_TRANSPORT must be gmail, smtp, memory or disabled.');
    if (cfg.mail.transport === 'gmail' && !(cfg.mail.gmailUser && cfg.mail.gmailPass)) errors.push('MAIL_TRANSPORT=gmail needs EMAIL_USER and EMAIL_APP_PASSWORD.');
    if (cfg.mail.transport === 'smtp' && !(cfg.mail.smtpHost && cfg.mail.from)) errors.push('MAIL_TRANSPORT=smtp needs SMTP_HOST and MAIL_FROM.');

    // ---- production only (fail closed)
    // ALLOW_MINIMAL_START=true skips mail and CAPTCHA checks for initial deploy only.
    // Remove this env var and add real SMTP + Turnstile credentials before going public.
    const minimalStart = isProd && Boolean(env.ALLOW_MINIMAL_START);
    if (isProd) {
        if (!/^https:\/\/[^/]+$/i.test(cfg.publicBaseUrl)) errors.push('PUBLIC_BASE_URL must be the https:// origin users reach the console on.');
        if (!cfg.cookieSecure) errors.push('COOKIE_SECURE must not be disabled in production.');
        if (!cfg.trustProxy) errors.push('TRUST_PROXY must name the reverse proxy (e.g. "loopback" or its IP); refusing to guess.');
        if (cfg.trustProxy === 'true' || cfg.trustProxy === '*') errors.push('TRUST_PROXY must not trust every hop.');
        if (cfg.mail.transport === 'memory') errors.push('MAIL_TRANSPORT=memory is for tests only.');
        if (!minimalStart && cfg.mail.transport === 'disabled') errors.push('MAIL_TRANSPORT must be configured in production (gmail or smtp); password reset and alert e-mails require a working transport.');
        if (!minimalStart && (!cfg.turnstileSiteKey || !cfg.turnstileSecretKey)) errors.push('TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY are required in production (CAPTCHA cannot be skipped).');
    } else if (cfg.mail.transport === 'disabled') {
        warnings.push('No mail transport configured: alert and password-reset e-mails are disabled.');
    }
    for (const legacy of ['JWT_SECRET', 'SESSION_SECRET']) {
        if (env[legacy] && !isTest) warnings.push(`${legacy} is no longer used (sessions are server-side) and can be removed from .env.`);
    }

    return { cfg, errors, warnings };
}

const { cfg, errors, warnings } = load();
module.exports = cfg;
module.exports.validation = { errors, warnings };
module.exports.reload = load; // used by tests
