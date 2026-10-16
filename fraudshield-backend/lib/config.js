// lib/config.js — single source of configuration, validated at startup.
// Production fails closed: missing or unsafe settings stop the process.

require('dotenv').config({ quiet: true, path: process.env.DOTENV_PATH || require('path').join(__dirname, '..', '.env') });

const env = process.env;
const NODE_ENV = env.NODE_ENV || 'development';
const isProd = NODE_ENV === 'production';
const isTest = NODE_ENV === 'test';

// nosemgrep: ajinabraham.njsscan.dos.regex_dos.regex_dos -- reviewed: anchored alternation on an env value
const bool = (v, dflt) => v === undefined || v === '' ? dflt : /^(1|true|yes|on)$/i.test(v);
const int = (v, dflt, min, max) => {
    const n = v === undefined || v === '' ? dflt : Number(v);
    if (!Number.isInteger(n) || n < min || n > max) throw new Error(`expected integer ${min}-${max}, got "${v}"`);
    return n;
};

function load() {
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
        // User uploads live outside the code tree and outside public/ (read-only images, writable data dir).
        uploadDir: require('path').resolve(__dirname, '..', env.UPLOAD_DIR || 'data/uploads'),
        dataKey: env.DATA_ENCRYPTION_KEY || '',
        publicBaseUrl: (env.PUBLIC_BASE_URL || '').replace(/\/$/, ''),
        trustProxy: env.TRUST_PROXY || (isProd ? '' : 'loopback'),
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
    };

    // ---- always required
    if (!/^[0-9a-f]{64}$/i.test(cfg.dataKey)) errors.push('DATA_ENCRYPTION_KEY must be 64 hex characters (32 random bytes).');
    else if (/^(.)\1+$/.test(cfg.dataKey) || /^(0123456789abcdef)+$/i.test(cfg.dataKey)) errors.push('DATA_ENCRYPTION_KEY is a placeholder value; generate a random key.');
    if (!['gmail', 'smtp', 'memory', 'disabled'].includes(cfg.mail.transport)) errors.push('MAIL_TRANSPORT must be gmail, smtp, memory or disabled.');
    if (cfg.mail.transport === 'gmail' && !(cfg.mail.gmailUser && cfg.mail.gmailPass)) errors.push('MAIL_TRANSPORT=gmail needs EMAIL_USER and EMAIL_APP_PASSWORD.');
    if (cfg.mail.transport === 'smtp' && !(cfg.mail.smtpHost && cfg.mail.from)) errors.push('MAIL_TRANSPORT=smtp needs SMTP_HOST and MAIL_FROM.');

    // ---- production only (fail closed)
    if (isProd) {
        if (!/^https:\/\/[^/]+$/i.test(cfg.publicBaseUrl)) errors.push('PUBLIC_BASE_URL must be the https:// origin users reach the console on.');
        if (!cfg.cookieSecure) errors.push('COOKIE_SECURE must not be disabled in production.');
        if (!cfg.trustProxy) errors.push('TRUST_PROXY must name the reverse proxy (e.g. "loopback" or its IP); refusing to guess.');
        if (cfg.trustProxy === 'true' || cfg.trustProxy === '*') errors.push('TRUST_PROXY must not trust every hop.');
        if (cfg.mail.transport === 'memory') errors.push('MAIL_TRANSPORT=memory is for tests only.');
        if (cfg.mail.transport === 'disabled') warnings.push('MAIL_TRANSPORT=disabled: password reset and alert e-mails will not be sent.');
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
