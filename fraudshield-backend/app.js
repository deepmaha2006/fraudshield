// app.js — builds the Express application (no listening, no side effects),
// so tests can run it against a disposable database.

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const config = require('./lib/config');
const { log, requestLogger } = require('./lib/logger');
const { originGuard } = require('./lib/http');
const { get } = require('./db');

function createApp() {
    const app = express();

    // Only the configured reverse proxy may set X-Forwarded-*; never "trust all".
    app.set('trust proxy', config.trustProxy || false);
    app.disable('x-powered-by');
    app.set('etag', false);

    app.use(requestLogger);
    app.use(helmet({
        contentSecurityPolicy: {
            useDefaults: false,
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", 'https://cdnjs.cloudflare.com'],
                // Inline style attributes are used for computed widths/colours; no inline scripts are allowed.
                styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
                fontSrc: ["'self'", 'https://fonts.gstatic.com'],
                imgSrc: ["'self'", 'data:'],
                connectSrc: ["'self'"],
                objectSrc: ["'none'"],
                baseUri: ["'none'"],
                frameAncestors: ["'none'"],
                formAction: ["'self'"],
                ...(config.isProd ? { upgradeInsecureRequests: [] } : {}),
            },
        },
        crossOriginEmbedderPolicy: false,
        hsts: config.isProd ? { maxAge: 31536000, includeSubDomains: true } : false,
        referrerPolicy: { policy: 'no-referrer' },
    }));
    app.use((req, res, next) => {
        res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
        next();
    });

    // ---- health (no auth, no details)
    app.get('/healthz', (req, res) => res.json({ status: 'ok' }));
    app.get('/readyz', async (req, res) => {
        const ok = await get('SELECT 1 AS ok').then(r => r?.ok === 1).catch(() => false);
        res.status(ok ? 200 : 503).json({ status: ok ? 'ready' : 'unavailable' });
    });

    // ---- API
    app.use('/api', (req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
    // Phones / SMS forwarders call ingest cross-origin with a device token (no cookies).
    app.use('/api/ingest', cors({ origin: '*', methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-Token'], credentials: false }));
    app.use('/api', express.json({ limit: '256kb', strict: true, type: 'application/json' }));
    app.use('/api', originGuard);

    app.use('/api', require('./routes/account'));
    app.use('/api', require('./routes/integrations'));
    app.use('/api', require('./routes/soc'));
    app.use('/api', (req, res) => res.status(404).json({ message: 'Not found.' }));

    // ---- user uploads: only verified images, from a dedicated directory, never executable.
    app.use('/uploads', express.static(config.uploadDir, {
        dotfiles: 'deny',
        index: false,
        redirect: false,
        setHeaders(res, filePath) {
            if (!/\.(png|jpg|webp|gif)$/i.test(filePath)) res.setHeader('Content-Type', 'application/octet-stream');
            res.setHeader('Content-Disposition', 'inline');
            res.setHeader('Content-Security-Policy', "default-src 'none'; img-src 'self'; sandbox");
            res.setHeader('Cache-Control', 'private, max-age=86400');
        },
    }));

    // ---- static console. dotfiles are refused; the DB, .env and source live outside public/.
    const publicDir = path.join(__dirname, 'public');
    app.use(express.static(publicDir, {
        extensions: ['html'],
        dotfiles: 'deny',
        index: 'index.html',
        setHeaders(res, filePath) {
            if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
            // The service worker must revalidate on every load so fixes reach browsers immediately.
            if (filePath.endsWith(`${path.sep}sw.js`)) res.setHeader('Cache-Control', 'no-cache');
            if (filePath.includes(`${path.sep}uploads${path.sep}`)) res.setHeader('Content-Disposition', 'inline');
        },
    }));

    // Browsers asking for a page get the animated status page; everything else gets plain text.
    // Browsers name text/html explicitly; `*/*` (curl, scripts, scanners) keeps the plain-text answer.
    const wantsPage = req => (req.method === 'GET' || req.method === 'HEAD') && /\btext\/html\b/i.test(req.get('accept') || '');
    app.use((req, res) => {
        if (wantsPage(req)) return res.status(404).sendFile(path.join(publicDir, '404.html'), { headers: { 'Cache-Control': 'no-store' } });
        res.status(404).type('text/plain').send('Not found');
    });

    // ---- errors: generic to clients, detailed (sanitised) to logs
    app.use((err, req, res, next) => {
        if (res.headersSent) return;
        let status = err.status || err.statusCode || 500;
        let message = err.expose && status < 500 ? err.message : 'Internal server error.';
        if (err.type === 'entity.parse.failed') { status = 400; message = 'Malformed JSON.'; }
        if (err.type === 'entity.too.large') { status = 413; message = 'Request body too large.'; }
        if (status === 503 && err.expose) message = err.message;
        if (status >= 500) log.error('http.error', { rid: req.id, method: req.method, path: req.path, err });
        else if (status === 400 || status === 413 || status === 415) log.info('http.client_error', { rid: req.id, path: req.path, status, message });
        // A failing page load shows the friendly error page (never details); API callers get JSON.
        if (status >= 500 && !req.originalUrl.startsWith('/api') && wantsPage(req)) {
            return res.status(status).sendFile(path.join(publicDir, '500.html'), { headers: { 'Cache-Control': 'no-store' } });
        }
        res.status(status).json({ message, requestId: req.id });
    });

    return app;
}

module.exports = { createApp };
