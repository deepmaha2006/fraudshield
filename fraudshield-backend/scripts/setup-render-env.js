#!/usr/bin/env node
// scripts/setup-render-env.js
//
// Prompts for every production secret with hidden input (no echo), tests the
// database connection, then sets all env vars on the Render service via the
// Render API and triggers a deploy.  No secret value is ever printed.
//
// Usage:
//   node scripts/setup-render-env.js

'use strict';

const https   = require('https');
const crypto  = require('crypto');

const SERVICE_ID = 'srv-db9jsp61egvs73fi3jvg';
const DB_HOST    = 'aws-0-ap-southeast-1.pooler.supabase.com';
const DB_USER    = 'postgres.bprhmfuoyxalgoamaciu';

// ── hidden prompt (stdin raw mode, no echo) ────────────────────────────────
function hidden(question) {
    return new Promise((resolve, reject) => {
        if (!process.stdin.isTTY) return reject(new Error('stdin must be a TTY'));
        process.stdout.write(question);
        process.stdin.setRawMode(true);
        process.stdin.resume();
        process.stdin.setEncoding('utf8');
        let buf = '';
        const onData = (ch) => {
            if (ch === '\u0003') { process.exit(1); }                // Ctrl-C
            if (ch === '\r' || ch === '\n') {
                process.stdin.setRawMode(false);
                process.stdin.pause();
                process.stdin.removeListener('data', onData);
                process.stdout.write('\n');
                const value = buf;
                buf = '';                                             // wipe buffer
                return resolve(value);
            }
            if (ch === '\u007f' || ch === '\b') { buf = buf.slice(0, -1); return; }
            buf += ch;
        };
        process.stdin.on('data', onData);
    });
}

// ── Render API ─────────────────────────────────────────────────────────────
function renderAPI(method, path, apiKey, body) {
    return new Promise((resolve, reject) => {
        const payload = body !== undefined ? JSON.stringify(body) : undefined;
        const req = https.request({
            hostname: 'api.render.com',
            path: '/v1' + path,
            method,
            headers: {
                Authorization: `Bearer ${apiKey}`,
                Accept:        'application/json',
                ...(payload ? {
                    'Content-Type':   'application/json',
                    'Content-Length': Buffer.byteLength(payload),
                } : {}),
            },
        }, (res) => {
            let raw = '';
            res.on('data', c => { raw += c; });
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    try { resolve(JSON.parse(raw || '{}')); }
                    catch { resolve(raw); }
                } else {
                    reject(new Error(`Render API ${method} ${path} → HTTP ${res.statusCode}: ${raw.slice(0, 200)}`));
                }
            });
        });
        req.on('error', reject);
        if (payload) req.write(payload);
        req.end();
    });
}

// ── Postgres connectivity test ─────────────────────────────────────────────
async function testDB(url) {
    const { Client } = require('pg');
    const client = new Client({
        connectionString: url,
        ssl: true,
        connectionTimeoutMillis: 10000,
        statement_timeout: 5000,
    });
    try {
        await client.connect();
        await client.query('SELECT 1');
    } finally {
        await client.end().catch(() => {});
    }
}

// ── fetch ALL current Render env vars (cursor-paginated) ───────────────────
async function getAllEnvVars(apiKey) {
    const out = [];
    let cursor = '';
    for (;;) {
        const qs  = '?limit=100' + (cursor ? `&cursor=${cursor}` : '');
        const res = await renderAPI('GET', `/services/${SERVICE_ID}/env-vars${qs}`, apiKey);
        const page = Array.isArray(res) ? res : [];
        for (const item of page) {
            if (item?.envVar?.key) out.push({ key: item.envVar.key, value: item.envVar.value ?? '' });
        }
        if (page.length < 100) break;
        cursor = page[page.length - 1]?.cursor ?? '';
        if (!cursor) break;
    }
    return out;
}

// ── main ───────────────────────────────────────────────────────────────────
(async () => {
    console.log('\n=== FraudShield – Render production env setup ===\n');
    console.log('All input is hidden. Press Enter after each value.\n');

    // Collect secrets via hidden prompts
    const renderKey   = await hidden('Render API key (Account → API Keys):      ');
    const dbPassword  = await hidden('Supabase DB password:                      ');
    const smtpLogin   = await hidden('Brevo SMTP login email:                    ');
    const smtpKey     = await hidden('Brevo SMTP key:                            ');
    const senderEmail = await hidden('Verified sender email (Brevo Senders tab): ');
    const tsiteKey    = await hidden('Cloudflare Turnstile site key:             ');
    const tsecretKey  = await hidden('Cloudflare Turnstile secret key:           ');

    // Build and generate secrets — never printed
    const dbUrl  = `postgresql://${DB_USER}:${encodeURIComponent(dbPassword)}@${DB_HOST}:5432/postgres`;
    const encKey = crypto.randomBytes(32).toString('hex');

    // Assemble the env vars to upsert
    const updates = {
        DATABASE_URL:          dbUrl,
        DATA_ENCRYPTION_KEY:   encKey,
        MAIL_TRANSPORT:        'smtp',
        SMTP_HOST:             'smtp-relay.brevo.com',
        SMTP_PORT:             '2525',
        SMTP_USER:             smtpLogin,
        SMTP_PASS:             smtpKey,
        MAIL_FROM:             `FraudShield <${senderEmail}>`,
        TURNSTILE_SITE_KEY:    tsiteKey,
        TURNSTILE_SECRET_KEY:  tsecretKey,
    };

    // ── 1. Test DB connection first ────────────────────────────────────────
    process.stdout.write('\n[1/3] Testing database connection ... ');
    try {
        await testDB(dbUrl);
        console.log('OK');
    } catch (err) {
        console.log('FAIL');
        console.error('      ' + err.message);
        console.error('      Aborting — check your Supabase password and try again.');
        process.exit(1);
    }

    // ── 2. Fetch + merge env vars, then PUT ───────────────────────────────
    process.stdout.write('[2/3] Fetching existing Render env vars ... ');
    let existing = [];
    try {
        existing = await getAllEnvVars(renderKey);
        console.log(`OK (${existing.length} existing)`);
    } catch (err) {
        console.log('FAIL');
        console.error('      ' + err.message);
        process.exit(1);
    }

    // Merge: new values win; existing vars not in `updates` are preserved
    const merged = [
        ...existing.filter(e => !(e.key in updates)),
        ...Object.entries(updates).map(([key, value]) => ({ key, value })),
    ];

    process.stdout.write('[2/3] Uploading env vars ... ');
    try {
        await renderAPI('PUT', `/services/${SERVICE_ID}/env-vars`, renderKey, merged);
        console.log('OK');
    } catch (err) {
        console.log('FAIL');
        console.error('      ' + err.message);
        process.exit(1);
    }

    console.log('\n      Key                        Status');
    console.log('      ' + '-'.repeat(40));
    for (const key of Object.keys(updates)) {
        console.log(`      ${key.padEnd(28)} OK`);
    }

    // ── 3. Trigger deploy ─────────────────────────────────────────────────
    process.stdout.write('\n[3/3] Triggering deploy ... ');
    try {
        const dep = await renderAPI('POST', `/services/${SERVICE_ID}/deploys`, renderKey,
            { clearCache: 'do_not_clear_cache' });
        console.log('OK (deploy id: ' + (dep?.id ?? 'unknown') + ')');
    } catch (err) {
        console.log('FAIL');
        console.error('      ' + err.message);
        console.error('      Env vars were saved. Trigger the deploy manually in the Render dashboard.');
        process.exit(1);
    }

    // Wipe secrets from memory
    Object.keys(updates).forEach(k => { updates[k] = '\0'.repeat(64); delete updates[k]; });
    merged.forEach(e => { e.value = '\0'.repeat(64); });

    console.log('\nDone. Check the Render Logs tab — the server should say "listening" in ~2 min.');
    console.log('Live URL: https://fraudshield-jujl.onrender.com\n');
})().catch(err => {
    console.error('\nFatal:', err.message);
    process.exit(1);
});
