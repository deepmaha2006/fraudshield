// lib/sessions.js — opaque, server-side browser sessions.
//
//  • Cookie holds a 256-bit random token; the DB stores only its SHA-256.
//  • HttpOnly + SameSite=Strict (+ Secure and the __Host- prefix in production).
//  • Absolute lifetime and idle timeout; individually revocable; all sessions
//    of a user are revoked on password change / reset / account deletion.
//  • Each session has a CSRF token that state-changing requests must echo in
//    the X-CSRF-Token header (defence in depth on top of SameSite + Origin checks).

const crypto = require('crypto');
const config = require('./config');
const { run, get } = require('../db');
const { sha256, randomToken } = require('./secrets');

const COOKIE = config.cookieSecure ? '__Host-fs_session' : 'fs_session';
const TOUCH_INTERVAL_MS = 60 * 1000;

function parseCookies(header = '') {
    const out = {};
    for (const part of header.split(';')) {
        const i = part.indexOf('=');
        if (i < 0) continue;
        const k = part.slice(0, i).trim();
        if (k && !(k in out)) out[k] = decodeURIComponent(part.slice(i + 1).trim());
    }
    return out;
}

function cookieHeader(value, maxAgeSeconds) {
    const parts = [`${COOKIE}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAgeSeconds}`];
    if (config.cookieSecure) parts.push('Secure');
    return parts.join('; ');
}

async function createSession(res, user, req) {
    const token = randomToken(32);
    const csrf = randomToken(24);
    const now = Date.now();
    const expires = new Date(now + config.sessionTtlHours * 3600 * 1000).toISOString();
    await run(`INSERT INTO sessions (user_id, token_hash, csrf_token, expires_at, last_seen_at, ip, user_agent)
               VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [user.id, sha256(token), csrf, expires, new Date(now).toISOString(), req.ip || null, String(req.get('user-agent') || '').slice(0, 200)]);
    res.append('Set-Cookie', cookieHeader(token, config.sessionTtlHours * 3600));
    return { csrf, expiresAt: expires };
}

function clearCookie(res) {
    res.append('Set-Cookie', cookieHeader('', 0));
}

/** Resolve the request's session, or null. Enforces expiry, idle timeout and revocation. */
async function loadSession(req) {
    const token = parseCookies(req.headers.cookie)[COOKIE];
    if (!token || token.length > 100) return null;
    const s = await get(`SELECT s.id, s.user_id, s.csrf_token, s.expires_at, s.last_seen_at, s.revoked_at,
                                u.full_name, u.email, u.avatar_url
                         FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`, [sha256(token)]);
    if (!s || s.revoked_at) return null;
    const now = Date.now();
    if (new Date(s.expires_at).getTime() <= now) return null;
    const lastSeen = new Date(s.last_seen_at).getTime();
    if (now - lastSeen > config.sessionIdleMinutes * 60 * 1000) {
        await run(`UPDATE sessions SET revoked_at = ? WHERE id = ?`, [new Date(now).toISOString(), s.id]);
        return null;
    }
    if (now - lastSeen > TOUCH_INTERVAL_MS) {
        run('UPDATE sessions SET last_seen_at = ? WHERE id = ?', [new Date(now).toISOString(), s.id]).catch(() => {});
    }
    return s;
}

const revokeSession = id => run(`UPDATE sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ? AND revoked_at IS NULL`, [id]);

const revokeAllForUser = (userId, exceptSessionId = null) =>
    run(`UPDATE sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE user_id = ? AND revoked_at IS NULL AND id IS NOT ?`, [userId, exceptSessionId]);

function csrfValid(session, header) {
    if (!session || typeof header !== 'string' || header.length !== session.csrf_token.length) return false;
    return crypto.timingSafeEqual(Buffer.from(header), Buffer.from(session.csrf_token));
}

module.exports = { COOKIE, createSession, clearCookie, loadSession, revokeSession, revokeAllForUser, csrfValid, parseCookies };
