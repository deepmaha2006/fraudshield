// integrations/gmail.js
// Real-time Gmail monitoring over IMAP IDLE. Gmail pushes an EXISTS event the
// moment a message lands in INBOX; we fetch it, run the detection pipeline,
// record the detection and (for malicious mail) apply a Gmail label.

const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const { run, get, all } = require('../db');
const { decrypt } = require('../lib/secrets');
const { publish } = require('../lib/realtime');
const { recordDetection } = require('../lib/detections');
const { analyzeMessage } = require('../engine');
const { ALERT_HEADER } = require('../mailer');
const { log } = require('../lib/logger');

const BACKFILL_ON_CONNECT = 5;   // analyse the latest few messages when first connected
const MAX_CATCH_UP = 25;         // after downtime, never process more than this at once
const THREAT_LABEL = 'FraudShield/Threat';

const watchers = new Map(); // userId -> GmailWatcher

class GmailWatcher {
    constructor(userId, email, password) {
        this.userId = userId;
        this.email = email;
        this.password = password;
        this.client = null;
        this.stopped = false;
        this.retryMs = 5000;
        this.queue = Promise.resolve();
    }

    async setStatus(status, error = null) {
        this.status = status;
        await run('UPDATE gmail_accounts SET status = ?, last_error = ? WHERE user_id = ?', [status, error, this.userId]).catch(() => {});
        publish(this.userId, 'integration', { type: 'gmail', status, error, email: this.email });
    }

    scheduleRetry(reason) {
        if (this.stopped || this.retryTimer) return;
        this.setStatus('reconnecting', reason);
        this.retryTimer = setTimeout(() => {
            this.retryTimer = null;
            if (!this.stopped) this.start().catch(() => {});
        }, this.retryMs);
        this.retryMs = Math.min(this.retryMs * 2, 5 * 60 * 1000);
    }

    async start() {
        this.stopped = false;
        await this.setStatus('connecting');
        const client = new ImapFlow({
            host: 'imap.gmail.com',
            port: 993,
            secure: true,
            auth: { user: this.email, pass: this.password },
            logger: false,
            emitLogs: false,
        });
        this.client = client;

        client.on('error', err => log.warn('gmail.client_error', { uid: this.userId, code: err.code, message: err.message }));
        client.on('close', () => {
            if (this.client !== client || this.stopped) return;
            this.scheduleRetry('Connection closed');
        });
        client.on('exists', () => this.enqueueSync());

        try {
            await client.connect();
        } catch (err) {
            const authFailed = err.authenticationFailed || /auth|credentials|Invalid/i.test(err.responseText || err.message);
            if (authFailed) {
                this.stopped = true;
                await this.setStatus('auth_failed', 'Gmail rejected the App Password. Generate a new one and reconnect.');
                throw Object.assign(new Error('Gmail rejected these credentials'), { status: 422 });
            }
            this.scheduleRetry(err.message);
            throw err;
        }

        // Holding the INBOX lock keeps the connection IDLE on it indefinitely.
        await client.getMailboxLock('INBOX');
        this.retryMs = 5000;
        await this.setStatus('live');
        this.enqueueSync();
    }

    enqueueSync() {
        this.queue = this.queue.then(() => this.sync()).catch(err => log.error('gmail.sync_failed', { uid: this.userId, message: err.message }));
    }

    async sync() {
        const client = this.client;
        if (!client || !client.mailbox) return;
        const { uidNext, uidValidity } = client.mailbox;
        const row = await get('SELECT last_uid, uid_validity FROM gmail_accounts WHERE user_id = ?', [this.userId]);
        if (!row) return this.stop();

        let lastUid = row.last_uid;
        if (lastUid == null || row.uid_validity !== String(uidValidity)) {
            lastUid = Math.max(0, uidNext - 1 - BACKFILL_ON_CONNECT);
            await run('UPDATE gmail_accounts SET last_uid = ?, uid_validity = ? WHERE user_id = ?', [lastUid, String(uidValidity), this.userId]);
        }
        if (uidNext - 1 <= lastUid) return;

        const from = Math.max(lastUid + 1, uidNext - MAX_CATCH_UP);
        const messages = [];
        for await (const msg of client.fetch(`${from}:*`, { uid: true, source: { maxLength: 2 * 1024 * 1024 } }, { uid: true })) {
            if (msg.uid > lastUid) messages.push({ uid: msg.uid, source: msg.source });
        }

        for (const msg of messages.sort((a, b) => a.uid - b.uid)) {
            try {
                await this.analyse(msg);
            } catch (err) {
                log.error('gmail.message_failed', { uid: this.userId, imapUid: msg.uid, message: err.message });
            }
            await run('UPDATE gmail_accounts SET last_uid = ? WHERE user_id = ?', [msg.uid, this.userId]);
        }
    }

    async analyse({ uid, source }) {
        const mail = await simpleParser(source, { skipImageLinks: true, skipTextToHtml: true });
        if (mail.headers.get(ALERT_HEADER.toLowerCase())) return; // our own alert e-mails

        const from = mail.from?.value?.[0] || {};
        const replyTo = mail.replyTo?.value?.[0]?.address || null;
        const authResults = [].concat(mail.headers.get('authentication-results') || []).join('; ');

        const report = await analyzeMessage({
            text: mail.text || '',
            html: typeof mail.html === 'string' ? mail.html : '',
            meta: { fromName: from.name, fromAddress: from.address, replyTo, authResults },
        });
        report.channel = { type: 'gmail', mailbox: this.email, uid, messageId: mail.messageId || null, date: mail.date || null };

        const firstLink = report.links[0]?.url;
        await recordDetection(this.userId, {
            source: 'gmail',
            sender: from.address ? `${from.name ? from.name + ' ' : ''}<${from.address}>` : null,
            subject: (mail.subject || '(no subject)').slice(0, 300),
            target: firstLink || mail.subject || '(no content)',
            report,
        });
        await run(`UPDATE gmail_accounts SET messages_scanned = messages_scanned + 1, last_event_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE user_id = ?`, [this.userId]);

        if (report.verdict === 'malicious') {
            // Gmail turns X-GM-LABELS into a visible label on the message.
            await this.client.messageFlagsAdd(String(uid), [THREAT_LABEL], { uid: true, useLabels: true })
                .catch(err => log.warn('gmail.label_failed', { uid: this.userId, message: err.message }));
        }
    }

    async stop() {
        this.stopped = true;
        clearTimeout(this.retryTimer);
        const c = this.client;
        this.client = null;
        if (c) await c.logout().catch(() => c.close());
    }
}

/** Verify credentials by logging in once, without starting a watcher. */
async function testCredentials(email, password) {
    const client = new ImapFlow({ host: 'imap.gmail.com', port: 993, secure: true, auth: { user: email, pass: password }, logger: false });
    try {
        await client.connect();
        await client.logout();
    } catch (err) {
        const msg = err.authenticationFailed
            ? 'Gmail rejected the login. Use a 16-character App Password (Google Account → Security → 2-Step Verification → App passwords), not your normal password.'
            : `Could not reach Gmail IMAP: ${err.message}`;
        throw Object.assign(new Error(msg), { status: err.authenticationFailed ? 422 : 502 });
    }
}

async function startWatcher(userId) {
    await stopWatcher(userId);
    const row = await get('SELECT email, secret, enabled FROM gmail_accounts WHERE user_id = ?', [userId]);
    if (!row || !row.enabled) return null;
    const w = new GmailWatcher(userId, row.email, decrypt(row.secret));
    watchers.set(userId, w);
    await w.start();
    return w;
}

async function stopWatcher(userId) {
    const w = watchers.get(userId);
    watchers.delete(userId);
    if (w) await w.stop();
}

async function startAll() {
    const rows = await all('SELECT user_id FROM gmail_accounts WHERE enabled = 1');
    for (const { user_id } of rows) {
        startWatcher(user_id).catch(err => log.warn('gmail.start_failed', { uid: user_id, message: err.message }));
    }
    return rows.length;
}

const watcherStatus = userId => watchers.get(userId)?.status || null;

async function stopAll() {
    await Promise.all([...watchers.keys()].map(stopWatcher));
}

module.exports = { testCredentials, startWatcher, stopWatcher, startAll, stopAll, watcherStatus };
