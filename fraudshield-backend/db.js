// db.js — database access: promise helpers, safe transactions, versioned
// migrations, retention housekeeping.
//
// Three modes, one set of (SQLite-flavoured) SQL:
//   * local file  (DB_FILE)                         — development, tests, single-host installs
//   * remote      (DATABASE_URL + DATABASE_AUTH_TOKEN, e.g. Turso) — hosts without a persistent disk
//   * PostgreSQL  (DATABASE_URL=postgres://…, e.g. Supabase) — statements are translated by lib/pg.js

const { createClient } = require('@libsql/client');
const fs = require('fs');
const path = require('path');
const { AsyncLocalStorage } = require('async_hooks');
const config = require('./lib/config');

const PG = /^postgres(ql)?:\/\//i.test(config.dbUrl);
const REMOTE = Boolean(config.dbUrl);
const DB_PATH = REMOTE ? null : config.dbFile === ':memory:' ? ':memory:' : path.resolve(__dirname, config.dbFile);
const pg = PG ? require('./lib/pg') : null;
const client = PG ? null : REMOTE
    ? createClient({ url: config.dbUrl, authToken: config.dbAuthToken })
    : createClient({ url: DB_PATH === ':memory:' ? ':memory:' : `file:${DB_PATH}` });
const pool = PG ? pg.createPool(config) : null;

// One client is shared by every request. While a transaction is open, any
// statement issued outside it must wait, so writes from different requests
// can never interleave with (or be rolled back by) another request's transaction.
const txContext = new AsyncLocalStorage(); // store: the open libSQL transaction
let lock = Promise.resolve();
async function waitTurn() {
    for (;;) {
        const current = lock;
        await current;
        if (current === lock) return; // no new transaction started meanwhile
    }
}

// sqlite3 bound `undefined` as NULL; libSQL rejects it — keep the old contract.
const bind = params => Array.isArray(params) ? params.map(v => v === undefined ? null : v) : params;
async function execute(sql, params = []) {
    const t = txContext.getStore();
    if (PG) {
        const q = pg.translate(sql);
        const r = await (t || pool).query({ text: q.text, values: bind(params), rowMode: 'array' });
        return { columns: r.fields.map(f => f.name), rows: r.rows, rowsAffected: r.rowCount, lastInsertRowid: q.returnsId ? r.rows[0]?.[r.fields.findIndex(f => f.name === 'id')] : undefined };
    }
    if (!t) await waitTurn();
    return (t || client).execute({ sql, args: bind(params) });
}
const toObject = (rs, row) => Object.fromEntries(rs.columns.map((c, i) => [c, row[i]]));

const run = async (sql, params = []) => {
    const rs = await execute(sql, params);
    return { lastID: rs.lastInsertRowid === undefined ? undefined : Number(rs.lastInsertRowid), changes: rs.rowsAffected };
};
const get = async (sql, params = []) => {
    const rs = await execute(sql, params);
    return rs.rows.length ? toObject(rs, rs.rows[0]) : undefined;
};
const all = async (sql, params = []) => {
    const rs = await execute(sql, params);
    return rs.rows.map(r => toObject(rs, r));
};

/** Run fn() atomically. Nested calls join the outer transaction. */
async function tx(fn) {
    if (txContext.getStore()) return fn();
    if (PG) {
        // The pool hands each transaction its own connection, so no global lock is needed.
        const conn = await pool.connect();
        try {
            await conn.query('BEGIN');
            const result = await txContext.run(conn, fn);
            await conn.query('COMMIT');
            return result;
        } catch (err) {
            await conn.query('ROLLBACK').catch(() => {});
            throw err;
        } finally {
            conn.release();
        }
    }
    // Inline (not `await waitTurn()`): the lock must be taken in the same tick the wait ends.
    for (;;) {
        const current = lock;
        await current;
        if (current === lock) break;
    }
    let release;
    lock = new Promise(r => { release = r; }); // taken synchronously after the wait
    try {
        if (!REMOTE) {
            // Local file: one connection, plain BEGIN/COMMIT (libSQL's transaction() would open a
            // second connection to the same file and contend with this one for the write lock).
            return await txContext.run(client, async () => {
                await run('BEGIN IMMEDIATE');
                try {
                    const result = await fn();
                    await run('COMMIT');
                    return result;
                } catch (err) {
                    await run('ROLLBACK').catch(() => {});
                    throw err;
                }
            });
        }
        // Remote: every request is stateless, so the transaction must be an interactive libSQL one.
        const t = await client.transaction('write');
        try {
            const result = await txContext.run(t, fn);
            await t.commit();
            return result;
        } catch (err) {
            await t.rollback().catch(() => {});
            throw err;
        } finally {
            t.close();
        }
    } finally {
        release();
    }
}

const NOW = "(strftime('%Y-%m-%dT%H:%M:%fZ','now'))";

// Ordered, append-only migrations tracked in PRAGMA user_version; each runs in
// a transaction. Never edit a released step — append a new one.
const MIGRATIONS = [
    // 1: baseline schema (idempotent, so pre-existing databases adopt it unchanged)
    async () => {
        await run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            phone_number VARCHAR(20),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            avatar_url VARCHAR(255),
            email_high_risk_enabled TINYINT(1) NOT NULL DEFAULT 1,
            email_weekly_summary_enabled TINYINT(1) NOT NULL DEFAULT 1,
            total_scans INTEGER NOT NULL DEFAULT 0,
            threats_neutralized INTEGER NOT NULL DEFAULT 0,
            community_reports INTEGER NOT NULL DEFAULT 0
        )`);
        await run(`CREATE TABLE IF NOT EXISTS user_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        await run(`CREATE TABLE IF NOT EXISTS identity_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            document_type TEXT CHECK(document_type IN ('Aadhaar', 'PAN', 'DL', 'Passport')) NOT NULL,
            document_number_hash VARCHAR(255) NOT NULL,
            full_name_on_doc VARCHAR(255) NOT NULL,
            dob_on_doc DATE NOT NULL,
            verification_status TEXT CHECK(verification_status IN ('Pending', 'Approved', 'Rejected')) NOT NULL DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        await run(`CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            phone_number VARCHAR(20),
            issue_description TEXT NOT NULL,
            ticket_status TEXT CHECK(ticket_status IN ('Open', 'In Progress', 'Closed')) NOT NULL DEFAULT 'Open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        await run(`CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            source TEXT NOT NULL CHECK(source IN ('manual', 'screenshot', 'gmail', 'sms')),
            kind TEXT NOT NULL CHECK(kind IN ('url', 'message')),
            sender TEXT,
            subject TEXT,
            target TEXT NOT NULL,
            risk INTEGER NOT NULL,
            verdict TEXT NOT NULL CHECK(verdict IN ('legit', 'suspicious', 'malicious')),
            confidence INTEGER,
            summary TEXT,
            report TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'acknowledged', 'resolved', 'false_positive')),
            created_at TEXT NOT NULL DEFAULT ${NOW}
        )`);
        await run('CREATE INDEX IF NOT EXISTS idx_detections_user_time ON detections(user_id, created_at DESC)');
        await run(`CREATE TABLE IF NOT EXISTS gmail_accounts (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            email TEXT NOT NULL,
            secret TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'connecting',
            last_error TEXT,
            last_uid INTEGER,
            uid_validity TEXT,
            messages_scanned INTEGER NOT NULL DEFAULT 0,
            last_event_at TEXT,
            created_at TEXT NOT NULL DEFAULT ${NOW}
        )`);
        await run(`CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            platform TEXT NOT NULL DEFAULT 'android',
            token_hash TEXT NOT NULL UNIQUE,
            messages_received INTEGER NOT NULL DEFAULT 0,
            last_seen_at TEXT,
            created_at TEXT NOT NULL DEFAULT ${NOW}
        )`);
    },

    // 2: server-side sessions and password-reset tokens
    async () => {
        await run(`CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            csrf_token TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT ${NOW},
            last_seen_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            ip TEXT,
            user_agent TEXT
        )`);
        await run('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)');
        await run(`CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL DEFAULT ${NOW}
        )`);
        await run('CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id)');
    },

    // 3: e-mail ownership verification. Alert e-mails are only sent to verified addresses,
    // so the service cannot be used to mail arbitrary third parties. Accounts that existed
    // before this migration are grandfathered as verified (documented in SECURITY_AUDIT.md).
    async () => {
        await run('ALTER TABLE users ADD COLUMN email_verified_at TEXT');
        await run(`UPDATE users SET email_verified_at = ${NOW} WHERE email_verified_at IS NULL`);
        await run(`CREATE TABLE IF NOT EXISTS email_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL DEFAULT ${NOW}
        )`);
        await run('CREATE INDEX IF NOT EXISTS idx_email_verifications_user ON email_verifications(user_id)');
    },

    // 4: profile pictures move into the database so they survive hosts without a persistent
    // disk. Pictures already on disk are imported once; links whose file is gone are cleared.
    async () => {
        await run(`CREATE TABLE IF NOT EXISTS avatars (
            name TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            mime TEXT NOT NULL,
            data BLOB NOT NULL,
            created_at TEXT NOT NULL DEFAULT ${NOW}
        )`);
        await run('CREATE INDEX IF NOT EXISTS idx_avatars_user ON avatars(user_id)');
        const { nameFromUrl, mimeFor } = require('./lib/avatars');
        for (const u of await all('SELECT id, avatar_url FROM users WHERE avatar_url IS NOT NULL')) {
            const name = nameFromUrl(u.avatar_url);
            let data = null;
            // eslint-disable-next-line security/detect-non-literal-fs-filename -- name validated by nameFromUrl (server-generated pattern)
            if (name) try { data = fs.readFileSync(path.join(config.uploadDir, 'avatars', name)); } catch { /* file no longer exists */ }
            if (data) await run('INSERT OR IGNORE INTO avatars (name, user_id, mime, data) VALUES (?, ?, ?, ?)', [name, u.id, mimeFor(name), data]);
            else await run('UPDATE users SET avatar_url = NULL WHERE id = ?', [u.id]);
        }
    },
];

if (MIGRATIONS.length !== require('./lib/schema').SCHEMA_VERSION || (PG && pg.MIGRATIONS.length !== MIGRATIONS.length)) {
    throw new Error('lib/schema.js SCHEMA_VERSION must equal the number of migrations in db.js and lib/pg.js');
}

// The schema version lives in a table rather than PRAGMA user_version, which
// hosted libSQL does not persist. Databases created before the switch adopt
// their user_version once.
async function schemaVersion() {
    await run('CREATE TABLE IF NOT EXISTS schema_meta (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL)');
    const row = await get('SELECT version FROM schema_meta WHERE id = 1');
    if (row) return row.version;
    if (PG) { await run('INSERT INTO schema_meta (id, version) VALUES (1, 0)'); return 0; }
    const legacy = await get('PRAGMA user_version').then(r => r?.user_version || 0).catch(() => 0);
    await run('INSERT INTO schema_meta (id, version) VALUES (1, ?)', [legacy]);
    return legacy;
}

async function migrate() {
    if (PG) await pg.prepareSchema(pool);
    if (!REMOTE) {
        await run('PRAGMA busy_timeout = 5000');
        await run('PRAGMA foreign_keys = ON');
        await run('PRAGMA journal_mode = WAL');
        await run('PRAGMA synchronous = NORMAL');
    }
    const from = await schemaVersion();
    for (let v = from; v < MIGRATIONS.length; v++) {
        await tx(async () => {
            await (PG ? pg.MIGRATIONS[v](run) : MIGRATIONS[v]());
            await run('UPDATE schema_meta SET version = ? WHERE id = 1', [v + 1]);
        });
    }
    restrictFilePermissions();
    return { from, to: MIGRATIONS.length };
}

/** Owner-only access to the database and its WAL/SHM files (POSIX; on Windows use NTFS ACLs — see SECURE_DEPLOYMENT.md). */
function restrictFilePermissions() {
    if (process.platform === 'win32' || REMOTE || DB_PATH === ':memory:') return;
    for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
        // eslint-disable-next-line security/detect-non-literal-fs-filename -- path is server-generated (config dir + multer/regex-validated name), never user input
        try { fs.chmodSync(f, 0o600); } catch { /* file may not exist yet */ }
    }
}

const integrityCheck = async () => PG ? (await get('SELECT 1 AS ok'))?.ok === 1 : (await get('PRAGMA quick_check')).quick_check === 'ok';

/** Data-retention housekeeping; idempotent. */
async function purgeExpired() {
    const cutoff = new Date(Date.now() - config.retentionDays * 86400000).toISOString();
    const week = new Date(Date.now() - 7 * 86400000).toISOString();
    const d = await run('DELETE FROM detections WHERE created_at < ?', [cutoff]);
    const s = await run('DELETE FROM sessions WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)', [week, week]);
    const r = await run('DELETE FROM password_resets WHERE expires_at < ?', [week]);
    const v = await run('DELETE FROM email_verifications WHERE expires_at < ?', [week]);
    return { detections: d.changes, sessions: s.changes, passwordResets: r.changes, emailVerifications: v.changes };
}

let closed = false;
async function close() {
    if (closed) return;
    closed = true;
    if (PG) await pool.end();
    else client.close();
}

module.exports = { client, run, get, all, tx, migrate, integrityCheck, purgeExpired, close, REMOTE, PG, DB_PATH, MIGRATIONS };
