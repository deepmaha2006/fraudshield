#!/usr/bin/env node
// scripts/restore-db.js — restore a backup produced by backup-db.js.
//
//   node scripts/restore-db.js <backup.db> --yes
//
// STOP THE SERVICE FIRST. Steps: verify the SHA-256 sidecar, run
// PRAGMA integrity_check on the backup, refuse backups from a newer schema,
// move the current database (and WAL/SHM) aside as *.pre-restore-<time>,
// then copy the backup into place. Nothing is deleted.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { createClient } = require('@libsql/client');
const config = require('../lib/config');
const { SCHEMA_VERSION } = require('../lib/schema'); // not ../db: that would open the live database

const [file, confirm] = process.argv.slice(2);
if (!file || confirm !== '--yes') {
    console.error('usage: node scripts/restore-db.js <backup.db> --yes   (stop the service first)');
    process.exit(2);
}
const backup = path.resolve(file);
const target = path.resolve(__dirname, '..', config.dbFile);
if (config.dbUrl) {
    console.error('DATABASE_URL points at a remote database: use the provider backups instead (Supabase: daily backups / pg_dump; Turso: `turso db shell <db> .dump`).');
    process.exit(1);
}

const open = file => createClient({ url: `file:${file}` });
const q = async (d, sql, args = []) => { const rs = await d.execute({ sql, args }); return rs.rows.map(r => Object.fromEntries(rs.columns.map((c, i) => [c, r[i]]))); };
const closeDb = d => d.close();
// Schema version: schema_meta table (current), PRAGMA user_version (before the libSQL switch).
const versionOf = d => q(d, 'SELECT version FROM schema_meta WHERE id = 1').then(r => r[0]?.version ?? 0, () => q(d, 'PRAGMA user_version').then(r => r[0].user_version));

// Take (and release) an exclusive lock, then checkpoint the WAL, in a child process:
// libSQL only lets go of a file handle once the connection is garbage-collected, and
// Windows refuses to rename a file that is still open — process exit releases it for sure.
const PROBE = `
const { createClient } = require(process.env.LIBSQL_CLIENT);
const c = createClient({ url: 'file:' + process.env.RESTORE_TARGET });
(async () => {
    await c.execute('PRAGMA busy_timeout = 0');
    await c.execute('BEGIN EXCLUSIVE');
    await c.execute('ROLLBACK');
    await c.execute('PRAGMA wal_checkpoint(TRUNCATE)').catch(() => {});
})().then(() => process.exit(0), () => process.exit(3));`;
function quiescent(file) {
    try {
        execFileSync(process.execPath, ['-e', PROBE], {
            stdio: 'ignore',
            env: { ...process.env, LIBSQL_CLIENT: require.resolve('@libsql/client'), RESTORE_TARGET: file },
        });
        return true;
    } catch {
        return false;
    }
}

async function main() {
    if (!fs.existsSync(backup)) throw new Error('backup file not found');
    const sidecar = `${backup}.sha256`;
    if (fs.existsSync(sidecar)) {
        const expected = fs.readFileSync(sidecar, 'utf8').split(/\s+/)[0];
        const actual = crypto.createHash('sha256').update(fs.readFileSync(backup)).digest('hex');
        if (expected !== actual) throw new Error('SHA-256 mismatch — backup corrupted or tampered with');
    } else {
        console.warn('warning: no .sha256 sidecar; skipping hash verification');
    }

    const d = open(backup);
    const [{ integrity_check: integrity }] = await q(d, 'PRAGMA integrity_check');
    const version = await versionOf(d);
    await closeDb(d);
    if (integrity !== 'ok') throw new Error(`backup failed integrity check: ${integrity}`);
    if (version > SCHEMA_VERSION) throw new Error(`backup schema v${version} is newer than this code (v${SCHEMA_VERSION}); deploy the matching release first`);

    // The live DB must be quiescent: an exclusive lock fails if the server holds it.
    if (fs.existsSync(target)) {
        if (!quiescent(target)) throw new Error('database is in use — stop the FraudShield service before restoring');
        const stamp = new Date().toISOString().replace(/[:.]/g, '-');
        for (const suffix of ['', '-wal', '-shm']) {
            if (fs.existsSync(target + suffix)) fs.renameSync(target + suffix, `${target}${suffix}.pre-restore-${stamp}`);
        }
    }
    fs.copyFileSync(backup, target);
    if (process.platform !== 'win32') fs.chmodSync(target, 0o600);
    console.log(JSON.stringify({ restored: target, from: backup, schemaVersion: version, integrity }));
    console.log('Start the service; pending migrations (if any) run automatically.');
}

main().catch(err => { console.error(`restore failed: ${err.message}`); process.exit(1); });
