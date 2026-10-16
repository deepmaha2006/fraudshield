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
const sqlite3 = require('sqlite3');
const config = require('../lib/config');
const { SCHEMA_VERSION } = require('../lib/schema'); // not ../db: that would open the live database

const [file, confirm] = process.argv.slice(2);
if (!file || confirm !== '--yes') {
    console.error('usage: node scripts/restore-db.js <backup.db> --yes   (stop the service first)');
    process.exit(2);
}
const backup = path.resolve(file);
const target = path.resolve(__dirname, '..', config.dbFile);

const open = (f, mode) => new Promise((resolve, reject) => { const d = new sqlite3.Database(f, mode, e => e ? reject(e) : resolve(d)); });
const q = (d, sql) => new Promise((resolve, reject) => d.all(sql, (e, r) => e ? reject(e) : resolve(r)));
const closeDb = d => new Promise(r => d.close(() => r()));

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

    const d = await open(backup, sqlite3.OPEN_READONLY);
    const [{ integrity_check: integrity }] = await q(d, 'PRAGMA integrity_check');
    const [{ user_version: version }] = await q(d, 'PRAGMA user_version');
    await closeDb(d);
    if (integrity !== 'ok') throw new Error(`backup failed integrity check: ${integrity}`);
    if (version > SCHEMA_VERSION) throw new Error(`backup schema v${version} is newer than this code (v${SCHEMA_VERSION}); deploy the matching release first`);

    // The live DB must be quiescent: an exclusive lock fails if the server holds it.
    if (fs.existsSync(target)) {
        const live = await open(target, sqlite3.OPEN_READWRITE);
        try {
            await q(live, 'PRAGMA busy_timeout = 0');
            await q(live, 'BEGIN EXCLUSIVE');
            await q(live, 'ROLLBACK');
        } catch {
            await closeDb(live);
            throw new Error('database is in use — stop the FraudShield service before restoring');
        }
        await q(live, 'PRAGMA wal_checkpoint(TRUNCATE)').catch(() => {});
        await closeDb(live);
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
