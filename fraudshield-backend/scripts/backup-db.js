#!/usr/bin/env node
// scripts/backup-db.js — consistent online backup of the SQLite database.
//
//   node scripts/backup-db.js [--dir <backup-dir>] [--keep <n>]
//
// Uses `VACUUM INTO`, which produces a transactionally consistent copy while
// the server keeps running (WAL mode). The copy is integrity-checked and a
// SHA-256 sidecar is written. Backups must live OUTSIDE public/ and be
// readable only by the service account (0600 on POSIX).

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3');
const config = require('../lib/config');

const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
const dir = path.resolve(opt('--dir', process.env.BACKUP_DIR || path.join(__dirname, '..', 'backups')));
const keep = Number(opt('--keep', process.env.BACKUP_KEEP || 14));
const dbPath = path.resolve(__dirname, '..', config.dbFile);

const publicDir = path.resolve(__dirname, '..', 'public');
if (dir.startsWith(publicDir)) {
    console.error('Refusing to write backups inside public/.');
    process.exit(1);
}

const open = (file, mode) => new Promise((resolve, reject) => { const d = new sqlite3.Database(file, mode, e => e ? reject(e) : resolve(d)); });
const q = (d, sql, p = []) => new Promise((resolve, reject) => d.all(sql, p, (e, r) => e ? reject(e) : resolve(r)));
const closeDb = d => new Promise(r => d.close(() => r()));

async function main() {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const out = path.join(dir, `fraudshield-${stamp}.db`);

    const src = await open(dbPath, sqlite3.OPEN_READONLY);
    await q(src, 'PRAGMA busy_timeout = 10000');
    await q(src, 'VACUUM INTO ?', [out]);
    await closeDb(src);

    const copy = await open(out, sqlite3.OPEN_READONLY);
    const [{ integrity_check: integrity }] = await q(copy, 'PRAGMA integrity_check');
    const [{ user_version: version }] = await q(copy, 'PRAGMA user_version');
    await closeDb(copy);
    if (integrity !== 'ok') {
        fs.rmSync(out, { force: true });
        throw new Error(`Backup failed integrity check: ${integrity}`);
    }
    if (process.platform !== 'win32') fs.chmodSync(out, 0o600);
    const hash = crypto.createHash('sha256').update(fs.readFileSync(out)).digest('hex');
    fs.writeFileSync(`${out}.sha256`, `${hash}  ${path.basename(out)}\n`, { mode: 0o600 });

    // Rotation: keep the newest N backups.
    const backups = fs.readdirSync(dir).filter(f => /^fraudshield-.*\.db$/.test(f)).sort().reverse();
    for (const old of backups.slice(keep)) {
        fs.rmSync(path.join(dir, old), { force: true });
        fs.rmSync(path.join(dir, `${old}.sha256`), { force: true });
    }
    console.log(JSON.stringify({ backup: out, schemaVersion: version, integrity, sha256: hash, kept: Math.min(backups.length, keep) }));
}

main().catch(err => { console.error(`backup failed: ${err.message}`); process.exit(1); });
