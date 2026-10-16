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
const { createClient } = require('@libsql/client');
const config = require('../lib/config');

const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
const dir = path.resolve(opt('--dir', process.env.BACKUP_DIR || path.join(__dirname, '..', 'backups')));
const keep = Number(opt('--keep', process.env.BACKUP_KEEP || 14));
const dbPath = path.resolve(__dirname, '..', config.dbFile);
if (config.dbUrl) {
    console.error('DATABASE_URL points at a remote database: use the provider backups instead (Supabase: daily backups / pg_dump; Turso: `turso db shell <db> .dump`).');
    process.exit(1);
}

const publicDir = path.resolve(__dirname, '..', 'public');
if (dir.startsWith(publicDir)) {
    console.error('Refusing to write backups inside public/.');
    process.exit(1);
}

const open = file => createClient({ url: `file:${file}` });
const q = async (d, sql, args = []) => { const rs = await d.execute({ sql, args }); return rs.rows.map(r => Object.fromEntries(rs.columns.map((c, i) => [c, r[i]]))); };
const closeDb = d => d.close();
// Schema version: schema_meta table (current), PRAGMA user_version (before the libSQL switch).
const versionOf = d => q(d, 'SELECT version FROM schema_meta WHERE id = 1').then(r => r[0]?.version ?? 0, () => q(d, 'PRAGMA user_version').then(r => r[0].user_version));

async function main() {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const out = path.join(dir, `fraudshield-${stamp}.db`);

    const src = open(dbPath);
    await q(src, 'PRAGMA busy_timeout = 10000');
    await q(src, 'VACUUM INTO ?', [out]);
    await closeDb(src);

    const copy = open(out);
    const [{ integrity_check: integrity }] = await q(copy, 'PRAGMA integrity_check');
    const version = await versionOf(copy);
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
