// End-to-end: back up a live database, damage it, restore, verify the data.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { db, tmpDir, releaseDbFiles } = require('./helpers');

const backupDir = path.join(tmpDir, 'backups');
const run = (script, args) => execFileSync(process.execPath, [path.join(__dirname, '..', 'scripts', script), ...args], { env: process.env, encoding: 'utf8' });

before(async () => { await db.migrate(); });
after(async () => { await db.close().catch(() => {}); });

test('backup is consistent, verified, and restorable', async () => {
    await db.run("INSERT INTO users (full_name, email) VALUES ('Backup Me', 'backup@example.test')");
    const out = JSON.parse(run('backup-db.js', ['--dir', backupDir]));
    assert.equal(out.integrity, 'ok');
    assert.ok(fs.existsSync(out.backup));
    assert.ok(fs.existsSync(`${out.backup}.sha256`));

    // Restore must refuse while the database is in use by this process' open transaction.
    await db.run('BEGIN IMMEDIATE');
    assert.throws(() => run('restore-db.js', [out.backup, '--yes']), /in use|locked/i);
    await db.run('ROLLBACK');

    // Simulate data loss after the backup, then restore with the app stopped.
    await db.run("DELETE FROM users WHERE email = 'backup@example.test'");
    await db.close();
    await releaseDbFiles();
    const restored = JSON.parse(run('restore-db.js', [out.backup, '--yes']).split('\n')[0]);
    assert.equal(restored.integrity, 'ok');
    assert.ok(fs.readdirSync(tmpDir).some(f => f.includes('.pre-restore-')), 'previous DB kept aside, not deleted');

    const { createClient } = require('@libsql/client');
    const check = createClient({ url: `file:${process.env.DB_FILE}` });
    const { rows } = await check.execute("SELECT email FROM users WHERE email = 'backup@example.test'");
    check.close();
    assert.equal(rows[0]?.email, 'backup@example.test');
});

test('restore rejects a tampered backup', () => {
    const file = fs.readdirSync(backupDir).find(f => f.endsWith('.db'));
    const p = path.join(backupDir, file);
    fs.appendFileSync(p, Buffer.from('tamper'));
    assert.throws(() => run('restore-db.js', [p, '--yes']), /SHA-256 mismatch/);
});

test('restore requires explicit confirmation', () => {
    assert.throws(() => run('restore-db.js', ['whatever.db']), /usage/);
});
