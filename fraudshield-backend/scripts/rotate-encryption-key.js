#!/usr/bin/env node
// scripts/rotate-encryption-key.js
// Re-encrypts every stored Gmail App Password from OLD_KEY to NEW_KEY.
//
// ─── How to run ─────────────────────────────────────────────────────────────
//
//  Step 1 — Back up the database first.
//           For SQLite:   node scripts/backup-db.js
//           For Postgres: pg_dump <your-database-url> > backup_$(date +%Y%m%d).sql
//
//  Step 2 — Dry run (verifies all rows decrypt without writing anything):
//           OLD_KEY=<current-64-hex-key> NEW_KEY=<new-64-hex-key> \
//               node scripts/rotate-encryption-key.js --dry-run
//
//  Step 3 — Apply (re-encrypts in a single transaction):
//           OLD_KEY=<current-64-hex-key> NEW_KEY=<new-64-hex-key> \
//               node scripts/rotate-encryption-key.js
//
//  Step 4 — Swap the env var:
//           Update DATA_ENCRYPTION_KEY in your .env and in your production
//           secret manager to NEW_KEY. Restart the server.
//
//  Step 5 — Verify:
//           Check that existing Gmail integrations still show "active" status
//           on the Integrations page.
//
// ─── Safety guarantees ──────────────────────────────────────────────────────
//  • Never prints decrypted values.
//  • If any row fails to decrypt with OLD_KEY, the script aborts without
//    writing anything (even without --dry-run).
//  • All updates run inside a single DB transaction: either all succeed or
//    none do.
//  • Refuses to run if OLD_KEY === NEW_KEY.
// ────────────────────────────────────────────────────────────────────────────

'use strict';

const crypto = require('crypto');
const TAG_LENGTH = 16; // must match lib/secrets.js

// ── Inline crypto so the script is independent of lib/secrets.js + config ──

function decryptWithKey(blob, keyBuf) {
    const [version, iv, tag, data] = String(blob).split(':');
    if (version !== 'v1') throw new Error('Unknown secret format');
    const ivBuf  = Buffer.from(iv   || '', 'base64');
    const tagBuf = Buffer.from(tag  || '', 'base64');
    if (ivBuf.length !== 12 || tagBuf.length !== TAG_LENGTH) throw new Error('Malformed secret (wrong IV or tag length)');
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, ivBuf, { authTagLength: TAG_LENGTH });
    decipher.setAuthTag(tagBuf);
    return Buffer.concat([decipher.update(Buffer.from(data, 'base64')), decipher.final()]).toString('utf8');
}

function encryptWithKey(plain, keyBuf) {
    const iv     = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv, { authTagLength: TAG_LENGTH });
    const data   = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
    return ['v1', iv.toString('base64'), cipher.getAuthTag().toString('base64'), data.toString('base64')].join(':');
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
    const dryRun = process.argv.includes('--dry-run');
    const oldHex = process.env.OLD_KEY;
    const newHex = process.env.NEW_KEY;

    if (!oldHex || !/^[0-9a-f]{64}$/i.test(oldHex)) {
        console.error('ERROR: set OLD_KEY to the current 64-hex DATA_ENCRYPTION_KEY.');
        process.exit(1);
    }
    if (!newHex || !/^[0-9a-f]{64}$/i.test(newHex)) {
        console.error('ERROR: set NEW_KEY to the new 64-hex DATA_ENCRYPTION_KEY.');
        console.error('  Generate: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
        process.exit(1);
    }
    if (oldHex.toLowerCase() === newHex.toLowerCase()) {
        console.error('ERROR: OLD_KEY and NEW_KEY must be different.');
        process.exit(1);
    }

    const oldBuf = Buffer.from(oldHex, 'hex');
    const newBuf = Buffer.from(newHex, 'hex');

    // Set a valid DATA_ENCRYPTION_KEY before requiring db (config.js validates it at load time).
    process.env.DATA_ENCRYPTION_KEY = oldHex;
    const db = require('../db');

    try {
        await db.migrate();

        const rows = await db.all('SELECT user_id, secret FROM gmail_accounts');

        if (rows.length === 0) {
            console.log('No Gmail accounts found — nothing to rotate.');
            console.log('Update DATA_ENCRYPTION_KEY in your .env and restart the server.');
            return;
        }

        console.log(`Found ${rows.length} Gmail account(s).`);

        // ── Phase 1: verify all rows decrypt with OLD_KEY ──────────────────
        const decrypted = [];
        let failures   = 0;
        for (const row of rows) {
            try {
                const plain = decryptWithKey(row.secret, oldBuf);
                decrypted.push({ user_id: row.user_id, plain });
            } catch (err) {
                console.error(`  FAIL user_id=${row.user_id}: ${err.message}`);
                failures++;
            }
        }

        if (failures > 0) {
            console.error(`\nAborted: ${failures} row(s) failed to decrypt.`);
            console.error('Verify that OLD_KEY matches the key currently in DATA_ENCRYPTION_KEY.');
            process.exit(1);
        }

        console.log(`All ${rows.length} row(s) verified (decryption successful).`);

        if (dryRun) {
            console.log('\n--dry-run: no changes were written.');
            console.log('Re-run without --dry-run to apply the re-encryption.');
            return;
        }

        // ── Phase 2: re-encrypt in a single transaction ────────────────────
        let updated = 0;
        await db.tx(async () => {
            for (const { user_id, plain } of decrypted) {
                const newSecret = encryptWithKey(plain, newBuf);
                const { changes } = await db.run(
                    'UPDATE gmail_accounts SET secret = ? WHERE user_id = ?',
                    [newSecret, user_id]
                );
                if (!changes) throw new Error(`Row user_id=${user_id} disappeared during transaction — rolled back.`);
                updated++;
            }
        });

        console.log(`\nSuccess: ${updated} row(s) re-encrypted.`);
        console.log('\nNext steps:');
        console.log('  1. Update DATA_ENCRYPTION_KEY in your .env and production secret manager to NEW_KEY.');
        console.log('  2. Restart the server.');
        console.log('  3. Verify that Gmail integrations still show "active" status in the console.');

    } finally {
        await db.close();
    }
}

main().catch(err => {
    console.error('Fatal:', err.message);
    process.exit(1);
});
