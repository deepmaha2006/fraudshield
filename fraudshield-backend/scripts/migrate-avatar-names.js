#!/usr/bin/env node
// scripts/migrate-avatar-names.js — one-time migration: rename legacy avatar names
// that embed the user ID (u<id>-<random>.<ext>) to fully-random names (<random>.<ext>),
// and update every DB reference in a single transaction.
//
// Usage:
//   node scripts/migrate-avatar-names.js [--dry-run]
//
//   --dry-run   Print what would change; write nothing.
//
// Prerequisites: stop the FraudShield service first so no concurrent writes occur.
// Run once. After it succeeds, the old u<id>- format is no longer accepted by
// isAvatarName() and will return 404 for any stale links.

const path = require('path');
const crypto = require('crypto');

// env must be set before requiring db / config
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const { run, get, all, tx, migrate, close } = require('../db');

const DRY_RUN = process.argv.includes('--dry-run');

// Matches only the old format: u<digits>-<rest>.<ext>
const LEGACY_NAME = /^u\d+-[\w-]+\.(png|jpg|webp|gif)$/;

// Generates a new fully-random name with the same extension.
function newName(ext) {
    // 16 random bytes → 22-char base64url string (same format as the upload path).
    return crypto.randomBytes(16).toString('base64url').replace(/[^A-Za-z0-9_-]/g, '') + '.' + ext;
}

function extOf(name) {
    return name.split('.').pop();
}

async function main() {
    await migrate();

    const rows = await all('SELECT name, user_id, mime, data FROM avatars');
    const legacy = rows.filter(r => LEGACY_NAME.test(r.name));

    if (legacy.length === 0) {
        console.log('No legacy avatar names found. Nothing to migrate.');
        await close();
        return;
    }

    console.log(`Found ${legacy.length} legacy avatar name(s) (${DRY_RUN ? 'DRY RUN — no changes written' : 'migrating'}):`);

    const plan = legacy.map(r => ({
        oldName: r.name,
        newName: newName(extOf(r.name)),
        userId: r.user_id,
        mime: r.mime,
        data: r.data,
    }));

    for (const p of plan) {
        console.log(`  user_id=${p.userId}  ${p.oldName}  →  ${p.newName}`);
    }

    if (DRY_RUN) {
        console.log('\n--dry-run: exiting without changes.');
        await close();
        return;
    }

    await tx(async () => {
        for (const p of plan) {
            const oldUrl = '/uploads/avatars/' + p.oldName;
            const newUrl = '/uploads/avatars/' + p.newName;

            // Insert under the new name (preserves the blob and timestamp).
            await run(
                `INSERT INTO avatars (name, user_id, mime, data, created_at)
                 SELECT ?, user_id, mime, data, created_at FROM avatars WHERE name = ?`,
                [p.newName, p.oldName],
            );

            // Update the user's avatar_url reference.
            await run(
                `UPDATE users SET avatar_url = ? WHERE id = ? AND avatar_url = ?`,
                [newUrl, p.userId, oldUrl],
            );

            // Delete the old row.
            await run('DELETE FROM avatars WHERE name = ?', [p.oldName]);
        }
    });

    // Verify: no legacy names should remain.
    const remaining = (await all('SELECT name FROM avatars')).filter(r => LEGACY_NAME.test(r.name));
    if (remaining.length > 0) {
        console.error(`ERROR: ${remaining.length} legacy name(s) still present after migration:`);
        remaining.forEach(r => console.error('  ' + r.name));
        await close();
        process.exit(1);
    }

    console.log(`\nMigrated ${plan.length} avatar(s) successfully.`);
    console.log('Next step: deploy the updated code so isAvatarName() only accepts the new format.');
    await close();
}

main().catch(err => {
    console.error('Migration failed:', err.message);
    process.exit(1);
});
