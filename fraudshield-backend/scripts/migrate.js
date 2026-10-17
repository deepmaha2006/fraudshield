#!/usr/bin/env node
// scripts/migrate.js — run all pending database migrations (idempotent).
//
// Usage:
//   node scripts/migrate.js            # applies all pending steps
//   DATABASE_URL=postgres://… node scripts/migrate.js
//
// The canonical migration logic lives in db.js (SQLite) / lib/pg.js (PostgreSQL).
// The SQL reference files in migrations/*.sql document what each step creates;
// for PostgreSQL they can also be applied manually with psql when needed.

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const db = require('../db');

db.migrate()
    .then(({ from, to }) => {
        if (from === to) {
            console.log(`Schema is already at version ${to}. Nothing to do.`);
        } else {
            console.log(`Migrations applied: v${from} → v${to}`);
        }
        return db.close();
    })
    .then(() => process.exit(0))
    .catch(err => {
        console.error('Migration failed:', err.message);
        process.exit(1);
    });
