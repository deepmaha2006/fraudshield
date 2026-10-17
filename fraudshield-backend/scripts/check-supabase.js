#!/usr/bin/env node
// scripts/check-supabase.js — verify Supabase security posture for this schema.
//
// Checks:
//   1. Every application table has Row Level Security (RLS) enabled.
//   2. No application table is accessible by the Supabase API roles
//      (anon, authenticated) — schema-level REVOKE should be sufficient
//      but this confirms no table-level grant crept in.
//   3. The application schema is not in anon/authenticated search_path grants.
//
// Usage:
//   DATABASE_URL=postgresql://postgres.<ref>:<pw>@…/postgres node scripts/check-supabase.js
//
// Exit code 0 = all checks pass. Exit code 1 = one or more failures.

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const config = require('../lib/config');

if (!config.dbUrl || !/^postgres(ql)?:\/\//i.test(config.dbUrl)) {
    console.error('DATABASE_URL must be a postgres:// URL. This script is Supabase-specific.');
    process.exit(1);
}

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const u = new URL(config.dbUrl);
const local = ['localhost', '127.0.0.1', '::1'].includes(u.hostname);
const caFile = config.dbCaFile || path.join(__dirname, '..', 'certs', 'supabase-ca.crt');
const pool = new Pool({
    host: u.hostname,
    port: Number(u.port) || 5432,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: decodeURIComponent(u.pathname.slice(1)) || 'postgres',
    ssl: local ? false : { ca: fs.readFileSync(caFile, 'utf8'), rejectUnauthorized: true },
    options: `-c search_path=${config.dbSchema}`,
});

const q = (sql, params) => pool.query(sql, params).then(r => r.rows);

async function main() {
    const schema = config.dbSchema;
    let failures = 0;
    const fail = msg => { console.error('  FAIL:', msg); failures++; };
    const pass = msg => console.log('  PASS:', msg);

    console.log(`\nChecking schema: ${schema}\n`);

    // 1. Tables with RLS disabled
    console.log('1. Row Level Security');
    const noRls = await q(`
        SELECT c.relname AS table_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1
          AND c.relkind = 'r'
          AND NOT c.relrowsecurity
        ORDER BY c.relname
    `, [schema]);
    if (noRls.length === 0) {
        pass('RLS is enabled on all tables');
    } else {
        for (const { table_name } of noRls) fail(`RLS disabled on ${schema}.${table_name}`);
    }

    // 2. Table-level grants to anon / authenticated
    console.log('\n2. Table grants to anon / authenticated');
    const badGrants = await q(`
        SELECT grantee, table_name, privilege_type
        FROM information_schema.role_table_grants
        WHERE table_schema = $1
          AND grantee IN ('anon', 'authenticated')
        ORDER BY table_name, grantee
    `, [schema]);
    if (badGrants.length === 0) {
        pass('No table-level grants to anon or authenticated');
    } else {
        for (const r of badGrants) fail(`${r.grantee} has ${r.privilege_type} on ${schema}.${r.table_name}`);
    }

    // 3. Schema-level usage grants to anon / authenticated
    console.log('\n3. Schema USAGE grants to anon / authenticated');
    const schemaGrants = await q(`
        SELECT grantee, privilege_type
        FROM information_schema.role_usage_grants
        WHERE object_schema = $1
          AND grantee IN ('anon', 'authenticated')
    `, [schema]);
    if (schemaGrants.length === 0) {
        pass('No schema USAGE grants to anon or authenticated');
    } else {
        for (const r of schemaGrants) fail(`${r.grantee} has ${r.privilege_type} on schema ${schema}`);
    }

    // 4. Tables in this schema (informational)
    const tables = await q(`
        SELECT c.relname, c.relrowsecurity
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1 AND c.relkind = 'r'
        ORDER BY c.relname
    `, [schema]);
    console.log(`\nTables in schema ${schema}:`);
    for (const t of tables) {
        console.log(`  ${t.relname}  RLS=${t.relrowsecurity ? 'ON' : 'OFF'}`);
    }

    console.log(`\n${failures === 0 ? '✔ All checks passed.' : `✖ ${failures} check(s) failed.`}\n`);
    await pool.end();
    process.exit(failures > 0 ? 1 : 0);
}

main().catch(err => {
    console.error('Check failed:', err.message);
    pool.end().catch(() => {});
    process.exit(1);
});
