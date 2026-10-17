'use strict';
// Send one test e-mail to verify the configured transport works.
// Usage: node scripts/test-mail.js you@example.com
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const to = process.argv[2];
if (!to || !to.includes('@')) {
    console.error('Usage: node scripts/test-mail.js you@example.com');
    process.exit(1);
}

const config = require('../lib/config');
if (config.validation.errors.length) {
    console.error('Config errors — fix these before testing mail:');
    for (const e of config.validation.errors) console.error('  •', e);
    process.exit(1);
}

const { sendPasswordReset } = require('../mailer');

async function main() {
    const m = config.mail;
    const desc = m.transport === 'smtp'
        ? `smtp://${m.smtpHost}:${m.smtpPort}`
        : m.transport;
    console.log(`Sending test e-mail via ${desc} → ${to}`);

    const ok = await sendPasswordReset(
        { full_name: 'Test Delivery', email: to },
        `${config.publicBaseUrl || 'https://test.example'}/reset-password.html?token=TEST-ONLY-NOT-A-REAL-LINK`,
    );

    if (ok) {
        console.log('✓ Delivered. Check your inbox.');
    } else {
        console.error('✗ Send failed. Set LOG_LEVEL=debug and re-run for details.');
        process.exit(1);
    }
}

main().catch(e => { console.error(e); process.exit(1); });
