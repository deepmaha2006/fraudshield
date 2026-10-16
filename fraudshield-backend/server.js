// server.js — process entry point: validate config, migrate, listen, shut down cleanly.

const os = require('os');
const config = require('./lib/config');
const { log } = require('./lib/logger');

const { errors, warnings } = config.validation;
for (const w of warnings) log.warn('config.warning', { message: w });
if (errors.length) {
    for (const e of errors) log.error('config.invalid', { message: e });
    process.stderr.write(`\nFraudShield refused to start — fix the configuration above (see .env.example).\n`);
    process.exit(1);
}

const { migrate, purgeExpired, close } = require('./db');
const { createApp } = require('./app');
const gmail = require('./integrations/gmail');

async function main() {
    const m = await migrate();
    log.info('db.ready', { schemaFrom: m.from, schemaTo: m.to });

    const purge = () => purgeExpired().then(r => log.info('retention.purged', r)).catch(err => log.error('retention.failed', { err }));
    await purge();
    const purgeTimer = setInterval(purge, 6 * 60 * 60 * 1000);
    purgeTimer.unref();

    const app = createApp();
    const server = app.listen(config.port, config.host, async () => {
        log.info('server.listening', { host: config.host, port: config.port, env: config.env });
        if (!config.isProd) {
            const lan = Object.values(os.networkInterfaces()).flat().filter(n => n && n.family === 'IPv4' && !n.internal).map(n => `http://${n.address}:${config.port}`);
            process.stdout.write(`\nFraudShield SOC console  http://localhost:${config.port}\n${lan.map(u => `  LAN / Android pairing   ${u}`).join('\n')}\n\n`);
        }
        const n = await gmail.startAll();
        if (n) log.info('gmail.watchers_starting', { accounts: n });
    });

    // Slowloris / hung-client protection.
    server.headersTimeout = 20 * 1000;
    server.requestTimeout = 120 * 1000; // live analysis of a slow site can take ~60 s
    server.keepAliveTimeout = 5 * 1000;
    server.maxHeadersCount = 100;

    let stopping = false;
    async function shutdown(signal) {
        if (stopping) return;
        stopping = true;
        log.info('server.stopping', { signal });
        const force = setTimeout(() => process.exit(1), 15 * 1000);
        force.unref();
        server.close();
        server.closeIdleConnections?.();
        await gmail.stopAll().catch(() => {});
        await close();
        log.info('server.stopped', {});
        process.exit(0);
    }
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}

process.on('unhandledRejection', reason => log.error('process.unhandled_rejection', { err: reason instanceof Error ? reason : { message: String(reason) } }));
process.on('uncaughtException', err => {
    log.error('process.uncaught_exception', { err });
    process.exit(1); // state is unknown — let the supervisor restart us
});

main().catch(err => {
    log.error('server.startup_failed', { err });
    process.exit(1);
});
