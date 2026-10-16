#!/usr/bin/env node
// scripts/check-config.js — validate configuration without starting the server.
// Prints problems by variable name only; never prints values.
//
//   NODE_ENV=production node scripts/check-config.js

const config = require('../lib/config');
const { errors, warnings } = config.validation;
console.log(`environment: ${config.env}`);
for (const w of warnings) console.log(`WARN  ${w}`);
for (const e of errors) console.log(`ERROR ${e}`);
console.log(errors.length ? `\n${errors.length} error(s): the server will refuse to start.` : '\nconfiguration OK');
process.exit(errors.length ? 1 : 0);
