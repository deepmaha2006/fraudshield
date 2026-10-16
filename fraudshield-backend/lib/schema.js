// lib/schema.js — current schema version. Kept separate from db.js so tools
// (restore) can read it without opening the live database.
// Bump together with a new entry in db.js MIGRATIONS (db.js asserts they match).
module.exports = { SCHEMA_VERSION: 4 };
