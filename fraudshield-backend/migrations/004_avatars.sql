-- Migration 004 — profile pictures stored in the database.
-- Pictures survive hosts without a persistent disk (e.g. Render free plan).
-- `data` is BYTEA. Names are 22-char base64url random IDs; the old u<id>-*
-- format is rejected by the application after running migrate-avatar-names.js.
SET search_path TO fraudshield;

CREATE TABLE IF NOT EXISTS avatars (
    name       TEXT PRIMARY KEY
                   CHECK(name ~ '^[A-Za-z0-9_-]{22}\.(png|jpg|webp|gif)$'),
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mime       TEXT NOT NULL,
    data       BYTEA NOT NULL,
    created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
);
CREATE INDEX IF NOT EXISTS idx_avatars_user ON avatars(user_id);
ENABLE ROW LEVEL SECURITY ON avatars;
ALTER TABLE avatars FORCE ROW LEVEL SECURITY;

UPDATE schema_meta SET version = 4 WHERE id = 1;
