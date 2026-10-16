-- FraudShield SOC — SQLite schema (reference).
-- You do not need to run this: server.js creates and upgrades every table on
-- startup (db.js → migrate()). It is kept here as documentation.

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone_number VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    avatar_url VARCHAR(255),
    email_high_risk_enabled TINYINT(1) NOT NULL DEFAULT 1,
    email_weekly_summary_enabled TINYINT(1) NOT NULL DEFAULT 1,
    total_scans INTEGER NOT NULL DEFAULT 0,          -- legacy, no longer updated
    threats_neutralized INTEGER NOT NULL DEFAULT 0,  -- legacy, no longer updated
    community_reports INTEGER NOT NULL DEFAULT 0     -- legacy, no longer updated
);

CREATE TABLE IF NOT EXISTS user_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,              -- bcrypt
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS identity_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    document_type TEXT CHECK(document_type IN ('Aadhaar', 'PAN', 'DL', 'Passport')) NOT NULL,
    document_number_hash VARCHAR(255) NOT NULL,       -- bcrypt, never stored in clear
    full_name_on_doc VARCHAR(255) NOT NULL,
    dob_on_doc DATE NOT NULL,
    verification_status TEXT CHECK(verification_status IN ('Pending', 'Approved', 'Rejected')) NOT NULL DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS support_tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone_number VARCHAR(20),
    issue_description TEXT NOT NULL,
    ticket_status TEXT CHECK(ticket_status IN ('Open', 'In Progress', 'Closed')) NOT NULL DEFAULT 'Open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Every analysis (manual, screenshot, Gmail, SMS). `report` holds the full engine output as JSON.
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK(source IN ('manual', 'screenshot', 'gmail', 'sms')),
    kind TEXT NOT NULL CHECK(kind IN ('url', 'message')),
    sender TEXT,
    subject TEXT,
    target TEXT NOT NULL,
    risk INTEGER NOT NULL,
    verdict TEXT NOT NULL CHECK(verdict IN ('legit', 'suspicious', 'malicious')),
    confidence INTEGER,
    summary TEXT,
    report TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'acknowledged', 'resolved', 'false_positive')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_detections_user_time ON detections(user_id, created_at DESC);

-- One monitored Gmail inbox per user. `secret` = AES-256-GCM(App Password, DATA_ENCRYPTION_KEY).
CREATE TABLE IF NOT EXISTS gmail_accounts (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    secret TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'connecting',
    last_error TEXT,
    last_uid INTEGER,
    uid_validity TEXT,
    messages_scanned INTEGER NOT NULL DEFAULT 0,
    last_event_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Paired Android phones. Only the SHA-256 of the device token is stored.
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    platform TEXT NOT NULL DEFAULT 'android',
    token_hash TEXT NOT NULL UNIQUE,
    messages_received INTEGER NOT NULL DEFAULT 0,
    last_seen_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
