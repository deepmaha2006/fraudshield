# FraudShield — Secure Deployment Guide

FraudShield is a single Node.js process with a SQLite-compatible (libSQL) database — a local file — or, on platforms without a persistent disk, a hosted PostgreSQL (Supabase) or Turso database (see §10, Render). It is designed for **one instance per database** behind a **TLS-terminating reverse proxy**. Nothing here has been deployed to a production host yet — follow this guide and complete the release checklist (§9) before going live.

## 1. Requirements

- Linux x86-64 host (recommended) or a container runtime. Windows works for development; see §7 for Windows-specific notes.
- Node.js **24 LTS** (≥ 20.17 supported; CI tests 22 and 24).
- A DNS name and TLS certificate (e.g. Let's Encrypt).
- Outbound HTTPS/HTTP to the public internet (the prober fetches untrusted sites), to `imap.gmail.com:993`, your SMTP server, and `data.iana.org` + TLD RDAP servers.
- No build tools: the libSQL driver ships prebuilt binaries.

## 2. Configuration

All settings are environment variables; see `fraudshield-backend/.env.example` (placeholders only). Validate before every start:

```bash
NODE_ENV=production node scripts/check-config.js   # prints variable names, never values
```

In production the server **refuses to start** unless:

| Variable | Requirement |
|---|---|
| `DATA_ENCRYPTION_KEY` | 64 hex chars from a CSPRNG; not a placeholder |
| `PUBLIC_BASE_URL` | `https://` origin users open (used for CSRF origin checks and e-mail links) |
| `TRUST_PROXY` | The proxy address (`loopback`, `10.0.0.5`, `172.18.0.0/16`) — never `true`/`*` |
| `COOKIE_SECURE` | not `false` (sessions use the `__Host-` cookie prefix) |
| `MAIL_TRANSPORT` | `gmail` or `smtp` (`disabled` allowed with a warning; `memory` refused) |

Generate the key: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`.

Keep separate credentials per environment (development, staging, production). Never reuse the development `.env` in production. `JWT_SECRET` and `SESSION_SECRET` are obsolete and can be deleted.

### Secret storage

- **Linux / systemd:** `/etc/fraudshield/fraudshield.env`, owner `root:fraudshield`, mode `0640`, loaded with `EnvironmentFile=`.
- **Containers:** inject via the orchestrator's secret mechanism (Docker/Kubernetes secrets) — never bake into the image (`.dockerignore` excludes `.env*`).
- A managed secret store (Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) is recommended when the platform offers one; FraudShield only needs the values present in its environment at start.

## 3. Option A — Linux + systemd + nginx (reference)

```bash
# 1. service account and directories
sudo useradd --system --home /var/lib/fraudshield --shell /usr/sbin/nologin fraudshield
sudo install -d -o root -g root -m 0755 /opt/fraudshield
sudo install -d -o fraudshield -g fraudshield -m 0700 /var/lib/fraudshield /var/backups/fraudshield
sudo install -d -o root -g fraudshield -m 0750 /etc/fraudshield

# 2. code (root-owned, read-only for the service)
sudo cp -r fraudshield-backend /opt/fraudshield/
cd /opt/fraudshield/fraudshield-backend
sudo npm ci --omit=dev --ignore-scripts

# 3. secrets
sudo cp .env.example /etc/fraudshield/fraudshield.env      # then edit real values
sudo chown root:fraudshield /etc/fraudshield/fraudshield.env && sudo chmod 0640 /etc/fraudshield/fraudshield.env

# 4. service, backups, proxy
sudo cp ../deploy/systemd/*.service ../deploy/systemd/*.timer /etc/systemd/system/
sudo cp ../deploy/nginx/fraudshield.conf /etc/nginx/sites-available/
sudo cp ../deploy/nginx/fraudshield-proxy.conf /etc/nginx/snippets/
sudo ln -s /etc/nginx/sites-available/fraudshield.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo systemctl daemon-reload
sudo systemctl enable --now fraudshield fraudshield-backup.timer
```

The unit runs as `fraudshield` with `NoNewPrivileges`, `ProtectSystem=strict`, an empty capability set, `UMask=0077`, write access only to `/var/lib/fraudshield`, and `ExecStartPre` config validation. The app binds `127.0.0.1:3000`; only nginx is exposed.

Firewall: allow inbound 80/443 only; deny 3000 from outside.

## 4. Option B — container

```bash
cd fraudshield-backend
docker build -t fraudshield:<version> .
docker run -d --name fraudshield --restart unless-stopped \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:3000:3000 \
  -v fraudshield-data:/data \
  --env-file /etc/fraudshield/fraudshield.env \
  -e TRUST_PROXY=<proxy-ip-or-docker-subnet> \
  fraudshield:<version>
```

- Pin the base image by digest before release (instructions at the top of the `Dockerfile`).
- The image runs as `node` (non-root), contains no compilers or npm cache, and stores data only in `/data`.
- Scan the built image (CI uses Trivy; fails on fixable HIGH/CRITICAL).
- Healthcheck: `GET /healthz` (liveness), `GET /readyz` (database reachable).

## 5. HTTPS, headers and proxy trust

- TLS 1.2+ at the proxy; HTTP redirects to HTTPS. HSTS (1 year, includeSubDomains) is emitted by the app in production — enable it only once HTTPS works for all subdomains.
- The proxy must **overwrite** `X-Forwarded-For` (provided snippet does) and set `X-Forwarded-Proto`.
- `TRUST_PROXY` must match the proxy's address; otherwise per-IP rate limits key on the proxy address (too strict) or on spoofable headers (too lax).
- CSP, `nosniff`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer` and `Permissions-Policy` are set by the app.

## 6. Data protection, backups, migrations, rollback

### Files

| Path | Contents | Permissions |
|---|---|---|
| `DB_FILE` (+ `-wal`, `-shm`) | all application data | `0600`, service account (set automatically on POSIX) |
| `UPLOAD_DIR` | verified avatar images | `0700` dir, service account |
| `BACKUP_DIR` | `*.db` + `.sha256` | `0700` dir, service account; ship off-host encrypted |

None of these may be inside `public/`. Retention: detections older than `DETECTION_RETENTION_DAYS` (default 180) and expired sessions/tokens are purged every 6 hours.

### Backup

```bash
node scripts/backup-db.js --dir /var/backups/fraudshield --keep 14
```

Online and consistent (`VACUUM INTO` while the service runs), integrity-checked, SHA-256 sidecar, rotation. The systemd timer runs it nightly. **Copy backups off the host** (encrypted, e.g. `restic`/`age`) — on-host backups do not survive host loss.

### Restore (tested by `tests/backup-restore.test.js`)

```bash
sudo systemctl stop fraudshield
sudo -u fraudshield node scripts/restore-db.js /var/backups/fraudshield/fraudshield-<time>.db --yes
sudo systemctl start fraudshield
```

The script verifies the hash and `PRAGMA integrity_check`, refuses if the database is in use or the backup's schema is newer than the code, and moves the current files aside as `*.pre-restore-<time>` (nothing is deleted). Practise a restore on a staging host at least quarterly and record the result.

### Migrations

Schema changes are append-only steps in `db.js` (`MIGRATIONS`), tracked by `PRAGMA user_version`, each in a transaction, applied automatically at start. Current version: **3**.

Release procedure:
1. `npm run db:backup` (or let the timer's latest backup suffice only if it is from just before the release).
2. Deploy the new code, start; check the `db.ready` log line (`schemaFrom`/`schemaTo`).
3. Smoke test: sign in, run an investigation, check `/readyz`.

### Rollback

- **Code-only release** (no schema change): redeploy the previous version and restart.
- **Release with migrations:** migrations are forward-only. Stop the service, restore the pre-release backup with `restore-db.js`, deploy the previous code version, start. Data written after the backup is lost — announce a maintenance window for schema-changing releases.

## 7. Windows hosting notes

Development runs on Windows; production on Windows is possible but less hardened:
- Run as a dedicated low-privilege local account (e.g. via NSSM or a Windows service wrapper).
- Restrict the data directory: `icacls D:\fraudshield-data /inheritance:r /grant:r "fraudshield:(OI)(CI)M" "Administrators:(OI)(CI)F"`.
- Use IIS/ARR or nginx for Windows as the TLS proxy and set `TRUST_PROXY=loopback`.
- POSIX file modes set by the app are no-ops on Windows; the ACL above replaces them.

## 8. Secret rotation procedures

Rotation is manual and must be authorised by the system owner. Never paste secret values into tickets or chat.

| Secret | Procedure | Side effects |
|---|---|---|
| `EMAIL_APP_PASSWORD` / `SMTP_PASS` | Create a new App Password in the Google account (Security → App passwords) or provider console → update the secret file → `systemctl restart fraudshield` → revoke the old App Password | None |
| User Gmail App Passwords | User revokes in their Google account and reconnects under Integrations | Monitoring pauses until reconnected |
| `DATA_ENCRYPTION_KEY` | Generate a new key → update secret → restart → every user must reconnect Gmail (old ciphertexts become undecryptable; watchers report `auth`/decrypt errors). For a planned rotation, announce it first. | Gmail reconnect required |
| All browser sessions (suspected token theft) | `sqlite3 "$DB_FILE" "UPDATE sessions SET revoked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE revoked_at IS NULL;"` | Everyone signs in again |
| One user's sessions | User: Settings → Active sessions → Sign out; or change password | — |
| Device token | Integrations → Revoke → pair again | Phone stops reporting until re-paired |
| TLS certificate | Standard certbot renewal; private key never leaves the proxy host | — |

## 9. Release checklist

- [ ] CI green on the release commit: tests, ESLint, Semgrep, npm audit, gitleaks, Trivy.
- [ ] `NODE_ENV=production node scripts/check-config.js` passes on the target host.
- [ ] HTTPS works; HTTP redirects; certificate auto-renewal configured.
- [ ] Port 3000 not reachable from outside.
- [ ] Backup timer active; an off-host copy exists; a restore has been rehearsed.
- [ ] Log collection configured (journald / container driver) with retention ≥ 30 days and alerts on `security:true` events (see `INCIDENT_RESPONSE.md` §2).
- [ ] `SECURITY.md` contact address set and monitored.
- [ ] Base image pinned by digest; GitHub Actions pinned by commit SHA.
- [ ] Decide on `ALLOW_REGISTRATION` (closed registration recommended for a private SOC deployment).
- [ ] Android companion built in **release** mode and pointed at the `https://` URL.

## 10. Scaling limits

SQLite + in-process rate limits + in-process Gmail watchers mean **one instance**. If you need more than one instance, first move sessions/rate limits to a shared store (e.g. Redis) and the database to PostgreSQL, and run the Gmail watchers in a single worker.

## 10. Render (free plan)

`render.yaml` at the repository root describes the service: Docker build of `fraudshield-backend/`, free plan, health check `/healthz`.

- **Database:** free Render services have no persistent disk, so `DATABASE_URL` points at Supabase PostgreSQL through the **session pooler** (`aws-0-<region>.pooler.supabase.com:5432`, IPv4 — the direct `db.<ref>.supabase.co` host is IPv6-only). TLS is verified against Supabase's root CA (`certs/supabase-ca.crt`). Tables are created in the `fraudshield` schema (`DATABASE_SCHEMA`), not `public`, and the schema is revoked from the `anon`/`authenticated` roles, so the project's Data API and anon key cannot read application data. Migrations run on start. Backups: Supabase daily backups / `pg_dump --schema=fraudshield` (the `db:backup` script is for local files only). A Turso `libsql://` URL + `DATABASE_AUTH_TOKEN` still works.
- **Proxy:** `TRUST_PROXY=1` — Render's load balancer is the one hop that sets `X-Forwarded-For`.
- **Mail:** Render free services block outbound SMTP (25/465/587), so `MAIL_TRANSPORT=disabled`; alert, verification and password-reset e-mails are not sent. Use a paid instance or an HTTP mail API to enable them.
- **Sleep:** free services stop after 15 minutes without inbound requests and take ~1 minute to wake. While asleep the Gmail IMAP watcher is not running (it resumes from the last processed message on wake) and the first SMS forwarded may time out and be retried by the phone. Free instance hours (750/month) are shared by all free services in the workspace.
- **Secrets:** set `DATA_ENCRYPTION_KEY`, `DATABASE_URL` (contains the database password) in the dashboard (never in `render.yaml`). Do not change `DATA_ENCRYPTION_KEY` after users connect Gmail.
