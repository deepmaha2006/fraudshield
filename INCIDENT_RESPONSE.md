# FraudShield — Incident Response

Practical procedures for the people operating a FraudShield deployment. Replace the placeholders in §1 before release.

## 1. Roles and contacts

| Role | Who | Contact |
|---|---|---|
| Incident commander (system owner) | REPLACE | REPLACE |
| Technical responder | REPLACE | REPLACE |
| Privacy / data-protection contact | REPLACE | REPLACE |

Severity: **SEV-1** active compromise or data exposure · **SEV-2** credible threat, contained · **SEV-3** suspicious activity under investigation.

## 2. Detection — what to watch

The application writes JSON lines to stdout/stderr (journald or the container log driver). Security-relevant lines carry `"security":true`. **No alerting is configured by this repository** — wire these queries into your log platform:

| Signal | Query (field = value) | Suggested alert |
|---|---|---|
| Password guessing | `event=auth.login_failed` | > 50 / 10 min, or `failures ≥ 5` for one `account` |
| Account lockouts | `event=auth.login_throttled` | any burst |
| Forged / stolen sessions | `event=auth.session_rejected` | > 20 / 10 min |
| CSRF attempts | `event=csrf.origin_rejected` or `csrf.token_rejected` | any |
| Rate-limit abuse | `event=ratelimit.triggered` | grouped by `limiter`, `ip` |
| Upload attacks | `event=upload.rejected` | any burst |
| Device token guessing | `event=device.auth_failed` | > 10 / 10 min |
| Account takeover follow-up | `event=auth.password_reset`, `auth.password_changed`, `account.deleted`, `integration.*` | review daily |
| Application faults | `level=error` (`http.error`, `process.*`, `gmail.sync_failed`) | any `process.uncaught_exception` |
| Data volume anomalies | `event=retention.purged` with unexpected counts | manual |

Each HTTP response has an `X-Request-Id`; correlate user reports with the `rid` field.

## 3. First response (all incidents)

1. **Open an incident log** (timestamped notes: who, what, when). Never paste secrets, tokens or user message content into it.
2. **Preserve evidence before changing anything:**
   ```bash
   journalctl -u fraudshield --since "-7 days" -o json > /secure/evidence/fraudshield-logs-$(date -u +%FT%TZ).json
   sudo -u fraudshield node scripts/backup-db.js --dir /secure/evidence --keep 1000
   sha256sum /secure/evidence/* > /secure/evidence/SHA256SUMS
   ```
   Store evidence on a restricted, write-once location.
3. **Contain** using the playbook below. **Eradicate**, **recover**, then hold a **post-incident review** (§6).

## 4. Playbooks

### 4.1 A user's account is compromised
1. Revoke the user's sessions: `UPDATE sessions SET revoked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE user_id=<id> AND revoked_at IS NULL;`
2. Ask the user to reset their password (sign-in page → *Forgot password*); this also revokes sessions.
3. Revoke and re-pair their Android devices; have them revoke and recreate the Gmail App Password in their Google account, then reconnect.
4. Review `auth.*` and `integration.*` events for that `uid` and source `ip`s.

### 4.2 Suspected theft of session cookies at scale (e.g. XSS discovered)
1. Deploy the fix (or take the console offline behind the proxy).
2. Revoke **all** sessions (`SECURE_DEPLOYMENT.md` §8).
3. Inspect `http` logs for unusual sequences of `PATCH /api/detections`, `DELETE /api/integrations/*`, `POST /api/user/change-password`.

### 4.3 Database or host compromise / data breach
1. Isolate the host (keep it running for forensics if possible; snapshot the disk).
2. Treat as exposed: password hashes (bcrypt 12), detection contents (e-mail subjects/senders/SMS previews — third-party personal data), identity data (names, DOBs, bcrypt of document numbers), encrypted Gmail App Passwords.
3. If `DATA_ENCRYPTION_KEY` may also be exposed (same host/env file): **assume all connected Gmail mailboxes are compromised** — notify users to revoke App Passwords immediately, then rotate the key.
4. Rotate SMTP/Gmail sending credentials and the TLS key if the proxy host is affected.
5. Force password resets for all users (revoke sessions; notify).
6. Legal/regulatory notification: personal data is involved (e.g. India DPDP Act 2023, GDPR where applicable). The privacy contact decides on notification within the applicable deadlines.
7. Rebuild the host from a known-good image; restore the last backup taken before the compromise window.

### 4.4 Leaked `DATA_ENCRYPTION_KEY` or Gmail credentials in a file, repository or ticket
1. Do not just delete the file — removal does not invalidate the secret.
2. Rotate per `SECURE_DEPLOYMENT.md` §8. For a leaked user App Password, the user must revoke it in Google.
3. If committed to git: rotate first, then purge history (e.g. `git filter-repo`) and force-push with the team's agreement; check forks and CI caches.

### 4.5 Malicious upload or analyzer abuse
1. `upload.rejected` bursts: identify `uid`/`ip`; revoke the user's sessions; disable registration (`ALLOW_REGISTRATION=false`) if the account is throwaway.
2. Prober abuse (a user submitting many third-party URLs): block the account, check `ratelimit.triggered`, consider closed registration; respond to third-party abuse complaints with timestamps and the offending URLs.

### 4.6 Stolen phone / device token
Integrations → **Revoke** the device. Its token stops working immediately. Check for unexpected `source=sms` detections before revocation.

### 4.7 Service outage / suspected DoS
1. Check `/healthz`, `/readyz`, CPU and memory; look for `process.*` errors and long `ms` in `http` logs.
2. Tighten nginx `limit_req` zones; block offending IPs at the edge.
3. If a specific URL or e-mail reliably hangs the engine, capture it (as evidence, defanged) and file a security report — it indicates a new ReDoS/resource bug.

## 5. Recovery

1. Restore from backup if data integrity is in doubt (`SECURE_DEPLOYMENT.md` §6).
2. Confirm: tests green on the deployed commit, `check-config.js` passes, sign-in works, `/readyz` ready, Gmail watchers reconnect (`gmail.*` logs), devices report.
3. Monitor closely for 72 hours.

## 6. Post-incident review (within 5 business days)

Timeline, root cause, what detected it and how fast, what slowed the response, and concrete actions (each with an owner and due date). Add a regression test for any vulnerability involved and update `SECURITY_AUDIT.md` and `THREAT_MODEL.md`.
