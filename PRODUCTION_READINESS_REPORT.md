# FraudShield — Production Readiness Report

**Date:** 2026-10-16 · **Assessed revision:** working tree of `E:\FraudShied Project` (no git repository) · **Baseline checkpoint:** `checkpoints/pre-hardening-20261016-1430.tgz`

## Release decision: **NOT READY**

The application code has been hardened and passes every check that could be executed locally (71/71 tests, 0 lint problems, 0 Semgrep findings, 0 known-vulnerable dependencies). It is **not** ready for production release because the gates that depend on the target environment and on review cannot be satisfied from this workstation: no production host exists to review, the CI pipeline has never run, the container image has never been built or scanned, secret scanning with gitleaks has not been executed, and no human has reviewed the changes. The application must not be declared production-ready until the blockers in §5 are closed.

## 1. Release gates

| Gate | Status | Evidence |
|---|---|---|
| No confirmed exploitable critical vulnerabilities | **PASS** | C-01 fixed; `npm audit` 0; tests |
| No unacceptable high-severity vulnerabilities | **PASS** | H-01–H-10 fixed with regression tests |
| No real secrets in distributable artefacts | **PASS (local)** | duplicate `backup-v1/.env` deleted; `.gitignore`/`.dockerignore` exclude secrets; no VCS history exists. gitleaks **not executed** |
| No authentication bypass / broken authorisation | **PASS** | `auth.test.js`, `csrf-and-authz.test.js` |
| No unrestricted access to private data or files | **PASS** | `exposure-and-headers.test.js`, BOLA tests |
| No SQL / command injection | **PASS** | parameterised SQL; Semgrep `sql-injection`, `command-injection` 0 |
| No exploitable SSRF | **PASS** | `engine.test.js` (loopback, metadata, encodings, ports, bombs) |
| No unprotected administrative operations | **PASS (N/A)** | no admin functions exist |
| Production security configuration present | **NOT MET** | enforced by `lib/config.js`, but no production environment has been configured or reviewed |
| Mandatory security tests pass | **PASS** | 71/71 |
| Backup / migration procedures verified | **PARTIAL** | backup + restore + tamper detection + 0→3 migration verified locally; schedule, off-host copies and a staging restore drill not yet done |
| Changes reviewed | **NOT MET** | no human code review; no pull request; CI never executed |
| Target deployment environment reviewed | **NOT MET** | none provided |

## 2. Checks executed (all on 2026-10-16, Windows 11, Node 24.16.0, npm 12.0.2)

| # | Command | Result |
|---|---|---|
| 1 | `npm audit` (baseline, before changes) | 26 vulnerable: 2 critical, 16 high, 6 moderate, 2 low |
| 2 | `npm audit` / `npm audit --omit=dev` (final) | **found 0 vulnerabilities** |
| 3 | `npm audit signatures` | registry signatures verified; 40 packages with attestations |
| 4 | `npm test` → `node --test --test-concurrency=1 "tests/*.test.js"` | **71 tests, 71 pass, 0 fail, 0 skipped** (≈ 42 s) |
| 5 | `npx eslint . --max-warnings=0` (with `eslint-plugin-security`) | **0 problems** (35 initially; 1 real issue class fixed, the rest reviewed and annotated) |
| 6 | Semgrep 1.181.0 `p/javascript`, `p/nodejsscan`, `p/owasp-top-ten`, `p/secrets`, `p/xss`, `p/sql-injection`, `p/command-injection`, `p/insecure-transport`, `p/jwt` | **0 findings** each (initially 3 + 9: GCM tag length and a ReDoS fixed; TLS-bypass and measured-linear regexes annotated) |
| 7 | `npm sbom --sbom-format cyclonedx --omit=dev` | CycloneDX 1.5, 192 components |
| 8 | Migration of a **copy** of the real database, schema 0 → 3 | success; `integrity_check` ok; 0 FK violations; original file untouched |
| 9 | Browser end-to-end on a copy of the real DB (mail disabled) | register → login → dashboard → live analysis (CSRF path) → live stream → sessions page → logout → 401: all OK; session cookie invisible to `document.cookie`; `localStorage` empty; no console/CSP errors; no secrets/e-mail addresses in logs |
| 10 | Adversarial benchmarks | 590 000-space ReDoS input 3 ms (was 19.5 s at 200 000); 64 MB gzip/brotli bombs capped at 3 MB |

### Test inventory (`fraudshield-backend/tests/`)

| File | Tests | Covers |
|---|---|---|
| `auth.test.js` | 13 | enumeration, cookie flags, forged/legacy tokens, logout revocation, fixation, expiry, idle, password policy, per-account throttle, revoke-others, cross-user revoke, hash upgrade, account deletion |
| `csrf-and-authz.test.js` | 10 | CSRF token, Origin/Sec-Fetch-Site, login-CSRF, BOLA (detections, devices), mass assignment, `__proto__`, type confusion, negative LIMIT, SQLi, stored-XSS data path |
| `recovery.test.js` | 5 | generic forgot response, single-use reset, session revocation, expired/forged/superseded tokens, hashed storage, per-address rate limit |
| `email-verification.test.js` | 4 | verification link, no relay to unverified addresses, resend limit, expiry |
| `ingest-and-uploads.test.js` | 8 | device auth, hashed/revocable tokens, scalar-only payloads, CORS scope, MIME spoofing, decompression-bomb images, body limit |
| `exposure-and-headers.test.js` | 5 | DB/.env/source/traversal not served (raw request lines), CSP and headers, generic errors, health endpoints, stream auth |
| `engine.test.js` | 10 | SSRF classification, blocked targets without connecting, port allow-list, decompression bombs, ReDoS, scheme rejection, lexical/content detection, scoring floor, offline message analysis |
| `platform.test.js` | 10 | migrations, transaction isolation, concurrent transactions, cascades, retention, GCM tamper + truncated tag, log redaction/forging, production config fail-closed, frontend escaping |
| `ratelimit.test.js` | 2 | per-IP auth and support limits at production scale |
| `logging.test.js` | 1 | access + security events emitted, no secrets/e-mails in logs |
| `backup-restore.test.js` | 3 | consistent backup, in-use refusal, restore, tamper refusal, confirmation |

## 3. Not executed / could not be verified

| Item | Reason | Required action |
|---|---|---|
| GitHub Actions CI (`.github/workflows/ci.yml`, `codeql.yml`) | not a git repository; never pushed | create the repository, push, confirm all jobs green |
| gitleaks secret scan | tool not installed locally | runs in CI; also run once locally before the first push |
| Docker build, non-root check, Trivy scan | Docker not installed | runs in CI `container` job |
| CodeQL | requires GitHub | runs in CI |
| Semgrep `p/express` | pack does not exist in the registry (HTTP 404) | none — Express rules are in `p/javascript` |
| nginx / systemd configuration | no Linux host available | `nginx -t`, `systemd-analyze security fraudshield` on the target |
| Android companion | no Android SDK; source reviewed only, never compiled | build debug + release in Android Studio; test on a device |
| Gmail IMAP watcher against a real mailbox (after hardening) | would use the owner's real credentials; not authorised for this run | test with a dedicated test mailbox |
| Real e-mail delivery (alerts, reset, verification) | real sends not authorised; tests use the in-memory transport | send to a test inbox in staging |
| Load / soak testing, DoS resilience at the edge | out of scope for a local, non-destructive assessment | staging load test with the nginx limits enabled |
| External penetration test | not performed | recommended before handling third-party data at scale |
| Detection accuracy (precision/recall) | no labelled dataset available | see R-01 |

## 4. Secrets requiring action (type and location only)

| Secret | Location | Action |
|---|---|---|
| Gmail App Password used for sending alerts (`EMAIL_APP_PASSWORD`) | `fraudshield-backend/.env` (development) | **Rotate before production (precautionary):** a duplicate of this file existed in `backup-v1/.env` until this assessment (now deleted). No evidence of external exposure was found. Use a separate sending account for production. |
| `JWT_SECRET`, `SESSION_SECRET` | `fraudshield-backend/.env` | No longer used — delete both lines. |
| `DATA_ENCRYPTION_KEY` (development) | `fraudshield-backend/.env` | Do not reuse in production; generate a new key for each environment. |

No secrets were printed, copied into reports, or committed anywhere during this work.

## 5. Blockers before release (priority order)

1. **Create the git repository, push, and get CI fully green** (tests, ESLint, Semgrep, audit, gitleaks, Docker build, Trivy, CodeQL). Pin all GitHub Actions to commit SHAs and the base image to a digest.
2. **Human code review** of all changes in this assessment (see §7), ideally by someone other than the author.
3. **Provision and review the production environment:** TLS proxy, `PUBLIC_BASE_URL`, `TRUST_PROXY`, firewall (3000 closed), secrets in a root-owned file or secret manager, `check-config.js` passing, `systemd-analyze security` / container runtime flags as documented.
4. **Rotate the sending App Password** and remove obsolete secrets (§4).
5. **Backups:** enable the timer, configure encrypted off-host copies, rehearse a restore on staging.
6. **Logging & alerting:** ship logs to a store with ≥ 30-day retention and create the alerts in `INCIDENT_RESPONSE.md` §2.
7. **Fill in contacts** in `SECURITY.md` and `INCIDENT_RESPONSE.md`.
8. **Build and test the Android companion** in release mode against the HTTPS URL.
9. Decide on **registration policy** (`ALLOW_REGISTRATION=false` recommended for a private SOC).

## 6. Residual risks

Owner for all items: **system owner** (to be named). Review: before release, then quarterly.

| ID | Risk | Compensating controls | Plan / expiry |
|---|---|---|---|
| R-01 | Detection accuracy is unvalidated; phishing sites can cloak (serve benign content to the prober) and language heuristics can be evaded. A false "legit" may lead a user to click. | Multi-signal model; critical-signal floor; partial-evidence verdicts labelled; UI warns never to open links | Build a labelled evaluation set (e.g. PhishTank/OpenPhish + Tranco top sites) and measure precision/recall before relying on verdicts; by first production release |
| R-02 | `DATA_ENCRYPTION_KEY` lives in an env file on the same host as the database; host compromise exposes connected Gmail mailboxes. Gmail App Passwords grant full mailbox access. | AES-256-GCM, file permissions, systemd sandbox | Move the key to a KMS / secret manager; migrate the Gmail connector to OAuth 2.0 with read-only scope (`gmail.readonly`); within 90 days of release |
| R-03 | The prober visits hostile sites from the server's IP (fingerprinting, exploitation of HTTP/TLS/zlib parsing bugs in Node). | Caps, timeouts, SSRF guard, port allow-list, non-root sandboxed process | Route prober egress through an isolated egress proxy/VM with its own IP; keep Node patched |
| R-04 | Rate limits and login throttling are in-memory: reset on restart, per-instance only. | Edge `limit_req` in nginx; single-instance deployment | Move to Redis if scaling beyond one instance |
| R-05 | No central logging/alerting is configured by the repository. | Structured security events exist | Blocker 6 |
| R-06 | Backups are on-host until the operator configures off-host copies. | Integrity-checked, hashed backups; tested restore | Blocker 5 |
| R-07 | Device tokens are stored in plain SharedPreferences on the phone. | Revocable, hashed server-side, per-device limits, `allowBackup=false` | Use Android Keystore-backed storage in the companion |
| R-08 | CI/supply-chain controls are defined but not yet proven in operation. | Lockfile, script allow-list, audit clean | Blocker 1 |
| R-09 | Identity verification collects name/DOB/document hash but no review workflow or admin role exists; support tickets have no handling UI. | Data minimised (document number hashed); retention via account deletion | Either implement a reviewed admin workflow (with RBAC, audit log, MFA) or remove the feature |
| R-10 | Open registration lets anyone use the prober within per-user limits. | Per-user/IP limits; e-mail verification gates alerts | Close registration for private deployments; add CAPTCHA or invite codes if public |
| R-11 | Pre-migration accounts were grandfathered as e-mail-verified. | Only one existing account | Optionally require re-verification for legacy accounts |
| R-12 | No multi-factor authentication. | Strong session controls, throttling | Add TOTP/WebAuthn for analyst accounts |

## 7. Files created or modified

**Backend — new:** `app.js`, `lib/config.js`, `lib/logger.js`, `lib/sessions.js`, `lib/images.js`, `lib/schema.js`, `scripts/backup-db.js`, `scripts/restore-db.js`, `scripts/check-config.js`, `eslint.config.js`, `Dockerfile`, `.dockerignore`, `.env.example`, `public/reset-password.html`, `public/js/reset-password.js`, `public/verify-email.html`, `public/js/verify-email.js`, `tests/*.test.js` (11 files) + `tests/helpers.js`.
**Backend — modified:** `server.js`, `db.js`, `mailer.js`, `lib/http.js`, `lib/secrets.js`, `lib/realtime.js`, `lib/detections.js`, `routes/account.js`, `routes/soc.js`, `routes/integrations.js`, `integrations/gmail.js`, `engine/index.js`, `engine/probe.js`, `engine/content.js`, `public/js/core.js`, `public/js/landing.js`, `public/js/profile.js`, page scripts (async session init), `public/index.html`, `public/profile.html`, `package.json`, `package-lock.json`.
**Android — modified/new:** `app/build.gradle.kts`, `Api.kt`, `MainActivity.kt`, `src/main/res/xml/network_security_config.xml`, `src/debug/res/xml/network_security_config.xml`.
**Repository — new:** `.gitignore`, `.gitleaks.toml`, `.github/workflows/ci.yml`, `.github/workflows/codeql.yml`, `.github/dependabot.yml`, `deploy/nginx/*`, `deploy/systemd/*`, `SECURITY_AUDIT.md`, `THREAT_MODEL.md`, `SECURITY.md`, `SECURE_DEPLOYMENT.md`, `INCIDENT_RESPONSE.md`, `DEPENDENCIES.md`, `PRODUCTION_READINESS_REPORT.md`, `checkpoints/pre-hardening-*.tgz`.
**Deleted:** `backup-v1/.env` (duplicate of live secrets); test-generated files in `public/uploads/avatars/`.

## 8. API / behaviour changes for users and integrators

- Browser sessions are cookies; the `Authorization: Bearer` JWT API is gone. Existing signed-in users must sign in again once.
- Writes require `X-CSRF-Token` (the console handles this). Third-party scripts calling console APIs must not exist; device ingest is unchanged (`Authorization: Device <token>`).
- Passwords: 8 characters to 72 bytes. Legacy hashes upgrade automatically on sign-in.
- New accounts must confirm their e-mail before alert e-mails are delivered.
- New endpoints: `/api/session`, `/api/logout`, `/api/password/forgot`, `/api/password/reset`, `/api/email/verify`, `/api/user/resend-verification`, `/api/user/sessions`, `DELETE /api/user/account`, `/healthz`, `/readyz`.
- Avatars are stored under `UPLOAD_DIR` (default `fraudshield-backend/data/uploads`) instead of `public/uploads`.
