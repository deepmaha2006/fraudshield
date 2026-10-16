# FraudShield — Security Audit

**Scope:** `fraudshield-backend/` (Node.js 24, Express 5, SQLite), the browser console in `fraudshield-backend/public/`, and `android-companion/` (Kotlin, source review only).
**Baseline:** checkpoint `checkpoints/pre-hardening-20261016-1430.tgz` (no git repository existed).
**Date:** 2026-10-16. **Method:** manual code review of every route, middleware, engine module and page script; threat modelling (`THREAT_MODEL.md`); dynamic tests against a local instance; ESLint + eslint-plugin-security; Semgrep OSS 1.181.0; `npm audit`; `npm audit signatures`.

No system can be shown to be free of vulnerabilities. This document lists what was found, what was changed, and how each fix was verified.

## Summary

| Severity | Found | Fixed and verified by test | Accepted / open |
|---|---|---|---|
| Critical | 1 | 1 | 0 |
| High | 10 | 10 | 0 |
| Medium | 15 | 15 | 0 |
| Low | 5 | 4 | 1 (L-05, documented) |
| Informational | 3 | — | 3 (by design, documented) |

Final automated results: **71/71 tests pass**, ESLint 0 problems, Semgrep 0 findings across 9 rule packs, `npm audit` 0 vulnerabilities (was 26). See `PRODUCTION_READINESS_REPORT.md` for exact commands.

## Findings

Severity reflects impact on FraudShield as deployed (a single-tenant-per-user SOC console that fetches untrusted URLs and stores e-mail credentials).

### Critical

**C-01 — Known-vulnerable dependencies, including 2 critical advisories.**
Evidence: baseline `npm audit`: 26 vulnerable packages (2 critical: `proxy-addr` IPv4-mapped-IPv6 trust bypass → IP spoofing that defeats per-IP rate limits; `tar` arbitrary file write via hardlinks; 16 high incl. `multer` DoS, `path-to-regexp` ReDoS, `nodemailer` SMTP command injection, `jws` HMAC verification, `lodash` code injection, `mongoose` injection).
Root cause: 14 declared dependencies were never used (`@react-three/*`, `mongoose`, `axios`, `lodash`, `moment`, `joi`, `langdetect`, `chalk`, `body-parser`, `bcrypt`, `express-session`, `morgan`, `jsonwebtoken`, `cookie-parser`); others were outdated.
Fix: removed all unused packages (production deps 26 → 12); `npm audit fix`; reviewed major upgrades `nodemailer` 6→10 and `sqlite3` 5→6. Lifecycle scripts blocked except the reviewed `sqlite3` native build (`allowScripts` in `package.json`).
Verification: `npm audit` and `npm audit --omit=dev` → 0 vulnerabilities; all tests pass on the upgraded stack; CI fails on high/critical.

### High

**H-01 — Session token readable by any script (localStorage) and never revocable.**
Evidence: `public/js/core.js` stored an 8-hour JWT in `localStorage`; no logout endpoint; password change did not invalidate tokens. Any XSS or malicious extension = full account takeover for 8 h with no way to cut it off.
Fix: opaque 256-bit server-side sessions (`lib/sessions.js`, `sessions` table, SHA-256 at rest), `HttpOnly; SameSite=Strict; Path=/` cookie (`Secure` + `__Host-` prefix in production), absolute (12 h) and idle (120 min) timeouts, logout, list/revoke own sessions, revoke-all on password change/reset/account deletion, session-fixation protection at login. JWT removed entirely.
Tests: `auth.test.js` (cookie flags, forged/oversized/legacy bearer tokens, logout revocation, fixation, expiry, idle timeout, revoke-others, cross-user revoke), `logging.test.js`. Browser-verified: `document.cookie` cannot see the session, `localStorage` is empty.

**H-02 — Session token placed in the URL of the live stream.**
Evidence: `new EventSource('/api/stream?token=…')` — tokens in URLs leak via logs, history and proxies.
Fix: stream authenticates by cookie only; `?token=` ignored. Test: `exposure-and-headers.test.js`.

**H-03 — Cross-site request forgery (introduced risk of cookie sessions; mitigated before release).**
Fix: `originGuard` rejects unsafe `/api` requests whose `Origin` (or `Sec-Fetch-Site`) is not the console's own origin, including login (login-CSRF); per-session CSRF token required in `X-CSRF-Token` on authenticated writes (constant-time compare); `SameSite=Strict`.
Tests: `csrf-and-authz.test.js` (missing/wrong token, foreign Origin, cross-site Sec-Fetch-Site, cross-site login).

**H-04 — ReDoS in page-content analysis: a crafted phishing page freezes the whole server.**
Evidence: `<meta[^>]+property…` and `oncontextmenu\s*=\s*["']?\s*return…` were quadratic on attacker-controlled HTML. Measured before the fix: 200 000 spaces after `oncontextmenu=` → **19.5 s** of blocked event loop (≈ minutes for the 600 KB cap); 20 000 unclosed `<meta` tags → test timed out at 60 s.
Fix: every tag quantifier bounded (`[^>]{0,1500}`), whitespace runs bounded, head-only scanning for `<title>`/`<meta>` (first 100 KB).
Tests: `engine.test.js` ReDoS case (590 000-space input now 3 ms; all three pathological inputs within limits).

**H-05 — ReDoS in e-mail anchor extraction.**
Evidence: `<a…>([\s\S]*?)</a>` unbounded lazy body — quadratic on many unclosed anchors in an inbound e-mail (Gmail watcher processes attacker mail automatically).
Fix: bounded quantifiers, ≤ 500 anchors, input caps (text 50 KB, HTML 500 KB). Test: `engine.test.js`.

**H-06 — Decompression bomb in the URL prober.**
Evidence: `zlib.gunzipSync/brotliDecompressSync` on up to 1.5 MB compressed with no output limit → gigabytes of memory.
Fix: `maxOutputLength` 3 MB; over-limit bodies are discarded. Test: 64 MB gzip and brotli bombs capped (`engine.test.js`).

**H-07 — Prober usable as a port scanner / protocol client against third parties.**
Evidence: any `scheme://public-host:PORT` was connected to (e.g. `:25`, `:6379`).
Fix: web-port allowlist (80, 443, 8000, 8008, 8080, 8443, 8888), enforced after address classification and on every redirect hop and TLS probe. Test: `engine.test.js`.

**H-08 — Alert e-mails could be sent to addresses the user does not own (mail relay / harassment).**
Evidence: registration accepted any address without verification; high-risk alerts were mailed to it; an attacker could register `victim@…` and trigger alerts at 30 analyses/min.
Fix: e-mail ownership verification (single-use 24 h link, token in URL fragment, hashed at rest, resend rate-limited); alerts only to verified addresses. Accounts that existed before migration 3 were grandfathered as verified (one account in the current database) to avoid silently disabling alerts.
Tests: `email-verification.test.js`.

**H-09 — Transaction race on the shared SQLite connection.**
Evidence: `db.tx()` issued `BEGIN … COMMIT` on the single connection used by all requests; a concurrent request's statements executed inside another request's transaction and were rolled back with it; two concurrent transactions failed with "cannot start a transaction within a transaction".
Fix: `AsyncLocalStorage`-scoped transaction lock; non-transaction statements wait for open transactions; nested calls join.
Tests: `platform.test.js` (rollback does not swallow concurrent writes; 20 concurrent transactions all succeed).

**H-10 — Screenshot OCR resource exhaustion.**
Evidence: unlimited concurrent Tesseract workers, no time limit, no image-dimension check (a 60 000 × 60 000 PNG header under 6 MB), language data downloaded from a CDN at runtime.
Fix: header-level dimension check (≤ 40 MP) before decoding, magic-byte verification, single OCR slot with a queue of 3 (503 beyond), 60 s hard timeout with worker termination, bundled language data only (`cacheMethod: readOnly`), 10 screenshots / 10 min / user.
Tests: `ingest-and-uploads.test.js` (bomb dimensions → 413, non-image → 415).

### Medium

| ID | Finding | Fix | Test |
|---|---|---|---|
| M-01 | Upload type trusted from client `Content-Type` (polyglot / disguised content) | Magic-byte sniffing, server-chosen name + extension from content, uploads moved out of `public/` to `UPLOAD_DIR`, served with `nosniff` + sandbox CSP | `ingest-and-uploads.test.js` |
| M-02 | Account enumeration: registration returned 409; login skipped bcrypt for unknown e-mails (timing) | Identical responses; dummy-hash comparison | `auth.test.js` |
| M-03 | No per-account brute-force protection | Exponential back-off after 5 failures per account (independent of IP), per-IP limits, security events | `auth.test.js`, `ratelimit.test.js` |
| M-04 | No password recovery, no way to revoke sessions after compromise, no account deletion | Single-use 30-min reset tokens (hashed, fragment-delivered, newest-only), revoke-all on reset, session list/revoke, password-confirmed deletion with cascade | `recovery.test.js`, `auth.test.js` |
| M-05 | AES-GCM decryption accepted truncated tags (Semgrep `gcm-no-tag-length`) | `authTagLength: 16`, IV/tag length checks | `platform.test.js` regression |
| M-06 | Password policy: 6-char minimum (8 in v2), silent bcrypt 72-byte truncation, cost 10 | ≥ 8 chars, ≤ 72 bytes rejected (not truncated), cost 12 with upgrade-on-login | `auth.test.js` |
| M-07 | Negative `LIMIT` returned unbounded result sets | Clamped 1–200 | `csrf-and-authz.test.js` |
| M-08 | No strict input validation (unknown fields accepted, `String(object)` coercion) | Strict per-route schemas (`lib/http.js validate`); unknown keys and wrong types rejected; ingest accepts scalars only | `csrf-and-authz.test.js`, `ingest-and-uploads.test.js` |
| M-09 | Logging: raw `console` output incl. user e-mail addresses; morgan log-forging advisory; no request ids or security events | Structured JSON logs, key-based redaction, control-character stripping, request ids, `security:true` events for auth/CSRF/rate-limit/upload/integration actions | `logging.test.js`, `platform.test.js` |
| M-10 | Production misconfiguration not detected (HTTP binding on all interfaces, proxy trust hard-coded, HSTS on HTTP, no secret validation) | `lib/config.js` fails closed in production (HTTPS public URL, secure cookies, explicit `TRUST_PROXY`, real key, real mail transport), loopback bind by default, `scripts/check-config.js` | `platform.test.js`, CI job |
| M-11 | Unbounded analysis queue (memory/sockets) | 6 concurrent probes, ≤ 40 queued, 503 beyond | code review |
| M-12 | Unbounded live-stream connections per user | ≤ 10 per user (oldest closed) | code review |
| M-13 | No HTTP server timeouts (slow-client exhaustion) | `headersTimeout` 20 s, `requestTimeout` 120 s, `keepAliveTimeout` 5 s, header count cap | code review |
| M-14 | Duplicate copy of live secrets on disk (`backup-v1/.env`: Gmail App Password, JWT and session secrets) | Copy deleted; `.gitignore`, `.dockerignore`, `.env.example`, gitleaks config added | file check |
| M-15 | Android companion permitted cleartext HTTP in release builds | Release: HTTPS-only network security config + URL check; cleartext only in debug source set | source review (not compiled) |

### Low

| ID | Finding | Status |
|---|---|---|
| L-01 | Pairing endpoint advertised internal LAN addresses | Production returns only `PUBLIC_BASE_URL` |
| L-02 | Ingest stored an unvalidated client timestamp | Parsed and normalised or null |
| L-03 | JSON parser errors echoed parser internals | Generic `Malformed JSON.` with request id |
| L-04 | "Weekly summary" preference implied a feature that does not exist | UI now states delivery is not implemented |
| L-05 | In-memory rate limits and login throttle reset on restart and do not span multiple instances | **Accepted** for single-instance deployment; see residual risk R-04 |

### Informational (by design)

- **I-01** — The prober sets `rejectUnauthorized: false` (`engine/probe.js`). Certificate validity of an untrusted site is the evidence being measured; nothing secret is sent on those sockets. Suppressed in Semgrep with justification.
- **I-02** — CSP allows `style-src 'unsafe-inline'` because the console sets computed widths/colours via style attributes. Scripts are restricted to `'self'` and cdnjs (Chart.js with SRI); no inline scripts exist.
- **I-03** — Reviewed static-analysis false positives (non-literal `fs` paths built from server-controlled values, constant-key `RegExp`s, deliberate control-character regexes, measured-linear regexes) carry inline `eslint-disable`/`nosemgrep` comments stating the reason. New occurrences still fail CI.

## Verified non-issues

- **SQL injection:** every query is parameterised; the only dynamic SQL fragment is a fixed `WHERE` built from allow-listed column names. Injection strings in search are inert (`csrf-and-authz.test.js`). Semgrep `p/sql-injection`: 0.
- **Command injection / eval:** no shell execution or dynamic code evaluation in application code. Semgrep `p/command-injection`: 0.
- **Object-level authorisation:** every detection/device/session query is scoped by `user_id` in SQL; foreign ids return 404 indistinguishable from missing (`csrf-and-authz.test.js`).
- **Administrative functions:** none exist — there is no admin role or endpoint to protect. Identity-verification records are created but no review workflow exists (see residual risk R-09).
- **Static file exposure:** database, `.env`, source, `node_modules`, `.git` and traversal variants are not served (`exposure-and-headers.test.js`, raw request lines).
- **SSRF:** loopback, RFC1918, link-local/metadata, CGNAT, multicast, IPv6 ULA/link-local, IPv4-mapped IPv6 and decimal/hex IP encodings are refused before connecting; DNS answers are pinned per hop (no rebinding window). `engine.test.js`.

## Residual risks

See `PRODUCTION_READINESS_REPORT.md` → *Residual risks* for the owner/expiry table.
