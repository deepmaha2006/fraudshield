# FraudShield — Threat Model

Method: data-flow decomposition + STRIDE per element, mapped to OWASP Top 10 (2021), OWASP API Security Top 10 (2023) and selected OWASP ASVS 4.0 requirements. Every threat below maps to actual code; theoretical threats with no corresponding behaviour were excluded.

## 1. System overview

```
 Browser (SOC console)                    Android phone                      Gmail (Google)
 public/*.html + js                       android-companion                  imap.gmail.com:993
   │ HTTPS, session cookie + CSRF           │ HTTPS, Device <token>             ▲ IMAP IDLE, App Password
   ▼                                        ▼                                   │
 ┌──────────────────────────── reverse proxy (TLS, nginx) ─────────────────────┐ │
 │ Express app (app.js)                                                        │ │
 │  routes/account.js   routes/soc.js   routes/integrations.js                 │ │
 │  lib/sessions, http (auth, CSRF, limits, validation), logger                │ │
 │  engine/ (lexical, probe, content, rdap)  ── outbound ──► arbitrary public web hosts (UNTRUSTED)
 │  integrations/gmail.js  ───────────────────────────────────────────────────┼─┘
 │  mailer.js ──► SMTP (Gmail / provider)                                      │
 │  tesseract.js OCR (worker thread)                                           │
 │  SQLite (DB_FILE) + UPLOAD_DIR                                              │
 └─────────────────────────────────────────────────────────────────────────────┘
          ──► rdap: data.iana.org + TLD registries (public)
```

## 2. Assets

| Asset | Where | Sensitivity |
|---|---|---|
| Account passwords | `user_credentials.password_hash` (bcrypt 12) | High |
| Session tokens / CSRF tokens | Cookie; `sessions.token_hash` (SHA-256) | High |
| Gmail App Passwords | `gmail_accounts.secret` (AES-256-GCM, key in `DATA_ENCRYPTION_KEY`) | **Critical** — full mailbox access |
| Device tokens | Phone storage; `devices.token_hash` | High |
| `DATA_ENCRYPTION_KEY`, SMTP credentials | Environment / secret file | Critical |
| Detections (e-mail subjects, senders, SMS text previews, URLs) | `detections.report` | High (personal data, third-party PII) |
| Identity verification data (name, DOB, bcrypt of document number) | `identity_verifications` | High |
| Reset / verification tokens | e-mail; `*_resets`/`email_verifications` (SHA-256) | High (short-lived) |
| Availability of analysis, Gmail watcher, alerting | process | Medium |
| Integrity of verdicts | engine | Medium (a wrong "legit" can cause a victim to click) |

## 3. Trust boundaries

1. **Internet → reverse proxy → app.** All browser input untrusted.
2. **Phone → ingest API.** Device token authenticates the phone, not the SMS content; SMS bodies are attacker-controlled.
3. **App → arbitrary web hosts (prober).** Responses (headers, redirects, HTML, certificates, compressed bodies) are fully attacker-controlled; the *direction* of connection must not reach internal networks.
4. **App ↔ Gmail.** Inbound mail is attacker-controlled; the IMAP credential is the most sensitive secret.
5. **App → SMTP.** Outbound mail must only go to verified owners.
6. **App ↔ filesystem.** DB, uploads, backups, secrets.
7. **Operator ↔ host.** Secrets, backups, restore.

## 4. Actors

| Actor | Capabilities | Goal |
|---|---|---|
| Unauthenticated internet user | Any HTTP request, any origin | Account takeover, enumeration, DoS, abuse prober |
| Malicious authenticated user | Valid session, unlimited registrations | Read others' data, SSRF, use server as relay/scanner, DoS |
| Phishing-site operator | Controls pages the prober fetches | Crash/hang the prober, evade detection, fingerprint the server |
| Malicious e-mail / SMS sender | Content processed automatically | ReDoS, parser exploits, alert loops, detection evasion |
| Cross-site attacker | Victim's browser visits attacker page | CSRF, login-CSRF, clickjacking, XSS-based token theft |
| Compromised dependency | Code execution at install or runtime | Secret theft, backdoor |
| Holder of a stolen device token / laptop | Replays credentials | Inject false detections, read pairing info |

## 5. Threat register

Status: **M** = mitigated and tested, **P** = partially mitigated / residual, **A** = accepted.

| ID | STRIDE | Component / entry point | Threat & preconditions | Impact | Mitigation | Test | Status |
|---|---|---|---|---|---|---|---|
| T-01 | S | `/api/login` | Credential stuffing from many IPs against one account | Account takeover | Per-account exponential back-off; per-IP limit; bcrypt 12; generic errors | auth, ratelimit | M |
| T-02 | I | `/api/register`, `/api/login`, `/api/password/forgot` | E-mail enumeration via status codes / timing | Targeting | Identical responses; dummy hash | auth, recovery | M |
| T-03 | S/E | Session handling | Token theft via XSS / logs / URL | Account takeover | HttpOnly SameSite=Strict cookie; no token in URL or storage; revocation; idle timeout | auth, exposure | M |
| T-04 | S | Session handling | Session fixation | Account takeover | Presented session revoked at login, new token issued | auth | M |
| T-05 | T | All state-changing APIs | CSRF / login-CSRF | Unwanted actions, attacker-account login | Origin/Sec-Fetch-Site guard; CSRF token; SameSite=Strict | csrf-and-authz | M |
| T-06 | I/E | `/api/detections/:id`, devices, sessions | BOLA — access another user's objects by id | Data breach | `user_id` in every query; 404 for foreign ids | csrf-and-authz, auth | M |
| T-07 | T | All JSON APIs | Mass assignment / prototype pollution / type confusion | Privilege change, crash | Strict schemas; unknown keys rejected; no object merging | csrf-and-authz | M |
| T-08 | T/I | Search & lists | SQL injection | Data breach | Parameterised queries; LIKE escaping | csrf-and-authz, Semgrep | M |
| T-09 | I | Console rendering | Stored XSS via e-mail subjects, senders, page titles, profile names | Session riding (token theft no longer possible) | `FS.esc` on every interpolation; strict script CSP; `nosniff` | platform (escaping), exposure (CSP) | M |
| T-10 | I/E | Prober (`engine/probe.js`) | SSRF to loopback, metadata, private networks, via IP encodings, redirects or DNS rebinding | Internal access, credential theft (cloud metadata) | Resolve → classify → pin per hop; IPv4/IPv6/mapped/encoded ranges blocked | engine | M |
| T-11 | D/E | Prober | Port scanning / protocol smuggling to third parties | Abuse attribution, legal | Web-port allowlist | engine | M |
| T-12 | D | Prober | Decompression bomb, huge bodies, slow responses, redirect loops | Memory/CPU exhaustion | 1.5 MB raw, 3 MB decoded caps; timeouts; 8 hops; bounded queue | engine | M |
| T-13 | D | Content analysis, Gmail parser | ReDoS in regexes over attacker HTML/mail | Event-loop freeze (service-wide DoS) | Bounded quantifiers, input caps, head-only scanning; measured | engine | M |
| T-14 | D | `/api/analyze/screenshot` | Image/decompression bombs, OCR exhaustion | DoS | Header dimension check, magic bytes, 1 OCR slot, 60 s timeout, per-user limit | ingest-and-uploads | M |
| T-15 | T/I | `/api/user/upload-picture` | Disguised HTML/script upload served from origin | Stored XSS | Magic-byte check; server name/extension; out-of-tree dir; sandbox CSP + nosniff | ingest-and-uploads | M |
| T-16 | I | Mailer | Alerts to unverified addresses (relay/harassment), header injection | Abuse, reputation | E-mail verification gate; nodemailer 10 + CRLF stripping; defanged content | email-verification | M |
| T-17 | S | Password reset | Token guessing/reuse/leak via logs or Referer | Account takeover | 256-bit token, SHA-256 at rest, 30 min, single use, newest-only, fragment delivery, `no-referrer` | recovery | M |
| T-18 | I | Gmail credentials at rest | DB exfiltration exposes mailbox access | Mailbox compromise | AES-256-GCM with pinned tag; key outside DB | platform | P — key in env file, no KMS (R-02) |
| T-19 | S | `/api/ingest/sms` | Forged SMS from stolen device token | False detections / alert spam | Hashed tokens, revocation, per-device + per-IP limits, verified-only alerts | ingest-and-uploads | P — token on phone storage (R-07) |
| T-20 | D | Live stream | Socket exhaustion | DoS | ≤ 10 streams/user; server timeouts | review | M |
| T-21 | R | All | Repudiation / missing audit trail | Undetected abuse | Structured security events with request ids, uid, ip | logging | P — no central log store/alerting configured (R-05) |
| T-22 | I | Logs | Secrets/PII in logs, log forging | Leak | Key-based redaction, control-char stripping, no e-mails in logs | logging, platform | M |
| T-23 | T | SQLite concurrency | Lost or corrupt writes under concurrency | Integrity | Transaction lock, WAL, busy timeout, FKs, integrity check | platform | M |
| T-24 | D/T | Backups | No recovery from corruption or loss | Data loss | Online `VACUUM INTO` backups, SHA-256, integrity check, guarded restore | backup-restore | P — schedule not yet deployed (R-06) |
| T-25 | I | Static serving | DB / `.env` / source exposure | Full compromise | DB & secrets outside `public/`; dotfiles denied; traversal tested | exposure | M |
| T-26 | E | Supply chain | Malicious/vulnerable dependency | RCE, secret theft | 12 prod deps; lifecycle scripts blocked except reviewed `sqlite3`; audit + signatures + SBOM; Dependabot; CI gates | CI | P — CI not yet executed (R-08) |
| T-27 | T | Detection integrity | Cloaking (benign page for non-browser clients), evasion of language heuristics, unvalidated scoring | Missed phishing → victim clicks | Browser-like UA; multi-signal model; partial-evidence labelling | engine | **A/P** — accuracy not validated (R-01) |
| T-28 | I | Prober egress | Server's IP revealed to phishing operators; server visits hostile sites | Targeting, blocklisting | — | — | A (R-03) |
| T-29 | S | Registration | Unlimited sign-ups use the prober as a fetch service | Abuse | Per-user limits; `ALLOW_REGISTRATION=false` option | ratelimit | P (R-10) |

## 6. OWASP mapping (summary)

- **A01 Broken Access Control / API1 BOLA / API5 BFLA:** T-06, T-05; no admin functions exist.
- **A02 Cryptographic Failures:** T-18 (GCM), bcrypt 12, TLS-only cookies in production.
- **A03 Injection:** T-08, T-09, T-16 (headers), T-07.
- **A04 Insecure Design:** T-16 (mail relay), T-11 (prober abuse), T-29.
- **A05 Security Misconfiguration:** fail-closed config, headers, CSP, trust proxy (M-10).
- **A06 Vulnerable Components:** C-01, T-26.
- **A07 Identification & Authentication Failures:** T-01–T-04, T-17.
- **A08 Software & Data Integrity:** SRI on CDN script, lifecycle-script policy, backup hashes.
- **A09 Logging & Monitoring Failures:** T-21, T-22.
- **A10 SSRF / API7:** T-10–T-12.
- **API4 Unrestricted Resource Consumption:** T-12–T-14, T-20, pagination clamp.
- **ASVS** (selected, L2 targets): V2.1.1/2.1.2 (length 8–72 bytes), V2.2.1 (anti-automation), V3.2.1 (new token at login), V3.3.1/3.3.2 (logout & idle timeout), V3.4.1–3.4.3 (cookie attributes), V4.1.3/4.2.1 (least privilege, BOLA), V5.1.3 (allow-list validation), V7.1.1 (no credentials in logs), V12.1.1 (upload size), V12.6.1 (SSRF allow-list), V14.4 (security headers).

## 7. Assumptions

- A TLS-terminating reverse proxy sits in front of the app and is the only peer allowed to set `X-Forwarded-*`.
- One application instance per database (SQLite, in-memory limits).
- The host OS, proxy and secret store are administered securely (outside this repository's control).
- Users are SOC analysts acting on their own data; there is no multi-user tenancy or admin role.
