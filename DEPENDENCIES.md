# FraudShield — Dependency & SBOM Report

Generated 2026-10-16 from `fraudshield-backend/package-lock.json` (npm 12.0.2, Node 24.16.0).

## Production dependencies (12 direct, 192 components in the SBOM)

| Package | Version | Purpose | Install script |
|---|---|---|---|
| express | 5.1.0 | HTTP framework | — |
| helmet | 8.1.0 | Security headers / CSP | — |
| cors | 2.8.5 | CORS for the device-ingest endpoint only | — |
| dotenv | 17.2.2 | `.env` loading (development) | — |
| bcryptjs | 3.0.2 | Password / document-number hashing (pure JS) | — |
| sqlite3 | 6.0.1 | Database driver (native) | **allowed** (reviewed: builds the native addon) |
| multer | 2.4.0 | Multipart uploads | — |
| nodemailer | 10.1.1 | Outbound e-mail | — |
| imapflow | 2.5.0 | Gmail IMAP IDLE client | — |
| mailparser | 3.9.39 | Parsing inbound e-mail | — |
| tesseract.js | 5.1.1 | OCR (WASM) | **denied** (postinstall only prints a donation message) |
| tldts | 7.4.18 | Public-suffix parsing | — |

Development only: `eslint` 9.39.1, `@eslint/js` 9.39.1, `eslint-plugin-security` 3.0.1, `globals` 15.15.0. Not installed in production images (`npm ci --omit=dev`).

## Changes made during hardening

- **Removed (unused, several vulnerable):** `@react-three/drei`, `@react-three/fiber`, `mongoose`, `axios`, `lodash`, `moment`, `joi`, `langdetect`, `chalk`, `body-parser`, `bcrypt`, `express-session`, `morgan`, `jsonwebtoken`, `cookie-parser`.
- **Upgraded (major, reviewed + covered by tests):** `nodemailer` 6.10.1 → 10.1.1 (SMTP command injection / unintended-domain advisories), `sqlite3` 5.1.7 → 6.0.1 (vulnerable `tar`/`node-gyp` build chain).
- **Upgraded via `npm audit fix` (in-range):** transitive `path-to-regexp`, `qs`, `body-parser`, `proxy-addr`, `multer`, `brace-expansion`, `minimatch`, `form-data`, `follow-redirects`, `http-cache-semantics`, and others.

## Audit results

| Check | Baseline | Final |
|---|---|---|
| `npm audit` (all) | 26 vulnerable packages: 2 critical, 16 high, 6 moderate, 2 low | **0** |
| `npm audit --omit=dev` | (included above) | **0** |
| `npm audit signatures` | not run | registry signatures verified; 40 packages carry provenance attestations |

A clean audit only means no *known* advisories at the time of the run; it says nothing about the application's own code.

## Supply-chain controls

- Lifecycle scripts are blocked by default (npm 12) and allow-listed per package in `package.json` → `allowScripts`. CI and the Dockerfile use `npm ci --ignore-scripts` + `npm rebuild sqlite3`.
- Lockfile committed; installs use `npm ci`.
- Browser CDN script (Chart.js 4.4.1) loaded with Subresource Integrity (`sha384-…`); fonts from Google Fonts (CSS only; scripts are not loaded from there).
- Dependabot (`.github/dependabot.yml`): weekly npm, Docker and GitHub Actions updates; semver-major updates are excluded from automation and need human review.
- CI: `npm audit --omit=dev --audit-level=high` blocks; `npm audit signatures`; CycloneDX SBOM uploaded as a build artefact.

## SBOM

`fraudshield-backend/sbom.cdx.json` — CycloneDX 1.5, production dependencies only, regenerated with `npm run sbom`. It is a build artefact (git-ignored); CI produces a fresh one per run.

Licences in the production tree: MIT (152), ISC (14), BSD-2/3-Clause (12), Apache-2.0 (7), BlueOak-1.0.0 (5), and dual-licensed MIT variants (4). No copyleft licences.
