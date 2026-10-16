# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public issue.

- E-mail: **security@REPLACE-WITH-YOUR-DOMAIN** (the project owner must set a monitored address before release)
- Include: affected component/endpoint, steps to reproduce, impact, and whether you have shared the details with anyone else.
- Do not include real user data, real credentials or tokens in the report.

We aim to acknowledge reports within **3 business days**, provide an initial assessment within **10 business days**, and agree a disclosure date with you (default: 90 days or on release of a fix, whichever is sooner). Reporters acting in good faith under this policy will not face legal action from the project.

## Scope

In scope: `fraudshield-backend/` (API, console, detection engine, Gmail watcher, mailer), `android-companion/`, and the deployment artefacts in `deploy/` and `fraudshield-backend/Dockerfile`.

Out of scope: third-party services (Gmail, registries, CDNs), findings that require a compromised host or physical device access, volumetric denial of service, social engineering, and verdict disagreements on individual URLs (send those as normal bug reports — they are accuracy issues, not vulnerabilities).

## Testing rules

- Test only against your own local instance (`npm start`) or an environment you are authorised to test.
- Never submit URLs to the analyzer that target systems you do not own in order to attack them; the prober will fetch them.
- No automated scanning of production deployments without written permission.

## Supported versions

Only the latest release on the default branch receives security fixes.

## Security documentation

- `SECURITY_AUDIT.md` — findings, fixes, verification
- `THREAT_MODEL.md` — assets, trust boundaries, threat register
- `SECURE_DEPLOYMENT.md` — hardening, configuration, backups, rotation
- `INCIDENT_RESPONSE.md` — what to do when something goes wrong
- `PRODUCTION_READINESS_REPORT.md` — release decision and evidence
