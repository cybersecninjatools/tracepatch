# TracePatch

A self-hosted pen test finding / POA&M (Plan of Action & Milestones) tracker for security teams.

## What it does

TracePatch centralizes penetration test findings, remediation ownership, and
auditor reporting in one place. It ingests scan/report output from common
tools, tracks findings through their remediation lifecycle, and generates
POA&M reports mapped to NIST SP 800-53.

**Core features:**
- Finding lifecycle tracking (Open → In Progress → Resolved)
- Engagement management (pen tests, vendor assessments)
- Evidence file uploads per finding
- Vulnerability scan ingestion and tracking
- POA&M report generation (PDF/CSV export)
- Role-based access with an access-request workflow
- Activity logging / audit trail

## Why self-hosted

Rather than a hosted multi-tenant SaaS, TracePatch is designed to run entirely
inside your own environment. Your findings — inherently sensitive security
data — never leave your infrastructure. You get vendor-style feature updates
(pull the latest image, `docker compose up -d`) without ever handing your
vulnerability data to a third party.

## Tech stack

- Python / Flask backend
- SQLite storage
- Vanilla JS frontend (no build step)
- Gunicorn + Docker for deployment

## Quick start

See [SETUP.md](./SETUP.md) for full install instructions. Short version:

```bash
git clone https://github.com/cybersecninjatools/tracepatch.git
cd tracepatch
cp .env.example .env
# edit .env — set SECTRACK_SECRET and SECTRACK_ORG_NAME
docker compose up -d
docker compose exec tracepatch python3 app/create_admin.py <username> <password> "<Display Name>"
```

## License

PolyForm Noncommercial 1.0.0 — free to use, modify, and self-host for
noncommercial purposes. See [LICENSE](./LICENSE).
