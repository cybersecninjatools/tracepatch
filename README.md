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
- Built-in Updates page — compares your running build's commit against the
  latest commit on GitHub's `main` branch and shows you the `git pull` /
  rebuild command when you're behind (no automatic patching, no OS-level
  changes — just a commit checker)

## Why self-hosted

Rather than a hosted multi-tenant SaaS, TracePatch is designed to run entirely
inside your own environment. Your findings — inherently sensitive security
data — never leave your infrastructure. You get vendor-style feature updates
(`git pull && ./build.sh`) without ever handing your vulnerability data to a
third party.

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
./build.sh
docker compose exec tracepatch python3 app/create_admin.py <username> <password> "<Display Name>"
```

`build.sh` bakes the current git commit and build date into the image (used
by the Updates page) and is the correct way to build and rebuild — prefer it
over calling `docker compose build`/`docker build` directly.

## Demo data

TracePatch ships with optional seed scripts under `demo/` that populate a
synthetic dataset, used for the public demo instance. A fresh self-hosted
install never runs these, so a normal install has no demo data and nothing to
configure here.

If you do seed demo data, seeded records are flagged internally and:
- can't be deleted directly (you'll be told to toggle demo data off in
  Settings instead)
- disappear automatically the moment any real (non-demo) finding is created —
  no manual cleanup step needed

See [SETUP.md](./SETUP.md#demo-data-optional) for details.

## Changelog

The in-app Changelog page reads `CHANGELOG.json` from the repo root, baked
into the image at build time. See
[SETUP.md](./SETUP.md#updating-the-changelog) if you're maintaining a fork
and want to add your own entries.

## License

PolyForm Noncommercial 1.0.0 — free to use, modify, and self-host for
noncommercial purposes. See [LICENSE](./LICENSE).
