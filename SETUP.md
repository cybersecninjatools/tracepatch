# TracePatch — Setup Guide

TracePatch is a self-hosted pen test finding / POA&M tracker. This guide gets you
from a fresh clone to a running instance in a few minutes.

## Requirements

- Docker and Docker Compose installed
- Port 8080 available (or edit `docker-compose.yml` to use a different port)

## 1. Clone the repository

```bash
git clone <your-repo-url>
cd tracepatch
```

## 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and set:
- `SECTRACK_SECRET` — a random secret string. Generate one with:
```bash
  openssl rand -hex 32
```
- `SECTRACK_ORG_NAME` — your organization's display name (shown throughout the UI)

The app will refuse to start if `SECTRACK_SECRET` is not set — this is intentional,
to prevent accidentally running with a known/default secret.

## 3. Start the application

```bash
./build.sh
```

This is the correct way to build and (re)start TracePatch — use it instead of
calling `docker compose build`/`docker build` directly. It bakes the current
git commit hash and build date into the image (`GIT_COMMIT`/`BUILD_DATE` build
args), which is what powers the "Current commit" display and update check on
the in-app Updates page; a raw `docker compose build` skips that and leaves
the version as `unknown`. `build.sh` also creates persistent storage volumes,
initializes an empty database automatically (via `init_db.py` on container
start), and starts the app. Your data (findings, uploads, users) persists
across restarts and updates via Docker named volumes.

## 4. Create your first admin account

```bash
docker compose exec tracepatch python3 app/create_admin.py <username> <password> "<Display Name>"
```

Password must be at least 8 characters. This creates a `master_admin` role account.

## 5. Log in

Open `http://localhost:8080/login` (or your server's address) and log in with the
account you just created.

## Updating to a new version

The **Updates** page in the app (admin only) compares your running build's
commit against the latest commit on GitHub's `main` branch and tells you
whether you're behind — it's a commit checker, not an auto-updater; it never
patches anything for you. When it shows an update is available:

```bash
git pull
./build.sh
```

Don't use `docker compose build` / `docker build` directly — `build.sh` is
what bakes the commit hash and build date into the image so the Updates page
reports accurate version info afterward. Your data is untouched either way —
it lives in Docker volumes, not in the container itself.

## Demo data (optional)

TracePatch ships with seed scripts under `demo/` that populate a synthetic
dataset (findings, vulnerability scans, users, etc.) for demoing or evaluating
the app. Running `docker compose up -d` / `./build.sh` on a fresh clone does
**not** run these — a normal install starts with an empty database and never
sees demo data or the settings below. Skip this section unless you've
intentionally run one of the `demo/seed_*.py` scripts.

If demo data is present:
- Seeded records are flagged internally (`is_demo=1`) and are protected from
  deletion — attempting to delete one returns an error telling you to turn
  off the **"Show demo data"** toggle in Settings instead of deleting it.
- The moment any real (non-demo) finding is created, demo data is
  automatically hidden — the "Show demo data" setting flips itself off, no
  manual step required. This means once you start entering real findings,
  the demo dataset gets out of your way on its own; you don't need to
  remember to clean it up.
- Demo data is hidden, not deleted, so toggling "Show demo data" back on in
  Settings brings it back at any time.

## Updating the changelog

The in-app **Changelog** page reads `CHANGELOG.json` from the repo root,
which is baked into the image at build time (`Dockerfile` copies it to
`/opt/sectrack/CHANGELOG.json`). It's not required reading for running your
own instance, but if you're maintaining a fork and want your own changes to
show up there, add an entry with:

```bash
python3 tools/add_changelog_entry.py --type add --text "Describe the user-facing change"
```

- `--type` is one of `add`, `fix`, or `remove`
- `--commit`/`--date` default to the current `HEAD`'s short hash and commit
  date if omitted
- Commit the resulting `CHANGELOG.json` change along with your other changes
  before rebuilding

## Troubleshooting

- **App won't start / crashes immediately**: check `docker compose logs` — the most
  common cause is a missing `SECTRACK_SECRET` in `.env`.
- **Can't reach the app in a browser**: confirm port 8080 isn't blocked by a firewall
  or security group, and that `docker compose ps` shows the container as running.
- **Lost admin access**: run `create_admin.py` again with a new username to create
  a second admin account.
