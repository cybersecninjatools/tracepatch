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
docker compose up -d
```

This builds the image, creates persistent storage volumes, initializes an empty
database automatically, and starts the app. Your data (findings, uploads, users)
persists across restarts and updates via Docker named volumes.

## 4. Create your first admin account

```bash
docker compose exec tracepatch python3 app/create_admin.py <username> <password> "<Display Name>"
```

Password must be at least 8 characters. This creates a `master_admin` role account.

## 5. Log in

Open `http://localhost:8080/login` (or your server's address) and log in with the
account you just created.

## Updating to a new version

```bash
git pull
docker build -t tracepatch:latest .
docker compose up -d --force-recreate
```

Your data is untouched — it lives in Docker volumes, not in the container itself.

## Troubleshooting

- **App won't start / crashes immediately**: check `docker compose logs` — the most
  common cause is a missing `SECTRACK_SECRET` in `.env`.
- **Can't reach the app in a browser**: confirm port 8080 isn't blocked by a firewall
  or security group, and that `docker compose ps` shows the container as running.
- **Lost admin access**: run `create_admin.py` again with a new username to create
  a second admin account.
