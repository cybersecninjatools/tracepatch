#!/usr/bin/env bash
set -euo pipefail

export GIT_COMMIT="$(git rev-parse --short HEAD)"
export BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "Building tracepatch (commit=${GIT_COMMIT}, date=${BUILD_DATE})"

docker compose build --no-cache
docker compose up -d --force-recreate
