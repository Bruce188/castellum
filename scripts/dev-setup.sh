#!/usr/bin/env bash
# One-time local setup: native PostgreSQL, the castellum role/database, and .env.
# Safe to re-run: an existing .env is kept and the role password is re-synced to it.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v psql >/dev/null || ! command -v htpasswd >/dev/null; then
  sudo apt-get update
  sudo apt-get install -y postgresql apache2-utils
fi
pg_isready -q || sudo service postgresql start

if [ ! -f .env ]; then
  read -rp "Admin username [admin]: " admin
  admin=${admin:-admin}
  read -rsp "Admin password: " pw
  echo
  [ -n "$pw" ] || { echo "Password must not be empty" >&2; exit 1; }
  hash=$(htpasswd -bnBC 12 "" "$pw" | tr -d ':\n')
  # Single-quoted so `source .env` keeps the $ in the bcrypt hash literal.
  sed -e "s|^DATABASE_PASSWORD=.*|DATABASE_PASSWORD=$(openssl rand -hex 16)|" \
      -e "s|^CASTELLUM_ADMIN_USERNAME=.*|CASTELLUM_ADMIN_USERNAME=$admin|" \
      -e "s|^CASTELLUM_ADMIN_PASSWORD_HASH=.*|CASTELLUM_ADMIN_PASSWORD_HASH='$hash'|" \
      -e "s|^# CASTELLUM_SECURITY_JWT_SECRET=.*|CASTELLUM_SECURITY_JWT_SECRET=$(openssl rand -base64 48 | tr -d '\n')|" \
      -e "s|^# CASTELLUM_INTEGRATION_KEY=.*|CASTELLUM_INTEGRATION_KEY=$(openssl rand -base64 32)|" \
      .env.example > .env
  chmod 600 .env
  echo "Wrote .env"
fi

set -a
# shellcheck disable=SC1091
source .env
set +a
db=${DATABASE_URL##*/}
db=${db%%\?*}

# psql vars + format(%I/%L) quote the identifiers and password safely.
(cd /tmp && sudo -u postgres psql -q -v ON_ERROR_STOP=1 \
  -v user="$DATABASE_USERNAME" -v pw="$DATABASE_PASSWORD" -v db="$db") <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', :'user') WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'user') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'user', :'pw') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'db', :'user') WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'db') \gexec
SQL

echo "Postgres ready: database '$db' owned by '$DATABASE_USERNAME'. Start the app with scripts/dev.sh"
