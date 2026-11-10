#!/usr/bin/env bash
# Start the backend and the Vite dev server with .env loaded. Ctrl-C stops both.
# --desktop also opens the app in the Tauri desktop window (see desktop/).
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "No .env: run scripts/dev-setup.sh first" >&2; exit 1; }
pg_isready -q || sudo service postgresql start

set -a
# shellcheck disable=SC1091
source .env
set +a

trap 'kill 0' EXIT
(cd backend && ./mvnw -q spring-boot:run) &
(cd frontend && { [ -d node_modules ] || npm ci; } && npm run dev) &
if [ "${1:-}" = --desktop ]; then
  # Native window on the Vite dev server; closing it stops the whole stack.
  (cd desktop && { [ -d node_modules ] || npm ci; } && CASTELLUM_URL=http://localhost:5173 npm run dev) &
fi
wait -n
