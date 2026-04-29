#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 [--since YYYY-MM-DD[THH:MM:SSZ]] [--until ...] [--api-key XXXX] [--results-per-page N]

Without --since, runs an incremental pull (cursor = MAX(last_modified) in the cve table).
With --since, runs a bulk pull over [since, until] (default until = now).

Exit codes:
  0  success
  1  Spring Boot/JVM failure (network, parse, DB, etc.)
  2  argument parse error
EOF
}

SINCE=""
UNTIL=""
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --since)            SINCE="$2"; shift 2 ;;
    --since=*)          SINCE="${1#--since=}"; shift ;;
    --until)            UNTIL="$2"; shift 2 ;;
    --until=*)          UNTIL="${1#--until=}"; shift ;;
    --api-key)          export NVD_API_KEY="$2"; shift 2 ;;
    --api-key=*)        export NVD_API_KEY="${1#--api-key=}"; shift ;;
    --results-per-page) EXTRA_ARGS+=("--castellum.nvd.results-per-page=$2"); shift 2 ;;
    -h|--help)          usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# Normalize SINCE: if no time component, append T00:00:00Z.
if [[ -n "$SINCE" ]]; then
  case "$SINCE" in
    *T*) ;;
    *)   SINCE="${SINCE}T00:00:00Z" ;;
  esac
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
BACKEND="$SCRIPT_DIR/../backend"

ARGS=("--nvd-sync")
[[ -n "$SINCE" ]] && ARGS+=("--since=$SINCE")
[[ -n "$UNTIL" ]] && ARGS+=("--until=$UNTIL")
ARGS+=("${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}")

# Spring Boot Maven plugin takes a comma-separated list for run arguments.
RUN_ARGS=$(printf '%s,' "${ARGS[@]}" | sed 's/,$//')

cd "$BACKEND"
exec ./mvnw -q -DskipTests spring-boot:run -Dspring-boot.run.arguments="$RUN_ARGS"
