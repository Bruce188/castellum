#!/bin/sh
# remote-docker-agent.test.sh — Stub-based test for remote-docker-agent.sh
#
# Stubs docker and curl in a temp dir on PATH.
# The stub curl records its argv and stdin to a file so we can assert the request shape.
# Daemon-free: docker is stubbed to return a minimal container array.
#
# Usage: sh scripts/test/remote-docker-agent.test.sh
# Exit: 0 on pass, non-zero on failure.

set -eu

PASS=0
FAIL=0
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_SCRIPT="$SCRIPT_DIR/remote-docker-agent.sh"

# ── Helpers ───────────────────────────────────────────────────────────────────
assert_contains() {
    _needle="$1"
    _haystack="$2"
    _label="${3:-assertion}"
    case "$_haystack" in
        *"$_needle"*)
            PASS=$((PASS + 1))
            printf '[PASS] %s\n' "$_label"
            ;;
        *)
            FAIL=$((FAIL + 1))
            printf '[FAIL] %s\n  expected to find: %s\n  in: %s\n' "$_label" "$_needle" "$_haystack"
            ;;
    esac
}

assert_not_contains() {
    _needle="$1"
    _haystack="$2"
    _label="${3:-assertion}"
    case "$_haystack" in
        *"$_needle"*)
            FAIL=$((FAIL + 1))
            printf '[FAIL] %s\n  must NOT contain: %s\n' "$_label" "$_needle"
            ;;
        *)
            PASS=$((PASS + 1))
            printf '[PASS] %s\n' "$_label"
            ;;
    esac
}

# ── Setup stubs ───────────────────────────────────────────────────────────────
TMPDIR="$(mktemp -d)"
CURL_RECORD="$TMPDIR/curl_record"
CURL_BODY="$TMPDIR/curl_body"

# Stub docker: return a minimal container array for 'inspect', empty list for 'ps -q'
cat > "$TMPDIR/docker" << 'EOF'
#!/bin/sh
if [ "$1" = "ps" ]; then
    printf 'stub-container-id\n'
elif [ "$1" = "inspect" ]; then
    printf '[{"Id":"stub-container-id","Name":"/stub-container","NetworkSettings":{"Ports":{},"Networks":{"bridge":{"IPAddress":"172.17.0.2","Gateway":"172.17.0.1"}}},"Config":{"Image":"nginx"}}]\n'
fi
EOF
chmod +x "$TMPDIR/docker"

# Stub curl: record argv and stdin; always succeed (exit 0)
cat > "$TMPDIR/curl" << 'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$CURL_RECORD_FILE"
cat - > "$CURL_BODY_FILE"
printf 'OK\n'
EOF
chmod +x "$TMPDIR/curl"

# Export the record files so the stub can write to them
export CURL_RECORD_FILE="$CURL_RECORD"
export CURL_BODY_FILE="$CURL_BODY"

# ── Run the agent ─────────────────────────────────────────────────────────────
TEST_TOKEN="test-bearer-token-xyz-123"
TEST_URL="https://castellum.example.com"

# Prepend our stubs to PATH
PATH="$TMPDIR:$PATH"
export PATH

CASTELLUM_URL="$TEST_URL" CASTELLUM_TOKEN="$TEST_TOKEN" \
    sh "$AGENT_SCRIPT" \
    --agent-id "test-agent-id" \
    --hostname "test-host.local" \
    --primary-ip "10.0.0.99"

# ── Load recorded request ─────────────────────────────────────────────────────
if [ ! -f "$CURL_RECORD" ]; then
    printf '[FAIL] curl stub was not called — no record file found\n'
    FAIL=$((FAIL + 1))
else
    RECORDED_ARGS="$(cat "$CURL_RECORD")"
    RECORDED_BODY="$(cat "$CURL_BODY")"

    # Assert Authorization header contains the bearer token
    assert_contains "Authorization: Bearer $TEST_TOKEN" "$RECORDED_ARGS" \
        "Authorization header contains bearer token"

    # Assert method is POST
    assert_contains "POST" "$RECORDED_ARGS" \
        "curl called with POST method"

    # Assert URL path contains /api/discovery/remote-docker
    assert_contains "/api/discovery/remote-docker" "$RECORDED_ARGS" \
        "URL contains /api/discovery/remote-docker"

    # Assert Content-Type header
    assert_contains "Content-Type: application/json" "$RECORDED_ARGS" \
        "Content-Type is application/json"

    # Assert body contains containers field
    assert_contains '"containers"' "$RECORDED_BODY" \
        "body contains containers field"

    # Assert body contains agentId
    assert_contains '"agentId"' "$RECORDED_BODY" \
        "body contains agentId field"

    # Assert body contains primaryIp
    assert_contains '"primaryIp"' "$RECORDED_BODY" \
        "body contains primaryIp field"

    # Assert token is NOT echoed to stdout/stderr in body
    assert_not_contains "$TEST_TOKEN" "$RECORDED_BODY" \
        "token value not echoed in request body"
fi

# ── Cleanup ───────────────────────────────────────────────────────────────────
rm -rf "$TMPDIR"

# ── Summary ───────────────────────────────────────────────────────────────────
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
