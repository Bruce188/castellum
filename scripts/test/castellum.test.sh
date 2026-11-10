#!/usr/bin/env bash
# castellum.test.sh: runs scripts/castellum against a stub API server (python3 http.server).
# Usage: bash scripts/test/castellum.test.sh   Exit: 0 on pass.
set -euo pipefail

CLI="$(cd "$(dirname "$0")/.." && pwd)/castellum"
tmp=$(mktemp -d)
trap 'kill "$srv" 2>/dev/null; rm -rf "$tmp"' EXIT
export XDG_CONFIG_HOME=$tmp/cfg

cat >"$tmp/stub.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")
    def authed(self):
        return self.headers.get("Authorization") == "Bearer tok123"
    def do_POST(self):
        if self.path == "/api/auth/login":
            b = self.body()
            if b == {"username": "admin", "password": "pa ss"}:
                return self.reply(200, {"token": "tok123", "roles": ["ADMIN"], "mustChangePassword": False})
            return self.reply(401, {"error": "bad credentials"})
        if not self.authed(): return self.reply(401, {})
        if self.path == "/api/scan": return self.reply(202, {"echo": self.body()})
        self.reply(404, {"error": "nope"})
    def do_GET(self):
        if not self.authed(): return self.reply(401, {})
        if self.path == "/api/devices": return self.reply(200, [{"id": 1, "ip": "10.0.0.5"}])
        self.reply(404, {"error": "nope"})

s = HTTPServer(("127.0.0.1", 0), H)
print(s.server_port, flush=True)
s.serve_forever()
PY
coproc SRV { python3 -I "$tmp/stub.py"; }
srv=$SRV_PID
read -r port <&"${SRV[0]}"
export CASTELLUM_URL=http://127.0.0.1:$port

fail=0
check() { # check <label> <expected-substring> <actual>
  if [[ $3 == *"$2"* ]]; then echo "[PASS] $1"; else echo "[FAIL] $1: expected '$2' in: $3"; fail=1; fi
}

check "devices before login" "not logged in" "$("$CLI" devices 2>&1 || true)"
check "wrong password rejected" "login failed" "$(printf 'nope\n' | "$CLI" login admin 2>&1 || true)"
check "login" "Logged in as admin" "$(printf 'pa ss\n' | "$CLI" login admin 2>&1)"
check "token file is private" "600" "$(stat -c %a "$tmp/cfg/castellum/token")"
check "devices" '"ip": "10.0.0.5"' "$("$CLI" devices)"
check "scan body" '"type": "SERVICE_DETECT"' "$("$CLI" scan 10.0.0.0/24 service)"
check "bad scan type" "must be ping" "$("$CLI" scan 10.0.0.0/24 udp 2>&1 || true)"
check "non-2xx surfaces status" "HTTP 404" "$("$CLI" api GET /api/missing 2>&1 || true)"
check "cve id validated" "expected a CVE id" "$("$CLI" cve ../admin 2>&1 || true)"
check "api path validated" "must start with /api/" "$("$CLI" api GET //evil 2>&1 || true)"
"$CLI" logout >/dev/null
check "logout" "not logged in" "$("$CLI" devices 2>&1 || true)"

exit $fail
