#!/usr/bin/env bash
# Narrated, paced version of demo/run_demo.sh, meant to be captured with
# `asciinema rec` (see demo/README.md) rather than run in CI. Same
# underlying commands and same policy file as run_demo.sh — this script
# only adds headers, pacing, and prettier JSON output for a viewer
# watching it play back, not different behavior to demonstrate.
set -euo pipefail
cd "$(dirname "$0")/.."

BOLD="$(tput bold 2>/dev/null || true)"
DIM="$(tput dim 2>/dev/null || true)"
GREEN="$(tput setaf 2 2>/dev/null || true)"
RED="$(tput setaf 1 2>/dev/null || true)"
RESET="$(tput sgr0 2>/dev/null || true)"

header() {
  echo
  echo "${BOLD}${GREEN}== $1 ==${RESET}"
  sleep 1.2
}

note() {
  echo "${DIM}$1${RESET}"
  sleep 0.6
}

run_and_show() {
  # $1 = request JSON, $2... = server command
  local request="$1"
  shift
  printf '%s\n%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' "$request" \
    | "$@" 2>&1 | while IFS= read -r line; do
        if echo "$line" | jq . >/dev/null 2>&1; then
          echo "$line" | jq -c .
        else
          echo "$line"
        fi
      done
  sleep 1.5
}

clear 2>/dev/null || true
echo "${BOLD}AgentGuard — a minimal-privilege proxy for AI agent tool calls${RESET}"
note "Wraps an MCP server; every tools/call is checked against policy, output"
note "is scanned for injected instructions and known secrets, and every"
note "decision lands in a hash-chained audit log."
sleep 1.5

WORKDIR="$(mktemp -d)"
mkdir -p "$WORKDIR/.ssh"
echo "-----BEGIN OPENSSH PRIVATE KEY-----FAKE-DEMO-KEY-----END OPENSSH PRIVATE KEY-----" > "$WORKDIR/.ssh/id_rsa"
echo "just some notes" > "$WORKDIR/notes.txt"
echo "deploy uses aws key AKIAABCDEFGHIJKLMNOP for staging" > "$WORKDIR/deploy_notes.txt"
AUDIT_LOG="$WORKDIR/agentguard_audit.log"

header "1. Unprotected: agent asks for ~/.ssh/id_rsa, server just hands it over"
run_and_show \
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"$WORKDIR/.ssh/id_rsa\"}}}" \
  python3 demo/vulnerable_server.py

header "2. Same request, now through AgentGuard: blocked before it reaches the server"
run_and_show \
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"$WORKDIR/.ssh/id_rsa\"}}}" \
  python3 -m agentguard.cli run --config policies/default.yaml --audit-log "$AUDIT_LOG" -- python3 demo/vulnerable_server.py

header "3. An ordinary file read still works — this isn't a blanket deny"
run_and_show \
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"$WORKDIR/notes.txt\"}}}" \
  python3 -m agentguard.cli run --config policies/default.yaml --audit-log "$AUDIT_LOG" -- python3 demo/vulnerable_server.py

header "4. A file that just happens to CONTAIN a secret: allowed, but redacted"
run_and_show \
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"$WORKDIR/deploy_notes.txt\"}}}" \
  python3 -m agentguard.cli run --config policies/default.yaml --audit-log "$AUDIT_LOG" -- python3 demo/vulnerable_server.py

header "5. Unprotected: agent fetches a page, poisoned instruction comes straight through"
run_and_show \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://blog.example.com/cookie-recipe"}}}' \
  python3 demo/vulnerable_server.py

header "6. Same fetch through AgentGuard: URL is allowed, output is blocked as injection"
run_and_show \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://blog.example.com/cookie-recipe"}}}' \
  python3 -m agentguard.cli run --config policies/default.yaml --audit-log "$AUDIT_LOG" -- python3 demo/vulnerable_server.py

header "7. A clean page still fetches normally"
run_and_show \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://docs.example.com/readme"}}}' \
  python3 -m agentguard.cli run --config policies/default.yaml --audit-log "$AUDIT_LOG" -- python3 demo/vulnerable_server.py

header "8. Verify the audit log's hash chain"
python3 -m agentguard.cli verify-audit "$AUDIT_LOG"
sleep 1.5

header "9. Someone edits a past entry directly in the file (covering their tracks)"
python3 - "$AUDIT_LOG" <<'PYEOF'
import json, sys
path = sys.argv[1]
with open(path) as f:
    lines = [l for l in f if l.strip()]
entry = json.loads(lines[0])
print(f"before: allowed={entry['allowed']}")
entry["allowed"] = True
lines[0] = json.dumps(entry) + "\n"
with open(path, "w") as f:
    f.writelines(lines)
print(f"after:  allowed={entry['allowed']}  (edited directly in the file)")
PYEOF
sleep 1.5

header "10. Verify again: the edit is caught immediately"
python3 -m agentguard.cli verify-audit "$AUDIT_LOG" || true
sleep 1

echo
echo "${BOLD}${GREEN}Done.${RESET} ${DIM}github.com/zgemini22/AgentGuard — see README.md and THREAT_MODEL.md for the full picture.${RESET}"
sleep 2
