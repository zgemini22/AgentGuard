#!/usr/bin/env bash
# Demo: an agent tries to read an SSH private key through a vulnerable
# MCP server. Run directly, AgentGuard blocks it and logs it; a normal
# file read still goes through; a file that merely *contains* a secret
# (rather than being one) gets its output redacted instead of blocked
# outright; and fetching a poisoned web page gets the whole response
# blocked as a suspected prompt injection.
set -euo pipefail
cd "$(dirname "$0")/.."

WORKDIR="$(mktemp -d)"
mkdir -p "$WORKDIR/.ssh"
echo "-----BEGIN OPENSSH PRIVATE KEY-----FAKE-DEMO-KEY-----END OPENSSH PRIVATE KEY-----" > "$WORKDIR/.ssh/id_rsa"
echo "just some notes" > "$WORKDIR/notes.txt"
echo "deploy uses aws key AKIAABCDEFGHIJKLMNOP for staging" > "$WORKDIR/deploy_notes.txt"

AUDIT_LOG="$WORKDIR/agentguard_audit.log"

echo "=== 1) Without AgentGuard: the vulnerable server just hands over the key ==="
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"$WORKDIR/.ssh/id_rsa\"}}}" \
  | python3 demo/vulnerable_server.py

echo
echo "=== 2) With AgentGuard: same request, now blocked ==="
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"$WORKDIR/.ssh/id_rsa\"}}}" \
  | python3 -m agentguard.cli run --config policies/default.yaml --audit-log "$AUDIT_LOG" -- python3 demo/vulnerable_server.py

echo
echo "=== 3) With AgentGuard: a normal file read still works ==="
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"$WORKDIR/notes.txt\"}}}" \
  | python3 -m agentguard.cli run --config policies/default.yaml --audit-log "$AUDIT_LOG" -- python3 demo/vulnerable_server.py

echo
echo "=== 4) With AgentGuard: an allowed file read still gets its secret redacted ==="
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"$WORKDIR/deploy_notes.txt\"}}}" \
  | python3 -m agentguard.cli run --config policies/default.yaml --audit-log "$AUDIT_LOG" -- python3 demo/vulnerable_server.py

echo
echo "=== 5) Without AgentGuard: fetching a poisoned page hands the injected instruction straight to the agent ==="
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://blog.example.com/cookie-recipe"}}}' \
  | python3 demo/vulnerable_server.py

echo
echo "=== 6) With AgentGuard: the same poisoned page is blocked as a suspected prompt injection ==="
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://blog.example.com/cookie-recipe"}}}' \
  | python3 -m agentguard.cli run --config policies/default.yaml --audit-log "$AUDIT_LOG" -- python3 demo/vulnerable_server.py

echo
echo "=== 7) With AgentGuard: a clean page still fetches normally ==="
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://docs.example.com/readme"}}}' \
  | python3 -m agentguard.cli run --config policies/default.yaml --audit-log "$AUDIT_LOG" -- python3 demo/vulnerable_server.py

echo
echo "=== Audit log ==="
cat "$AUDIT_LOG"
