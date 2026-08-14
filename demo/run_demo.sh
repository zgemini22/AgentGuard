#!/usr/bin/env bash
# 30-second demo: an agent tries to read an SSH private key through a
# vulnerable MCP server. Run directly, AgentGuard blocks it and logs it;
# a normal file read still goes through.
set -euo pipefail
cd "$(dirname "$0")/.."

WORKDIR="$(mktemp -d)"
mkdir -p "$WORKDIR/.ssh"
echo "-----BEGIN OPENSSH PRIVATE KEY-----FAKE-DEMO-KEY-----END OPENSSH PRIVATE KEY-----" > "$WORKDIR/.ssh/id_rsa"
echo "just some notes" > "$WORKDIR/notes.txt"

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
echo "=== Audit log ==="
cat "$AUDIT_LOG"
