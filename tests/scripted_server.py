"""A stand-in MCP server for tests: for each request it reads, it writes
the raw lines scripted for that method (argv[1] is a JSON object mapping
method -> list of lines). `__ID__` in a line becomes the request's id as
JSON, `__IDSTR__` the same id as a JSON string. Unscripted `initialize`
gets a plain answer; anything else unscripted gets nothing."""

import json
import sys

script = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    try:
        message = json.loads(raw)
    except ValueError:
        continue
    if not isinstance(message, dict):
        continue
    method = message.get("method")
    request_id = message.get("id")
    lines = script.get(method)
    if lines is None and method == "initialize":
        lines = [json.dumps({"jsonrpc": "2.0", "id": request_id, "result": {"serverInfo": {"name": "scripted"}}})]
    for line in lines or []:
        line = line.replace("__IDSTR__", json.dumps(str(request_id))).replace("__ID__", json.dumps(request_id))
        sys.stdout.write(line + "\n")
    sys.stdout.flush()
