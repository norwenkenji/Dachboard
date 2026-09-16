"""E2E: drive the MCP server over stdio with a freshly minted admin token.
Run on the server: DACH_TOKEN=... python3 mcp/e2e.py"""
import json
import os
import subprocess

BASE = os.environ.get("DACH_URL", "http://127.0.0.1:8420")
TOKEN = os.environ.get("DACH_TOKEN") or open("/home/zxc/.mcp-test-tok").read().strip()

lines = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "e2e", "version": "0"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": {"name": "dach_whoami", "arguments": {}}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
     "params": {"name": "dach_overview", "arguments": {}}},
    {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
     "params": {"name": "dach_files_list", "arguments": {"path": "etc"}}},
    {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
     "params": {"name": "dach_services", "arguments": {}}},
    {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
     "params": {"name": "dach_files_write",
                "arguments": {"path": "mcp-e2e.txt", "content": "mcp wrote this"}}},
    {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
     "params": {"name": "dach_files_read", "arguments": {"path": "mcp-e2e.txt"}}},
    {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
     "params": {"name": "dach_files_delete", "arguments": {"path": "mcp-e2e.txt"}}},
]
proc = subprocess.run(
    ["python3", "/home/zxc/dachboard-mcp/dachboard_mcp.py"],
    input="\n".join(json.dumps(x) for x in lines) + "\n",
    capture_output=True, text=True, timeout=180,
    env={"DACH_URL": BASE, "DACH_TOKEN": TOKEN, "PATH": "/usr/bin:/bin"})
if proc.returncode != 0:
    print("mcp stderr:", proc.stderr[-800:])
out = [json.loads(l) for l in proc.stdout.strip().splitlines() if l.strip()]
byid = {o.get("id"): o for o in out}
tools = byid[2]["result"]["tools"]
print("tools:", len(tools), [t["name"] for t in tools][:6], "...")
ok = True
for i in (3, 4, 5, 6, 7, 8, 9):
    res = byid[i]["result"]
    bad = res.get("isError")
    txt = res["content"][0]["text"]
    print(i, "ERR" if bad else "ok", txt[:80].replace("\n", " "))
    ok = ok and not bad
print("E2E", "PASS" if ok else "FAIL")
