#!/usr/bin/env python3
"""MCP server bridging an LLM to the Dachboard REST API.

Auth: Bearer API token (created in the Users tab or via POST /api/tokens).
Scoping: the token's rights are the hard ceiling for everything below.

Run:
    DACH_URL=http://127.0.0.1:8420 DACH_TOKEN=dach_... python3 mcp/dachboard_mcp.py

Config (Claude Desktop / any MCP client):
    {"mcpServers": {"dachboard": {
        "command": "python3",
        "args": ["/path/to/mcp/dachboard_mcp.py"],
        "env": {"DACH_URL": "...", "DACH_TOKEN": "dach_..."}
    }}}

Transport: stdio, JSON-RPC 2.0, MCP 2024-11-05 (initialize/tools/list/tools/call).
No external deps — stdlib only, works on any python 3.10+.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = (os.environ.get("DACH_URL") or "http://127.0.0.1:8420").rstrip("/")
TOKEN = os.environ.get("DACH_TOKEN") or ""
if not TOKEN:
    print("DACH_TOKEN is not set", file=sys.stderr)
    sys.exit(1)

PROTO = "2024-11-05"
S = { "_id": 0 }


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _err(msg: str, code: int = 32603, ident: int | None = None) -> None:
    _send({"jsonrpc": "2.0", "id": ident, "error": {"code": code, "message": msg}})


def _next_id() -> int:
    S["_id"] += 1
    return S["_id"]


def api(method: str, path: str, body: dict | list | None = None,
        params: dict | None = None, raw: bool = False) -> dict | str:
    url = BASE + path
    if params:
        url += "?" + "&".join(
            f"{k}={urllib.request.quote(str(v), safe='')}" for k, v in params.items() if v is not None)
    data = None
    headers = {"Authorization": f"Bearer {TOKEN}"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=900) as r:
            text = r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:500]
        raise RuntimeError(f"HTTP {e.code}: {detail}") from None
    if raw or not text.strip():
        return text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _arg(args: dict, *names: str, default=None):
    for n in names:
        if n in args and args[n] is not None:
            return args[n]
    return default


# ---------- tool implementations (plain dicts, easy to test) ----------

def t_overview(_a: dict) -> dict:
    return api("GET", "/api/metrics")

def t_services(_a: dict) -> dict:
    return api("GET", "/api/services")

def t_service_logs(a: dict) -> dict:
    return api("GET", f"/api/services/{_arg(a, 'name')}/logs",
               params={"tail": _arg(a, "tail", default=200)})

def t_service_action(a: dict) -> dict:
    act = _arg(a, "action")
    if act not in ("start", "stop", "restart"):
        raise RuntimeError("action must be start|stop|restart")
    return api("POST", f"/api/services/{_arg(a, 'name')}/{act}")

def t_containers(_a: dict) -> dict:
    return api("GET", "/api/containers")

def t_container_action(a: dict) -> dict:
    act = _arg(a, "action")
    if act not in ("start", "stop", "restart"):
        raise RuntimeError("action must be start|stop|restart")
    return api("POST", f"/api/containers/{_arg(a, 'name')}/{act}")

def t_container_logs(a: dict) -> dict:
    return api("GET", f"/api/containers/{_arg(a, 'name')}/logs",
               params={"tail": _arg(a, "tail", default=200)})

def t_files_list(a: dict) -> dict:
    return api("GET", "/api/files", params={"path": _arg(a, "path", default=""),
                                            "slot": _arg(a, "slot", default="")})

def t_files_read(a: dict) -> dict:
    return api("GET", "/api/files/read", params={"path": _arg(a, "path", ""),
                                                 "slot": _arg(a, "slot", "")})

def t_files_write(a: dict) -> dict:
    return api("POST", "/api/files/write", body={
        "path": _arg(a, "path"), "content": _arg(a, "content", default=""),
        "slot": _arg(a, "slot")})

def t_files_mkdir(a: dict) -> dict:
    return api("POST", "/api/files/mkdir", body={
        "path": _arg(a, "path"), "slot": _arg(a, "slot")})

def t_files_delete(a: dict) -> dict:
    return api("POST", "/api/files/delete", body={
        "path": _arg(a, "path"), "slot": _arg(a, "slot")})

def t_files_move(a: dict) -> dict:
    return api("POST", "/api/files/move", body={
        "path": _arg(a, "path"), "to": _arg(a, "to"), "slot": _arg(a, "slot")})

def t_files_unzip(a: dict) -> dict:
    return api("POST", "/api/files/unzip", body={
        "path": _arg(a, "path"), "into": _arg(a, "into", default=""),
        "slot": _arg(a, "slot")})

def t_files_upload(a: dict) -> dict:
    """Upload a local file (MCP host machine) to the server via multipart."""
    import mimetypes
    import uuid
    lp = str(_arg(a, "local_path"))
    remote = _arg(a, "remote_path")  # relative dir or full dest name
    with open(lp, "rb") as f:
        blob = f.read()
    name = remote if ("/" not in str(remote)) else (str(remote).rstrip("/").rsplit("/", 1)[1])
    folder = "" if "/" not in str(remote) else str(remote).rstrip("/").rsplit("/", 1)[0].strip("/")
    ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
    boundary = uuid.uuid4().hex
    part = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'
            f"Content-Type: {ctype}\r\n\r\n").encode() + blob + f"\r\n--{boundary}--\r\n".encode()
    url = BASE + "/api/files/upload"
    if folder:
        url += "?path=" + urllib.request.quote(folder, safe="")
    req = urllib.request.Request(url, data=part, method="POST", headers={
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with urllib.request.urlopen(req, timeout=900) as r:
            return json.loads(r.read().decode(errors="replace"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode(errors='replace')[:500]}") from None

def t_commands(a: dict) -> dict:
    return api("GET", "/api/commands")

def t_command_create(a: dict) -> dict:
    return api("POST", "/api/commands", body={
        "name": _arg(a, "name"),
        "argv": _arg(a, "argv"),
        "run_as": _arg(a, "run_as", default="owner"),
        "allowed": _arg(a, "allowed", default=[]),
        "timeout_sec": _arg(a, "timeout_sec", default=60)})

def t_command_run(a: dict) -> dict:
    """Run by name or id: name lookups fetch the list first."""
    name = _arg(a, "name")
    cid = _arg(a, "id")
    if name and not cid:
        for c in api("GET", "/api/commands"):
            if c.get("name") == name:
                cid = c["id"]
                break
        if not cid:
            raise RuntimeError(f"no command named {name!r}")
    return api("POST", f"/api/commands/{int(cid)}/run", body={})

def t_command_delete(a: dict) -> dict:
    cid = _arg(a, "id")
    if not cid and _arg(a, "name"):
        for c in api("GET", "/api/commands"):
            if c.get("name") == _arg(a, "name"):
                cid = c["id"]
                break
    return api("DELETE", f"/api/commands/{int(cid)}")

def t_runs(_a: dict) -> dict:
    return api("GET", "/api/runs")

def t_tunnel(_a: dict) -> dict:
    return api("GET", "/api/tunnel")

def t_whoami(_a: dict) -> dict:
    """Token introspection: rights + slot scope. Needs no extra right."""
    return api("GET", "/api/me")


TOOLS = [
    ("dach_overview", t_overview, "Host vitals: CPU, memory, disk, temps, load",
     {}),
    ("dach_services", t_services,
     "List systemd units (admin tokens only)", {}),
    ("dach_service_logs", t_service_logs,
     "Read a unit's journal (admin tokens only)",
     {"name": {"type": "string", "description": "unit name, e.g. nginx.service"},
      "tail": {"type": "integer", "description": "last N lines, default 200"}}),
    ("dach_service_action", t_service_action,
     "Start/stop/restart a systemd unit — runs as root on the host "
     "(admin tokens only)",
     {"name": {"type": "string"}, "action": {"type": "string",
      "enum": ["start", "stop", "restart"]}}),
    ("dach_containers", t_containers, "List docker containers", {}),
    ("dach_container_logs", t_container_logs, "Read docker container logs",
     {"name": {"type": "string"}, "tail": {"type": "integer", "default": 200}}),
    ("dach_container_action", t_container_action, "Start/stop/restart a container",
     {"name": {"type": "string"}, "action": {"type": "string",
      "enum": ["start", "stop", "restart"]}}),
    ("dach_files_list", t_files_list, "List a directory",
     {"path": {"type": "string", "description": "relative to the token's root"},
      "slot": {"type": "string", "description": "admin tokens only"}}),
    ("dach_files_read", t_files_read, "Read a text file",
     {"path": {"type": "string"}, "slot": {"type": "string"}}),
    ("dach_files_write", t_files_write, "Write/create a text file",
     {"path": {"type": "string"}, "content": {"type": "string"},
      "slot": {"type": "string"}}),
    ("dach_files_mkdir", t_files_mkdir, "Create a directory",
     {"path": {"type": "string"}, "slot": {"type": "string"}}),
    ("dach_files_delete", t_files_delete, "Delete a file or directory",
     {"path": {"type": "string"}, "slot": {"type": "string"}}),
    ("dach_files_move", t_files_move, "Move/rename",
     {"path": {"type": "string"}, "to": {"type": "string"},
      "slot": {"type": "string"}}),
    ("dach_files_unzip", t_files_unzip, "Unpack a zip on the server (safe members only)",
     {"path": {"type": "string"}, "into": {"type": "string",
      "description": "destination dir, default: folder named after the zip"},
      "slot": {"type": "string"}}),
    ("dach_files_upload", t_files_upload, "Upload a local file to the server",
     {"local_path": {"type": "string", "description": "path on the MCP host"},
      "remote_path": {"type": "string",
      "description": "'dir/' or 'dir/name' relative to the token's root"}}),
    ("dach_commands", t_commands, "List preset commands", {}),
    ("dach_command_create", t_command_create, "Create a preset command",
     {"name": {"type": "string"}, "argv": {"type": "array", "items": {"type": "string"}},
      "run_as": {"type": "string", "enum": ["owner", "self"],
      "description": "owner = the token's slot user"},
      "allowed": {"type": "array", "items": {"type": "string"},
      "description": "'*' = anyone with commands_run"},
      "timeout_sec": {"type": "integer", "default": 60}}),
    ("dach_command_run", t_command_run, "Run a preset command by name or id",
     {"name": {"type": "string"}, "id": {"type": "integer"}}),
    ("dach_command_delete", t_command_delete, "Delete a preset command",
     {"name": {"type": "string"}, "id": {"type": "integer"}}),
    ("dach_runs", t_runs, "Recent command runs with output", {}),
    ("dach_tunnel", t_tunnel, "Current public tunnel URL", {}),
    ("dach_whoami", t_whoami, "Token rights and slot scope", {}),
]


# ---------- stdio JSON-RPC loop ----------

def handle(msg: dict) -> dict | None:
    m = msg.get("method")
    ident = msg.get("id")
    if m == "initialize":
        return {"jsonrpc": "2.0", "id": ident, "result": {
            "protocolVersion": PROTO,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "dachboard-mcp", "version": "1.0.0"}}}
    if m == "notifications/initialized":
        return None
    if m == "ping":
        return {"jsonrpc": "2.0", "id": ident, "result": {}}
    if m == "tools/list":
        out = []
        # `fn` is deliberately unused here: the listing describes tools, and the
        # handler is only needed by tools/call.
        for name, _fn, desc, props in TOOLS:
            schema = {"type": "object", "properties": props}
            schema["required"] = [k for k in props
                                  if k in ("name", "path", "local_path", "argv",
                                           "action", "to", "content")
                                  and "default" not in props[k]]
            out.append({"name": name, "description": desc, "inputSchema": schema})
        return {"jsonrpc": "2.0", "id": ident, "result": {"tools": out}}
    if m == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        fn = next((f for n, f, _d, _p in TOOLS if n == name), None)
        if not fn:
            return {"jsonrpc": "2.0", "id": ident, "result": {
                "isError": True,
                "content": [{"type": "text", "text": f"unknown tool {name}"}]}}
        try:
            res = fn(params.get("arguments") or {})
            text = res if isinstance(res, str) else json.dumps(res, ensure_ascii=False)
            return {"jsonrpc": "2.0", "id": ident, "result": {
                "content": [{"type": "text", "text": text}]}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": ident, "result": {
                "isError": True,
                "content": [{"type": "text", "text": str(e)}]}}
    if m in ("resources/list", "prompts/list"):
        return {"jsonrpc": "2.0", "id": ident, "result": {"resources": []} if m == "resources/list" else {"prompts": []}}
    if ident is None:
        return None
    return {"jsonrpc": "2.0", "id": ident, "error": {"code": -32601,
                                                     "message": f"unknown method {m}"}}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            _err("bad json", -32700, None)
            continue
        if not isinstance(msg, dict):
            continue
        try:
            resp = handle(msg)
        except Exception as e:  # never die mid-conversation
            _err(str(e), 32603, msg.get("id"))
            continue
        if resp is not None:
            _send(resp)


if __name__ == "__main__":
    main()
