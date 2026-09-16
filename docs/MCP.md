# MCP: let an LLM drive your server through Dachboard

The dashboard exposes its whole API to machines via **Bearer API tokens**.
`mcp/dachboard_mcp.py` is a stdio MCP server that wraps that API as 22 tools.
The token's rights are the hard ceiling: whatever the token may do, the model
may do — and nothing more.

## 1. Create a token

Users tab → **API tokens** → name it, pick a slot (or leave empty), tick
**admin** if the model should see the whole filesystem.

- plain token: sees only its slot's home dir and only the rights you ticked;
- admin token: whole filesystem + all rights **except user/token management**
  (a leaked token can never mint admins).

The token is shown once. Copy it.

## 2. Point an MCP client at it

Any MCP client (Claude Desktop, Claude Code, opencode, …):

```json
{
  "mcpServers": {
    "dachboard": {
      "command": "python3",
      "args": ["/path/to/repo/mcp/dachboard_mcp.py"],
      "env": {
        "DACH_URL": "https://your-tunnel-host/dash",
        "DACH_TOKEN": "dach_..."
      }
    }
  }
}
```

Through the tunnel use the public URL with the `/dash` prefix; on the server
itself `http://127.0.0.1:8420` works. Stdlib only, python 3.10+.

## 3. What the model gets

| tool | what it does |
|---|---|
| `dach_overview` | CPU / RAM / disk / temps / load |
| `dach_services`, `dach_service_logs`, `dach_service_action` | systemd units: list, journal, start/stop/restart |
| `dach_containers`, `dach_container_logs`, `dach_container_action` | docker: list, logs, control |
| `dach_files_list/read/write/mkdir/delete/move` | file ops inside the token's root |
| `dach_files_upload` | push a local file (from the MCP host) to the server |
| `dach_files_unzip` | unpack a zip already on the server (safe members only) |
| `dach_commands`, `dach_command_create/run/delete` | preset commands: the model's "shell" without a shell |
| `dach_runs` | recent runs with output |
| `dach_tunnel` | current public URL |
| `dach_whoami` | the token's own rights and slot |

Deploy pattern the model should use: `dach_files_upload` a zip (or files),
then `dach_files_unzip`, then `dach_command_create` + `dach_command_run` to
build/start, `dach_service_logs` to read back.

## 4. Limits and safety

- Every tool call is a normal authenticated API call: CSRF-exempt bearer path,
  rights checked per call, file ops jailed to the token's root (no symlink or
  `../` escapes; zip members validated before anything is written).
- Uploads: `client_max_body_size 250m` on `/dash/` (nginx), 200 MiB per file
  on the backend (`max_upload_mb` in config.yaml), zips capped at 200 MiB
  unpacked / 5000 entries.
- The model never gets a raw shell. `dach_command_*` is argv-only, no shell
  expansion, and runs as the slot user (or root for admin tokens) with the
  same systemd-run caps as the UI.
- Revoking the token in the Users tab cuts the model off instantly.

## 5. Test it

```bash
DACH_URL=http://127.0.0.1:8420 DACH_TOKEN=dach_... python3 mcp/e2e.py
```

Drives initialize → tools/list → whoami/overview/files/services/write/read/
delete over stdio and prints `E2E PASS`.
