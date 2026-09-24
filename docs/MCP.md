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

> **An admin token is root on the host, not just "wide read access".** It
> includes `services_control` — `systemctl start/stop/restart` on *any* unit,
> run by the daemon as root — and `services_view`, which can read
> `journalctl -u dachboard` (the one-time setup token lives there) and whatever
> else your services log. Hand an admin token to a model only when you would
> hand it a root shell. A plain token cannot reach either right: `services_*`
> is admin-only by design (`rbac.ADMIN_ONLY`), not a checkbox you can tick.

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
| `dach_services`, `dach_service_logs`, `dach_service_action` | systemd units: list, journal, start/stop/restart — **admin tokens only**, runs as root on the host |
| `dach_containers`, `dach_container_logs`, `dach_container_action` | docker: list, logs, control (delegable: scoped to containers, not the host) |
| `dach_files_list/read/write/mkdir/delete/move` | file ops inside the token's root |
| `dach_files_upload` | push a local file (from the MCP host) to the server |
| `dach_files_unzip` | unpack a zip already on the server (safe members only) |
| `dach_commands`, `dach_command_create/run/delete` | preset commands: the model's "shell" without a shell |
| `dach_runs` | recent runs with output |
| `dach_tunnel` | current public URL |
| `dach_whoami` | the token's own rights and slot |

Deploy pattern the model should use: `dach_files_upload` a zip (or files),
then `dach_files_unzip`, then `dach_command_create` + `dach_command_run` to
build/start, and `dach_runs` to read the output back. (`dach_service_logs` also
works but needs an admin token — see above.)

## 4. Limits and safety

- Every tool call is a normal authenticated API call: CSRF-exempt bearer path,
  rights checked per call, file ops jailed to the token's root (no symlink or
  `../` escapes; zip members validated before anything is written).
- **Every call the model makes is audited.** Logins, denials, `systemctl` and
  docker actions, journal reads, preset runs and irreversible file deletes are
  written to the `dachboard.audit` logger, tagged with the token's identity, so
  "what did the model do" is answerable after the fact:

  ```
  journalctl -u dachboard | grep 'event='
  ```

  ```
  ts=1790267950 event=service_action unit=nginx.service action=restart exit=0 ip=203.0.113.7 actor=token#7 actor_via=token actor_admin=1 actor_slot=u-motya
  ts=1790267950 event=denied right=services_control ip=203.0.113.7 actor=bob actor_slot=u-bob
  ts=1790267950 event=bad_token right=overview ip=198.51.100.4
  ```

  `actor=token#<id>` plus `actor_via=token` identifies a machine caller; the
  line format is `ts= event= key=value`, one event per line, no passwords or
  file contents. Set `audit.file` in `config.yaml` to also keep it out of the
  panel's own journal.
- Uploads: `client_max_body_size 250m` on `/dash/` (nginx), 200 MiB per file
  on the backend (`max_upload_mb` in config.yaml), zips capped at 200 MiB
  unpacked / 5000 entries.
- The model never gets a raw shell. `dach_command_*` is argv-only, no shell
  expansion, and runs as the slot user (or root for admin tokens) with the
  same systemd-run caps as the UI.
- Revoking the token in the Users tab cuts the model off instantly. A
  presented-but-unknown token is audited as `bad_token`, so a revoked token
  still in use somewhere is visible rather than silent.

## 5. Test it

```bash
DACH_URL=http://127.0.0.1:8420 DACH_TOKEN=dach_... python3 mcp/e2e.py
```

Drives initialize → tools/list → whoami/overview/files/services/write/read/
delete over stdio and prints `E2E PASS`.
