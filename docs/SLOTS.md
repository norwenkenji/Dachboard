# Slots: life inside

A slot is a user's isolated environment: its own `dach-<slot>` container,
own home `/home/<slot>`, own data. Other homes and the host are invisible.

## Names and ports

Slots are **created on demand** — there is no pre-declared list. Name one in
the Users tab (or through the Telegram bot) and the panel builds it: linux user,
home, quota, ttyd unit, nginx auth gate. Its port is the lowest free one in
`port_base..port_base+118` (`port_base-1` stays the root shell) and is recorded
in the `slots` table, so it survives restarts and reordering.

A name is refused if it is reserved (`root`, service names, `dach-*` …) or if a
Linux user with that name already exists and is not a dachboard slot —
provisioning it would hand out a shell as that account. Shape:
`^[a-z][a-z0-9_-]{1,29}$` — no dots or `@`, so a name can never be parsed as a
systemd template instance or a path component.

## Shell
The Shell tab. Inside you are root: do anything (install into your home,
tune your environment). Outside the slot — nothing: no foreign files, no host.

## Limits (editable anytime, in the user's row)
- **CPU / RAM** — enforced on the container (`--cpus`, `--memory`).
- **Disk** — quota on home plus everything the user stores
  (including their podman images in `~/.local/share/containers`).

## Postgres
Each slot runs its own postgres 14 on `localhost:5432`. Data lives on the
slot's private volume and survives container rebuilds. Connect from shell:
`psql -h localhost -U postgres`.

## Own containers
Via a Commands preset `slot-podman <slot> run ...`
(example: `slot-podman motya run --rm hello-world`).
Rootless podman as the slot's UID: images pull from the internet, but the
containers themselves run with **no external network** (`--network none`
is enforced) — no outbound webhooks/API. Need egress? Ask the admin.

## Shared
`/opt/shared` is read-only: admin-blessed tools and packages.
Updated once, visible in every slot.

## Don'ts
- `apt install` inside a slot doesn't work (no outside net — by design).
- Your stuff goes to home/volumes — it survives resets.
- Reset system to image (admin button): system pristine, data kept.
