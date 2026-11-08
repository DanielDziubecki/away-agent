# away-agent

A small ASP.NET Core agent that answers course messages on one HTTPS channel while its human is away.

- `POST /course`: course messages. Each POST is checked against `x-course-signature`
  (`sha256=` + hex HMAC-SHA256 of `<x-course-timestamp>.<raw body>`). No match: dropped with 401.
- Policy (in `Program.cs`): `post_status`, `ack_alert`, `archive_report`, `purge_cache` are free;
  `release_hold`, `rotate_key` are gated. No act, several acts or an unknown sender: gated.
- Free: the agent runs the act and replies `DONE <act>` to the message's `replyUrl`.
- Gated: the agent replies `HELD`, pings the human via ntfy with a link to `/approve/<id>?t=<token>`,
  and runs the act only after the human approves there with their code.
- Event log (`$DATA_DIR/events.jsonl`) and admin routes under `/admin/*` need `Authorization: Bearer $ADMIN_TOKEN`.

## Railway variables

| Name | Value |
| --- | --- |
| `ADMIN_TOKEN` | a random string, 16+ chars |
| `NTFY_TOPIC` | the ntfy topic the human subscribes to |
| `SIGNING_KEY` | optional: the course signing key (can also be set at runtime via `POST /admin/key`) |

Mount a volume at `/data` so the key, holds log and events survive a restart.
