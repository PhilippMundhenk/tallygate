# ADR-0018: Notification credentials may be stored by the control plane

- Status: Accepted
- Date: 2026-11-15
- Issue: #201
- Extends: ADR-0010 (outbound-polling bots), ADR-0015 (a backend-owned config)

## Context

The notification channels (Telegram, Matrix, ntfy, Gotify, Pushover) were configured only through environment
variables. Setting one up meant editing `.env` and restarting the control container, and the Setup tab could
only say "environment-only". In the UI review (#201) this was the one part of the first-run flow that could not
be finished in the browser.

Configuring them in the UI means the control plane has to **keep** bot tokens, which until now it only read
from its environment. The control plane already keeps secrets of the same weight in its data volume (the
session secret, the password hash, the Web Push signing key and the push subscriptions), and it is the
component that uses these tokens anyway.

## Decision

- Notification credentials may be stored by the control plane, in one backend-owned file in the control data
  volume: `notify.json`, mode 0600, written atomically. Nothing else writes it.
- **Write-only.** The API (`GET /api/notify/config`) returns for every field whether it is set and where it
  comes from (`ui`, `environment`, `unset`), and the value of non-secret fields (URLs, chat and room ids,
  allowed users). A token is never returned, logged or put into an error message. In the UI a password field
  is always empty; leaving it empty keeps the stored token.
- **Precedence, per field:** a value saved in the UI overrides the environment variable of that field; a field
  the UI does not set falls back to the environment. Removing a channel's override returns the whole channel
  to the environment. The environment keeps working unchanged for installations that prefer it.
- **A token stays with its server.** When the URL of a channel changes (Matrix homeserver, ntfy topic URL,
  Gotify server), the token has to be entered again, whether it was stored in the UI or comes from the
  environment. Otherwise a UI session could point an existing token at a server of its choice and read it
  there, which would undo "write-only". The Telegram and Pushover API hosts are not UI settings.
- **ADR-0010 stays in force.** Telegram and Matrix decide approvals, so saving them without allowed user ids /
  allowed Matrix users is refused, and the notifier still switches such a channel off if it finds one. Bots
  still only poll outwards; nothing new listens.
- **Applied without a restart.** The notifier re-reads its settings and restarts the poll loop of a channel
  only when that channel changed; the old loop is cancelled and awaited before the new one starts. The event
  worker, its queue and the open prompts are not touched.
- **Never sent to the agent or the gateway.** The file lives in a volume only the control container mounts.
  The routes need a UI session and the CSRF header, like every state-changing control API call. Who changed
  which fields is logged; values are not.
- If the data volume is not writable, the store is read-only: the UI says so and the channels stay
  environment-only, as Web Push is off in that case.

## Consequences

- ✅ All channels can be set up, tested and removed from the Setup tab, without a restart.
- ✅ No new exposure towards the agent: it cannot reach the control plane, and the gateway never sees the file.
- ⚠️ A stolen UI session can now change where notifications go, or switch a channel off. It cannot read the
  tokens, and it cannot approve through a new Telegram/Matrix channel without also controlling that chat
  account; but it could add its own. A UI session can already approve everything directly, so this does not
  add authority (threat model T44).
- ⚠️ The control data volume now holds bot tokens in plain text (mode 0600, the container's own user), next to
  the session secret. Back it up and protect it like `.env`.
- ⚠️ Two sources for one setting. The UI shows the source of every channel and field so it stays clear which
  one is in effect.
