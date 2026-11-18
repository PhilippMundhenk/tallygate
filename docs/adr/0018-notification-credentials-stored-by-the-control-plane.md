# ADR-0018: Notification credentials may be stored by the control plane

- Status: Accepted
- Date: 2026-11-15
- Issue: #201
- Extends: ADR-0010 (outbound-polling bots), ADR-0015 (a backend-owned config)
- Amended: 2026-11-17 (#212, the notification buttons are stored in the same file)

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

## Amendment (2026-11-17, #212): the notification buttons

Which decisions a connection-approval notification offers is a setting of the same kind and lives in the same
file (`notify.json`, key `ask_actions`): a behaviour setting the UI owns (ADR-0015), written only by the
control plane, never sent to the agent or the gateway.

- **No environment variable.** Unlike the channel credentials there was no earlier way to set it, so there is
  one source: the UI. Without a saved value every channel keeps the buttons it had (Web Push: *Allow once*,
  *Deny*; Telegram and Matrix: *Allow once*, *Allow host permanently*, *Deny* first).
- **A closed list.** One to four of the gateway's fixed approval scopes (`once`, `hour`, `always`, `domain`,
  `deny`, `deny_always`), validated by the control plane on write and again on read: a file with anything else
  means the default, never a wider choice. Durations that need a number stay in the UI.
- **The setting chooses buttons, not authority.** What a tap may do is still decided by its action token
  (ADR-0010 for the bots, `app/webpush.py` for Web Push): bound to one request, one decision and one device,
  single use, short-lived. The control plane mints a token only for a button it offers, refuses a token whose
  button was switched off since, and offers no allow button for an IP-literal destination in Web Push.
- **Why here and not in the gateway's settings:** the gateway accepts every scope from the control plane
  anyway (the UI needs them); which of them a *notification* offers is a property of the notification
  channels, which only the control plane knows.

Consequence: ⚠️ with a permanent allow among the buttons, one tap on a notification (also on a lock screen
that shows buttons) adds a permanent rule. It is opt-in and confirmed; see threat model T47 and the residual
risk *Web Push metadata*.
