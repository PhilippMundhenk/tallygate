# User guide

The control UI is the operator's cockpit: approve connections, watch traffic, edit the policy, open
consoles into the agent, and run the setup wizard. Remote Control itself is used from the
[Claude app](https://claude.ai/download) or [claude.ai/code](https://claude.ai/code) as usual.

- [Approvals](#approvals)
- [Away mode and quiet hours](#away-mode-and-quiet-hours)
- [Log](#log)
- [Rules](#rules)
- [Console](#console)
- [Setup wizard](#setup-wizard)
- [Telegram approvals](#telegram-approvals)
- [Matrix approvals](#matrix-approvals)
- [Rule cookbook](#rule-cookbook)
- [Working with the agent](#working-with-the-agent)

## Approvals

![Approvals](images/approvals.png)

When the agent connects somewhere that no rule covers (and the default is `ask`), the connection is **held**
and appears here, on Telegram/Matrix if configured, and as a desktop notification while the tab is in the
background (turn these on once with **Enable browser notifications** in the Setup tab). The countdown shows
when it will be denied automatically.

| Button | Effect |
|---|---|
| Allow 2 min | This host:port for 2 minutes (covers follow-up connections of one operation) |
| Allow 1 h | This host:port for one hour |
| Always (host) | Permanent allow rule for exactly this host:port |
| Always (*.example.com) | Permanent allow rule for the registrable domain and all subdomains. The button shows the exact pattern; it is not offered when the name has no registrable domain of its own (e.g. `github.io`, IPs). |
| Deny | Deny for 2 minutes (the tool gets an error now; asking again later is possible) |
| Block forever | Permanent deny rule |

Every decision becomes a normal rule (tagged `[approval]`) that you can review or delete under **Rules**.
Before you click, check the **domain** line: the host is chosen by the agent, so `github.com.evil.example`
has the domain `evil.example`. Punycode names (`xn--…`) are flagged. Names are not resolved before your
approval, so IPs show as "not resolved yet". A destination you approve can still be refused by the hard
deny (LAN, host, metadata…). At most `max_pending` (10) requests wait at once; further unknown destinations
are denied immediately until you have answered.

## Away mode and quiet hours

When you cannot answer, the agent should not wait 60 seconds for every new destination, and your phone
should not buzz at night. The **Availability** card at the top of **Approvals** has two switches:

- **I'm away** (until you are back, for 1 h, 4 h or until 08:00): new destinations and grant requests that
  need your approval are refused at once. The agent gets a clear message (`operator away until 14:00:
  unknown destinations are refused without asking …`) instead of a held connection. Whatever was waiting
  for you when you switch it on is denied too.
- **Quiet hours** (e.g. 22:00–07:00, on the days you pick): the same, every day, without notifications.

Nothing is ever allowed automatically because you are away: away mode only turns *ask* into *deny*. Rules
that allow a destination keep working, and grants with `approval: auto` are still granted (and logged).
What was refused is listed under **Refused while you were away**, with *Allow 1 h* per destination, and sent
as one **digest** to Telegram/Matrix: when quiet hours end, when you are back, and while away every
`digest_minutes` (30). The header shows *away* or *quiet hours* on every tab. The agent sees the state in
`tallygate grants`.

Quiet hours use the gateway's time zone: set `TZ` (e.g. `TZ=Europe/Berlin` in `.env`) or `tz` in
`quiet_hours`. They can be preset in the gateway config (`quiet_hours`, see
[configuration](configuration.md#availability)); a change in the UI is stored and wins over the file.

## Grants

For access the normal rules would refuse, especially services on your home network, define **grants**:
named bundles with targets, read/write levels, LAN access, credentials and a duration. The agent requests
them (`tallygate request homeassistant --write --reason "…"`). Grant requests appear at the top of
**Approvals** and in Telegram/Matrix, where you can approve, approve read-only, or deny. The **Grants** tab
lists definitions and active grants (with *Revoke*), has an editor for UI-defined grants, and holds the
write-only secrets used for credential injection. Full guide: [grants.md](grants.md).

## Log

![Log](images/log.png)

Live view of every decision: connections (`conn`), approval requests (`ask`), blocked DNS lookups (`dns`), and
admin changes. Filter by text, hide DNS noise, or show only blocked entries. The **allow / deny** buttons
create a rule for exactly that host:port.

## Rules

![Rules](images/rules.png)

- **Mode**: what happens to unmatched destinations: `ask` (human in the loop), `deny` (strict allowlist) or
  `allow` (blocklist).
- **Quick actions** (top of the tab), see below.
- **Test a destination**: dry run against the current policy, including DNS resolution and hard deny.
- **Add rule**: host glob or CIDR, ports, note and optional TTL. New rules go to the top (first match wins).
- **Hard deny**: CIDRs that are never reachable. The built-in floor is read-only here (change it only in the
  gateway config file); you can add more, e.g. your Docker host's public IP.
- **Raw policy JSON**: edit everything at once (validated server-side).

### Quick actions and templates

| Action | What it does | Undo |
|---|---|---|
| Allow web for 15 min / 1 h | Adds the `open` preset (any public host, ports 80 and 443) with that time limit | *Active → Undo*, or wait |
| Allow all ports for 15 min | Adds the `internet` preset (any public host and port: SSH, databases, ...) | same |
| Unknown destinations: ask me / block / allow | Sets the mode (`ask`, `deny`, `allow`); changes nothing else | click another mode |
| Emergency stop | Revokes all active grants, denies everything waiting for approval (connections and grant requests), undoes the internet shortcuts, sets the mode `deny` and suspends automatic grant approval | set the mode again |
| Allow a device on the local network | Opens the grant editor with a LAN target (see below) | delete the grant |
| Templates | Allow what a tool ecosystem needs: Python, Node.js, Go, Rust, Debian/Ubuntu apt, container registries, Hugging Face. Until undone, for 1 h or for 1 day | *Undo* on the template |

Actions that are hard to take back (*allow (log only)*, *Emergency stop*, deleting a grant or a secret) ask
for confirmation in the page: the first click arms the button (*Confirm: …*) and says what will happen, a
second click within 8 seconds runs it. Escape or moving the focus elsewhere cancels. The panel updates in
place when the policy changes elsewhere, so a duration you picked and the keyboard focus stay where they were.

The **emergency stop** runs on the gateway, most important step first, and carries on when a step fails.
The panel lists every step with a ✔ or ✖, so you can see what did not work. Until you change the mode again,
grants with automatic approval need your approval like any other: the agent cannot switch its access back on
right after the stop. The Grants tab shows when this is in effect.

The mode buttons and *Save* in the Mode card change only the mode and the approval timeout, never the rules.
*Save additional hard deny* starts from the policy as it is on the gateway. *Replace policy* (raw JSON) refuses
to save when the policy was changed elsewhere after the text was loaded (another tab, a Telegram approval): it
keeps your text and marks it; *Reload from the gateway* fetches the current policy, a second *Replace policy*
overwrites on purpose.

All of them create normal rules at the top of the list, with ids like `python:pypi` and tagged `preset:<name>` in
the table, so you can see what a shortcut added. *Undo* removes exactly those rules. Rules you added yourself are
never touched. Because they sit at the top, **template and shortcut rules win over your own rules while they are
active, deny rules included**: a template that allows `*.quay.io` opens it even if you deny it further down. Undo
them, or pick a time limit. *Apply again* replaces the template's rules with the new time limit; the message shows
the time the gateway actually set.

**The local network** (private ranges, the Docker host, cloud metadata) is always blocked by the hard deny, and
no rule or shortcut can open it. This is deliberate: an agent with broad access to your network is the main
risk tallygate exists for. To let the agent reach one device, define a [grant](grants.md): exact host and port,
read or write, a time limit, and your approval each time. Grants created in the UI may only reach addresses
inside `grants_lan_allow` in the gateway config; the button explains what to add when that list is empty.

## Console

![Console](images/console.png)

| Console | Purpose |
|---|---|
| **rc** | The Remote Control server (tmux session). Answer first-start prompts here and watch connection status. |
| **bash** | A persistent shell in the agent (tmux), e.g. for `claude auth login`, `gh repo clone`, `git config`. |
| **claude** | An interactive Claude Code session in the terminal. |

Sessions persist when you close the tab. tmux basics: `Ctrl-b d` detaches, scroll with `Ctrl-b [`.

## Setup wizard

![Setup](images/setup.png)

Walks through gateway status, GitHub token (stored in the gateway only), Claude login, git identity,
Remote Control, and the isolation self-test. The status lines refresh whenever you open the tab.

## Telegram approvals

1. Create a bot: talk to [@BotFather](https://t.me/BotFather), `/newbot`, copy the token.
2. Send any message to your bot, then get your chat ID:
   `curl https://api.telegram.org/bot<TOKEN>/getUpdates` → `message.chat.id` (and `message.from.id`).
3. In `.env`: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_ALLOWED_USER_IDS=<your from.id>`.
4. `docker compose up -d control`.

Each request arrives with six buttons. After a decision the message is edited to show the outcome and who
decided. Taps from users not in the allowlist are answered with "Not authorised".

## Matrix approvals

1. Create a dedicated bot user on your homeserver (e.g. `@tallygate:example.org`) and get an access token
   (log in once with any client and copy the token, or use the login API).
2. Create an **unencrypted** room, invite the bot and join with the bot user.
3. In `.env`: `MATRIX_HOMESERVER`, `MATRIX_ACCESS_TOKEN`, `MATRIX_ROOM_ID` (`!…:example.org`),
   `MATRIX_ALLOWED_USERS=@you:example.org`.
4. `docker compose up -d control`.

Each request is posted as `🔐 #3 Agent wants to connect: host:port …` with pre-seeded reactions. Tap a
reaction (👍 2 min · ⏰ 1 h · ✅ always · 🌐 domain · 👎 deny · ⛔ block) or reply `allow 3`, `hour 3`,
`always 3`, `domain 3`, `deny 3` or `block 3`. The bot confirms the outcome in a reply.

## Rule cookbook

| Goal | Rule / setting |
|---|---|
| Strict allowlist, no prompts | Mode `deny`; add allow rules for what you need |
| Everything public allowed, but log it | Mode `allow` (hard deny still protects the LAN) |
| Allow a package ecosystem | *Quick actions → Templates* (Python, Node.js, Go, Rust, apt, container registries, Hugging Face) |
| Allow docs browsing for an hour | *Quick actions → Allow web for 1 h* (preset `open` with TTL `3600`) |
| Let the agent install Go modules today | *Templates → Go modules → for 1 day → Apply* |
| Block a noisy telemetry host quietly | `deny` rule for the host (no more prompts) |
| Reach a LAN database | `services:` entry with `allow_private: true` in `config/gateway.yaml` |
| SSH to one external host | Allow `host:22`; add `openssh-client netcat-openbsd` to `AGENT_EXTRA_PACKAGES`; then `ssh -o ProxyCommand='nc -X connect -x 172.31.10.2:3128 %h %p' host` |

## Working with the agent

- **Repositories**: `gh repo clone owner/repo /workspace/repo`. git uses HTTPS; the gateway injects your token.
- **Parallel sessions**: start more sessions on the same environment from the Claude app; set
  `RC_ARGS=--spawn worktree` to give each session its own git worktree.
- **Skills**: put them in `/home/agent/.claude/skills/<name>/SKILL.md` in the agent (the `agent-home` volume, owner uid 1000), e.g. with `docker compose cp`.
- **Toolchains**: add Debian packages via `AGENT_EXTRA_PACKAGES` and rebuild the agent. `pip install --user`
  and `npm install` work through the proxy if the registries are allowed.
