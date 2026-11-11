# User guide

The control UI is the operator's cockpit: approve connections, watch traffic, edit the policy, open
consoles into the agent, and run the setup wizard. Remote Control itself is used from the
[Claude app](https://claude.ai/download) or [claude.ai/code](https://claude.ai/code) as usual.

- [Approvals](#approvals)
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
background. The countdown shows when it will be denied automatically.

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
- **Test a destination**: dry run against the current policy, including DNS resolution and hard deny.
- **Presets**: apply a preset's rules on top, optionally with a TTL (e.g. `open` for 900 s during setup).
- **Add rule**: host glob or CIDR, ports, note and optional TTL. New rules go to the top (first match wins).
- **Hard deny**: CIDRs that are never reachable. The built-in floor is read-only here (change it only in the
  gateway config file); you can add more, e.g. your Docker host's public IP.
- **Raw policy JSON**: edit everything at once (validated server-side).

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
| Allow a package ecosystem | `*.pythonhosted.org`, `pypi.org`; `registry.npmjs.org`; `proxy.golang.org`, `sum.golang.org`; `*.crates.io`, `static.crates.io` (port 443) |
| Allow docs browsing for an hour | Preset `open` with TTL `3600` |
| Block a noisy telemetry host quietly | `deny` rule for the host (no more prompts) |
| Reach a LAN database | `services:` entry with `allow_private: true` in `config/gateway.yaml` |
| SSH to one external host | Allow `host:22`; add `openssh-client netcat-openbsd` to `AGENT_EXTRA_PACKAGES`; then `ssh -o ProxyCommand='nc -X connect -x 172.31.10.2:3128 %h %p' host` |

## Working with the agent

- **Repositories**: `gh repo clone owner/repo /workspace/repo`. git uses HTTPS; the gateway injects your token.
- **Parallel sessions**: start more sessions on the same environment from the Claude app; set
  `RC_ARGS=--spawn worktree` to give each session its own git worktree.
- **Skills**: put them in `state/agent-home/.claude/skills/<name>/SKILL.md` (owner uid 1000).
- **Toolchains**: add Debian packages via `AGENT_EXTRA_PACKAGES` and rebuild the agent. `pip install --user`
  and `npm install` work through the proxy if the registries are allowed.
