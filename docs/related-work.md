# Related work and comparison

sluicegate draws on ideas from several projects. This page compares protections, to help decide what fits.

| | sluicegate | Anthropic dev container | Docker Sandboxes (sbx) | Moat | gw0/docker-claude-code |
|---|---|---|---|---|---|
| Isolation boundary | Container (+ optional gVisor) | Container | **microVM** | Container (Docker, Apple containers, gVisor) | Container (+ gVisor, seccomp profile) |
| Egress enforcement | Gateway outside the agent; agent on an internal network | iptables inside the container | Host-side proxy | TLS-intercepting proxy | None by default (bwrap sandbox for Bash) |
| Policy granularity | Domain/IP/CIDR/port, first match, TTLs | IP allowlist resolved at startup | Domain policy (allow/deny) | Host allowlist (strict/permissive) | – |
| Human in the loop | ✅ hold + approve (web, Telegram, Matrix) | – | – | – | – |
| LAN protection | Hard deny on resolved IPs + pinning | Depends on the allowlist | ✅ | Depends on the policy | – |
| DNS exfiltration | Blocked (NXDOMAIN) | Open | Via policy | – | Open |
| Credentials kept out of the agent | ✅ GitHub (configurable) | – | ✅ AI providers | ✅ many providers | – |
| Non-HTTP | SOCKS5, CONNECT, service ports | iptables rules | Explicit rules | Service sidecars | Open |
| Web UI / consoles | ✅ / ✅ | VS Code | CLI / TUI | CLI | – |
| Remote Control focus | ✅ (server mode, setup wizard) | – | – | – | – |
| Needs root/capabilities in the agent | No | `NET_ADMIN` at start | n/a (VM) | No | No |

Links:
- Anthropic: [Claude Code development containers](https://docs.anthropic.com/en/docs/claude-code/devcontainer)
- Docker: [Docker Sandboxes security model](https://docs.docker.com/ai/sandboxes/security/)
- Moat: [majorcontext.com/moat](https://majorcontext.com/moat/)
- gw0: [github.com/gw0/docker-claude-code](https://github.com/gw0/docker-claude-code)
- Egressor (local egress monitor for developer tools): [github.com/ehsaniara/egressor](https://github.com/ehsaniara/egressor)

**When to choose what:**
- Want the strongest isolation on a workstation and can use Docker Desktop/sbx → Docker Sandboxes.
- Want an always-on server with Remote Control, phone approvals and a LAN you care about → sluicegate.
- Want VS Code-integrated, per-project containers → Anthropic's dev container.
