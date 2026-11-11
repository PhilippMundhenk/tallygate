# ADR-0009: Web consoles via ttyd + tmux, proxied by control

- Status: Accepted
- Date: 2026-11-11

## Context

Setup (Claude login, Remote Control confirmation, git identity) and occasional maintenance need a shell in
the agent. `docker exec` from a web UI would require the Docker socket, which is equivalent to root on the
host.

## Decision

The agent runs three `ttyd` instances (rc, bash, claude), each attaching to a persistent tmux session,
protected by a shared credential and listening on the agent network only. The control plane reverse-proxies
`/term/<name>/` (HTTP + WebSocket) after session authentication and an Origin check, adding the ttyd
credential. Remote Control itself runs inside the `rc` tmux session, so its interactive prompts can be
answered from the browser.

## Consequences

- ✅ No Docker socket anywhere in the stack.
- ✅ Sessions survive browser reconnects (tmux).
- ⚠️ The ttyd credential is known to the agent (it runs ttyd); it only protects against other hosts on
  agent-net, which has no other members.
- ⚠️ ttyd is not packaged for Debian trixie; the image installs the pinned upstream static binary with a
  SHA-256 check.
