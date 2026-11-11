# ADR-0009: Web consoles via ttyd + tmux, relayed by control

- Status: Accepted (revised 2026-11-11 after the security review, finding TG-01)
- Date: 2026-11-11

## Context

Setup (Claude login, Remote Control confirmation, git identity) and occasional maintenance need a shell in
the agent. `docker exec` from a web UI would require the Docker socket, which is equivalent to root on the
host.

The first version reverse-proxied ttyd's complete HTTP interface. That served HTML and JavaScript produced
by a process **inside the agent** on the control UI's origin: an agent that replaces ttyd with its own
server could run script in the operator's browser and use the UI's API (approve its own requests, rewrite
the policy, set secrets).

## Decision

The agent runs three `ttyd` instances (rc, bash, claude), each attaching to a persistent tmux session,
protected by a shared credential and listening on the agent network only.

The control plane **serves the console page itself** (`static/term.html` with a vendored, checksummed
xterm.js) and relays **only the ttyd WebSocket** at `/term/<name>/ws`, after session authentication and an
Origin check:

- browser → agent: the size handshake (control adds the ttyd credential), `0` input and `1` resize only;
- agent → browser: `0` terminal output only (ttyd title/preference messages are dropped);
- frames are size-limited in both directions; the console closes when the session ends.

No HTTP response from the agent ever reaches the browser. A strict CSP (`script-src 'self'`) applies to
every page, the console included. Remote Control itself runs inside the `rc` tmux session, so its
interactive prompts can be answered from the browser.

## Consequences

- ✅ No Docker socket anywhere in the stack.
- ✅ The agent cannot inject markup or script into the UI origin; the worst it can send is terminal output.
- ✅ Sessions survive browser reconnects (tmux).
- ⚠️ xterm.js is vendored and must be updated deliberately (`control/app/static/vendor/SHA256SUMS`).
- ⚠️ The ttyd credential is known to the agent (it runs ttyd); it only protects against other hosts on
  agent-net, which has no other members. Control treats whatever answers on those ports as untrusted.
- ⚠️ ttyd is not packaged for Debian trixie; the image installs the pinned upstream static binary with a
  SHA-256 check.
