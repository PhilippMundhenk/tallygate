# ADR-0005: Credential injection by selective TLS interception

- Status: Accepted
- Date: 2026-11-11

## Context

The agent needs GitHub access (clone, push, PRs). Putting a token into the agent means a prompt injection
can exfiltrate it. Docker Sandboxes and similar products inject credentials in a proxy instead.

## Decision

- The real token lives only in the gateway (`secrets.json`, set via the UI, never returned by the API).
- For configured hosts (`github.com`, `api.github.com`, `uploads.github.com`) the gateway intercepts TLS with
  its own CA (trusted by the agent) and **replaces** the configured header.
- TLS is intercepted whenever the CONNECT target (`orig_host`, recorded at decision time) is a configured
  host, whatever the client's SNI says, so the agent's own credentials are always stripped. Injection happens
  only if the HTTP `Host` matches that target too. Plain-HTTP requests are never injected.
- The agent holds placeholders (`GH_TOKEN`, a git credential helper) so tools behave as "logged in".
- Upstream TLS is verified normally (system trust store) against the configured hostname.

## Consequences

- ✅ The token cannot be read, logged or exfiltrated by the agent.
- ✅ SNI/Host spoofing to obtain the token is prevented (covered by e2e tests).
- ⚠️ The agent can still *use* the token for anything it permits — use fine-grained PATs scoped to the
  needed repositories.
- ⚠️ Claude's own OAuth login cannot be injected this way (Remote Control requires a full-scope login in the
  agent).
