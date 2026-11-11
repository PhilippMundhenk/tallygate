# ADR-0004: Separate gateway and control plane containers

- Status: Accepted
- Date: 2026-11-11

## Context

The operator needs a UI, phone notifications, web consoles and a setup wizard. These have a much larger
attack surface (HTTP sessions, websockets, third-party APIs) than the enforcement logic.

## Decision

Two containers:
- **egress-gw**: enforcement, log, secrets, a bearer-token API bound to an internal `control-net` only.
- **control**: everything user-facing; calls the gateway API through an allowlist of methods/paths.

## Consequences

- ✅ A compromise of the UI or bot libraries does not give code execution in the enforcement point.
- ✅ The gateway has no outbound integrations beyond forwarding agent traffic.
- ✅ Control is stateless and can be restarted freely without affecting held connections' policy.
- ⚠️ A compromised control plane can still change policy via the API (it holds the token) — it is a trusted
  component; protect the UI with TLS and strong auth (OIDC via reverse proxy recommended).
