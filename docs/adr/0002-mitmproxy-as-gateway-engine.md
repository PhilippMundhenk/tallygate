# ADR-0002: mitmproxy as the gateway engine

- Status: Accepted
- Date: 2026-11-11

## Context

The gateway must: act as HTTP CONNECT proxy, SOCKS5 server and TCP port forwarder; make an asynchronous
decision per connection that may wait up to minutes for a human; selectively intercept TLS for
credential injection while passing all other TLS through untouched; answer DNS.

Options considered: Squid (+ external ACL helper), Envoy (+ ext_authz), a custom Go/Python proxy, mitmproxy.

## Decision

Use **mitmproxy** (pinned, ≥ 12) with a Python addon. One process runs `regular`, `socks5`, `dns` and
`reverse:tcp://…` modes on one event loop; the addon implements policy, approvals, injection and the API.

## Consequences

- ✅ Async hooks make "hold a connection until approved" trivial and cheap.
- ✅ Per-connection TLS decision (`tls_clienthello` → `ignore_connection`) gives passthrough by default and
  interception only where configured.
- ✅ All protocol modes share the same hook surface and log.
- ✅ Mature, widely audited TLS stack; small amount of own code (~400 lines for the gateway).
- ⚠️ Python performance: fine for one agent; not designed as a high-throughput corporate proxy.
- ⚠️ We depend on mitmproxy hook semantics (`server_connect`, `tls_clienthello`); pinned version plus e2e
  tests guard upgrades.
- ⚠️ mitmproxy aborts startup on error-level logs from addons — startup diagnostics use warning level.
