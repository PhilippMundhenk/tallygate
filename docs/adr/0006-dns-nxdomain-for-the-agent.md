# ADR-0006: Agent DNS always answers NXDOMAIN

- Status: Accepted
- Date: 2026-11-11

## Context

Even without a route, DNS can be an exfiltration channel if any resolver in the path forwards queries to
the internet (data encoded in query names). Docker's embedded resolver forwards external names to the
configured upstream servers.

## Decision

The agent's upstream DNS server is the gateway (`dns: [172.31.10.2]`), which runs mitmproxy's DNS mode and
answers **every** query with NXDOMAIN, logging the queried name. The proxy resolves names itself when it
connects upstream, so proxy-aware clients work normally.

## Consequences

- ✅ No DNS exfiltration path; attempts are visible in the log.
- ✅ Container names on Docker networks still resolve (handled by the embedded resolver).
- ⚠️ Tools that insist on resolving names locally before using a proxy fail — use `socks5h://`/proxy-side
  resolution or a service port.
