# ADR-0003: One enforcement hook for all protocols

- Status: Accepted
- Date: 2026-11-11

## Context

Policy must apply identically to HTTP proxy CONNECT, absolute-form plain HTTP, SOCKS5 and TCP service
ports. Implementing checks per protocol (e.g. in `http_connect` and a separate SOCKS hook) risks
inconsistencies and bypasses.

## Decision

Enforce exclusively in mitmproxy's `server_connect` hook, which fires before **every** upstream connection
regardless of the client-side protocol. Setting `server.error` aborts the connection.

## Consequences

- ✅ One code path, one log format, one approval mechanism for all protocols.
- ✅ New mitmproxy modes are automatically covered.
- ⚠️ mitmproxy only logs an exception raised in a hook and continues, so a crashing hook would let the
  connection through. Every hook is wrapped to fail closed (refuse the connection or kill the flow).
- ⚠️ `connection_strategy=eager` is required so that CONNECT targets are evaluated at CONNECT time (and the
  original host is known before the TLS ClientHello arrives).
