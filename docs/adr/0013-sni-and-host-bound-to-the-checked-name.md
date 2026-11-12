# ADR-0013: TLS SNI and HTTP Host are bound to the checked name

- Status: Accepted
- Date: 2026-11-12

## Context

The gateway decides on the CONNECT name (or the URL host of a plain-HTTP proxy request), pins the checked
IP and, for most hosts, passes TLS through. On a shared CDN (Fastly, Cloudflare, CloudFront) or any
virtual-host server, the site is picked by the TLS SNI and the HTTP `Host`, not by the IP. An agent could
CONNECT to an allowed name such as `pypi.org` and send the SNI or `Host` of any other site on the same CDN
(domain fronting). That made most of the web reachable through a few allowed names (#57).

## Decision

- **TLS passthrough only with the checked SNI.** In `tls_clienthello`, the SNI (lower case, trailing dot
  removed) must equal the checked name. A missing SNI, another name or an ECH outer name is refused.
- **IP literals.** A CONNECT to an IP has no name to compare. No SNI is normal and passes. An SNI name passes
  only if the rules allow that name by itself (`evaluate_name`, no CIDR rules, no asking) on that port: the
  connection then reaches nothing that the rules do not allow anyway. An IP allowed by a CIDR rule therefore
  does not open every site behind it.
- **Refusing TLS.** mitmproxy's TLS hooks cannot close a connection. A refused connection is marked, and
  `tls_start_client` / `tls_start_server` hand mitmproxy a TLS object without certificate and SNI, so both
  handshakes fail. The fail-closed wrapper does the same when `tls_clienthello` raises.
- **Host binding.** Every HTTP request the gateway parses is refused with `403` if its `Host` (or
  `:authority`) is not the checked target: plain-HTTP proxy requests, plain HTTP inside a CONNECT tunnel or
  over SOCKS5, and intercepted TLS. A request without `Host` goes to the upstream's default site and passes.
  Grants already had this check; raw TCP grants stay untouched.

## Consequences

- ✅ An allowed name reaches only that name, also on shared CDNs.
- ✅ Intercepted hosts (injection, read-only) can no longer be used to front other sites either.
- ⚠️ Clients that send no SNI to a hostname, or an SNI that differs from the CONNECT name (some
  `--connect-to` setups), are refused. Clients that use ECH are refused on passthrough hosts, because the
  outer SNI is not the checked name.
- ⚠️ A refused TLS connection shows up in the client as a handshake failure, not as an HTTP error. The
  reason is in the event log.
