# Architecture decision records

Format: [MADR](https://adr.github.io/madr/)-style, one decision per file. Status values: *Accepted*,
*Superseded by …*, *Deprecated*.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-network-topology-instead-of-iptables.md) | Enforce isolation via Docker network topology, not iptables | Accepted |
| [0002](0002-mitmproxy-as-gateway-engine.md) | mitmproxy as the gateway engine | Accepted |
| [0003](0003-single-enforcement-hook.md) | One enforcement hook for all protocols (`server_connect`) | Accepted |
| [0004](0004-separate-gateway-and-control-plane.md) | Separate gateway and control plane containers | Accepted |
| [0005](0005-credential-injection-by-tls-interception.md) | Credential injection by selective TLS interception | Accepted |
| [0006](0006-dns-nxdomain-for-the-agent.md) | Agent DNS always answers NXDOMAIN | Accepted |
| [0007](0007-hard-deny-on-resolved-ips-and-pinning.md) | Hard-deny on resolved IPs and pinning to the checked IP | Accepted |
| [0008](0008-approvals-as-rules-with-ttl.md) | Approvals are rules with TTL; hold connections while asking | Accepted |
| [0009](0009-web-console-via-ttyd-and-tmux.md) | Web consoles via ttyd + tmux, relayed by control | Accepted (revised) |
| [0010](0010-notifications-via-outbound-polling-bots.md) | Notifications via outbound-polling Telegram/Matrix bots | Accepted |
| [0011](0011-decide-on-names-before-resolving.md) | Decide on names before resolving them | Accepted |
| [0012](0012-grants-for-scoped-temporary-access.md) | Grants for scoped, temporary access | Accepted |
