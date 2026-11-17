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
| [0007](0007-hard-deny-on-resolved-ips-and-pinning.md) | Hard-deny on resolved IPs and pinning to the checked IP | Accepted; the hard-deny part amended by 0019 (deciding on resolved IPs and pinning stay) |
| [0008](0008-approvals-as-rules-with-ttl.md) | Approvals are rules with TTL; hold connections while asking | Accepted |
| [0009](0009-web-console-via-ttyd-and-tmux.md) | Web consoles via ttyd + tmux, relayed by control | Accepted (revised) |
| [0010](0010-notifications-via-outbound-polling-bots.md) | Notifications via outbound-polling Telegram/Matrix bots | Accepted |
| [0011](0011-decide-on-names-before-resolving.md) | Decide on names before resolving them | Accepted; phase 2 amended by 0019 (the address rules of the list instead of the hard deny); holds without exception |
| [0012](0012-grants-for-scoped-temporary-access.md) | Grants for scoped, temporary access | Accepted; the LAN exemption amended by 0019 |
| [0013](0013-sni-and-host-bound-to-the-checked-name.md) | TLS SNI and HTTP Host are bound to the checked name | Accepted |
| [0014](0014-one-destination-model.md) | One destination model and one evaluation path | Accepted; §3 (never-reachable list), the `lan` part of §4 and the order of evaluation superseded by 0019 |
| [0015](0015-configuration-tiers-and-a-backend-owned-config.md) | Configuration tiers and a backend-owned settings file | Accepted; tier 3 narrowed by 0019 |
| [0016](0016-several-agents-with-their-own-policy.md) | Several agents with their own policy | Proposed |
| [0017](0017-admin-editable-deny-floor.md) | The admin may edit the deny floor from the UI | Superseded by 0019 |
| [0018](0018-notification-credentials-stored-by-the-control-plane.md) | Notification credentials may be stored by the control plane (write-only) | Accepted |
| [0019](0019-one-ordered-rule-list.md) | One ordered rule list, first match wins; built-in blocks are rules, only the stack itself is locked. Amended 2026-11-17: names pass two checks | Accepted (amended) |
