# Security policy

sluicegate is a security boundary: a bypass of the egress policy, a way for the agent to reach the
management plane, or a leak of injected credentials is a vulnerability.

## Reporting

Please report vulnerabilities **privately** via
[GitHub Security Advisories](../../security/advisories/new) ("Report a vulnerability").
Do not open public issues for security problems.

Include: affected version/commit, a description, reproduction steps, and the impact you see.
You can expect an acknowledgement within 7 days and a fix or mitigation plan within 30 days for
confirmed issues.

## Scope

In scope:
- Agent reaching any destination the policy does not allow (incl. DNS, IPv6, UDP, LAN, metadata IPs)
- Agent reaching the gateway API, the control UI, or other containers' management ports
- Disclosure of injected secrets to the agent or to non-configured hosts
- Authentication/CSRF/session flaws in the control UI; approval spoofing via Telegram/Matrix
- Container escapes made possible by sluicegate's configuration

Out of scope (documented limitations, see [docs/threat-model.md](docs/threat-model.md)):
- Data exfiltration through destinations you have allowed
- Kernel/container-runtime vulnerabilities (shared kernel)
- Misuse of an injected token's legitimate permissions

## Supported versions

Only the latest release receives security fixes.
