# Rules by example

How the gateway decides, and about twenty worked examples: what a rule matches, what it does not, and the mistakes
that are easy to make. The reference for every field is in [configuration.md](configuration.md#policyyaml). For how rules fit
together with grants, read-only hosts and the never-reachable list, see [How access works](access.md).

- [How a connection is decided](#how-a-connection-is-decided)
- [Hosts](#hosts)
- [Ports](#ports)
- [IP addresses and CIDRs](#ip-addresses-and-cidrs)
- [Order, time limits and modes](#order-time-limits-and-modes)
- [The local network](#the-local-network)
- [Checking a rule before relying on it](#checking-a-rule-before-relying-on-it)

## How a connection is decided

For every connection the agent makes (`host:port`), in this order:

1. **Hard deny** on literal IPs: private ranges, loopback, link-local and cloud metadata, the Docker host. Never
   reachable, never asked, and no rule can change that.
2. **Rules on the name**, top to bottom: the first rule that matches decides. If no rule matches, the **mode**
   (`default`) decides: `ask` holds the connection and asks you, `deny` refuses it, `allow` lets it through
   (still logged). A `deny`, or an `ask` that you have not approved yet, means the name is never even resolved,
   so nothing leaks through DNS.
3. **Resolution**, only once the name is allowed: by a rule, by mode `allow`, by your approval (it adds a rule)
   or by learning mode.
4. **The same check again with the resolved IPs**: the hard deny first (a public name that resolves to
   `192.168.x.x` is still refused), then the rules top to bottom, now including `deny` rules on CIDRs, then the
   mode. The connection is pinned to the checked IP.

Two things come before the rules. A destination covered by an **active** [grant](grants.md) is handled by the
grant; one that a grant is defined for but that no rule allows is refused with a hint instead of a prompt.
During learning mode, the mode is replaced by "allow and record" for names on `learning_ports`; rules and the
hard deny still decide first.

The *Test a destination* box in the Rules tab runs exactly this for a host and port, and shows which step and
which rule decided.

## Hosts

| # | Goal | Rule | Matches | Does not match |
|---|---|---|---|---|
| 1 | One exact host | `allow github.com:443` | `github.com` | `api.github.com`, `github.com.evil.example` |
| 2 | A domain and all its subdomains | `allow *.github.com:443` | `github.com`, `api.github.com`, `a.b.github.com` | `notgithub.com`, `github.com.evil.example` |
| 3 | Only subdomains, not the domain | `allow ?*.github.com:443` | `api.github.com` | `github.com` |
| 4 | Every public host | `allow *:443` | any name or public IP on 443 | anything on another port; the local network (hard deny) |
| 5 | Block a telemetry host quietly | `deny telemetry.example.org` (all ports) | that host on every port, no prompt | `www.example.org` |
| 6 | Block a whole domain except one host | 1. `allow docs.example.org:443`  2. `deny *.example.org` | `docs.example.org` is allowed (rule 1 comes first), the rest of `example.org` is denied | – |
| 7 | Ask every time for one domain, even in `allow` mode | `ask *.pastebin.com` | prompts for `pastebin.com` and its subdomains | – |

**Common mistakes**

- `example.com` does **not** cover `www.example.com`. Use `*.example.com` for both.
- `*example.com` (without the dot) also matches `evilexample.com`. Always write `*.example.com`.
- Host patterns compare names, not ownership: `github.com.evil.example` belongs to `evil.example`. The approval
  prompt shows the registrable domain for this reason.
- Names are case-insensitive, and a trailing dot (`github.com.`) is ignored.
- Apart from the `*.domain` form, a host pattern is a shell-style glob: `*` also matches dots (`api.*.com` covers
  `api.a.b.com`), `?` is exactly one character and `[abc]` one of a set. Example 3 uses this.

## Ports

| # | Goal | Port field | Matches | Does not match |
|---|---|---|---|---|
| 8 | HTTPS only | `443` | 443 | 80, 8443 |
| 9 | HTTP and HTTPS | `80,443` | 80, 443 | 8080 |
| 10 | A range | `8000-8100` | 8000, 8042, 8100 | 7999, 8101 |
| 11 | Ranges and single ports | `22,8000-8100` | 22, 8050 | 443 |
| 12 | Every port | `*` (or leave empty) | all | – |

The UI refuses anything else (`443,`, `https`, `44 3`) with a message instead of guessing.

This is the syntax of the port field in the UI. In `policy.yaml` and the API, `port` is a number (`443`), a
range as a string (`"8000-8100"`), `"*"` or a list of those (`[22, "8000-8100"]`); leave it out for every port.

## IP addresses and CIDRs

| # | Goal | Rule | Effect |
|---|---|---|---|
| 13 | One public IP | `allow 203.0.113.10/32:443` | the agent may connect to `203.0.113.10:443` **by IP**. A name that resolves to this IP is *not* allowed by it (step 2 decides names). |
| 14 | Block a hosting provider's range | `deny 198.51.100.0/24` | refuses IPs in the range, **and** names that resolve into it, as long as the rule is **above** the rule that allows the name (first match wins) |
| 15 | The same IP written as IPv6 | (nothing to do) | IPv4-mapped forms like `[::ffff:203.0.113.10]` are treated as the IPv4 address, so rule 13 and 14 cover them. tallygate has no IPv6 egress. |

The addresses in these examples are placeholders from the documentation ranges. Those ranges are part of the
built-in hard deny, so the rules do nothing as written: put a real public address or range in their place.

A CIDR `deny` rule is a normal rule in the list. Approvals are added at the top, so an *Always* approval for a
name given later sits above it and wins. For a block that no rule can override, add the range to `hard_deny`
in the policy instead.

Why CIDR *allow* rules only cover IP literals: if they also covered names, the gateway would have to resolve
every name to check them, and an unknown name like `<secret>.attacker.example` would leak through DNS before you
were asked.

## Order, time limits and modes

| # | Goal | How |
|---|---|---|
| 16 | Allow something for one hour | add the rule with *TTL* `3600` (a UI field; the API takes `expires`, a unix time), or approve the prompt with *More → Allow 1 h* |
| 17 | Open the web for 15 minutes during setup | *Shortcuts → Allow web for 15 min* |
| 18 | Strict allowlist, no prompts | mode `deny`, then allow rules for what is needed (or *Shortcuts → Tool ecosystems*) |
| 19 | Everything public allowed, but logged | mode `allow`; add `deny` or `ask` rules for exceptions |
| 20 | Let one rule win over another | it must be **above** it: new rules, approvals, accepted suggestions and shortcuts are added at the top; rules saved from learning mode are added at the bottom |

Rules from approvals are tagged `approval`, rules from shortcuts `preset:<name>`, rules saved
from learning mode `learning` and accepted suggestions `suggestion`. Expired rules are ignored and cleaned up.

## The local network

No rule opens the local network, the Docker host or cloud metadata addresses: that is the hard deny, and it is
checked again after resolution. For one device use a [grant](grants.md) (exact host and port, read or write, a
time limit, and your approval), or a [service port](configuration.md#configgatewayyaml) with
`allow_private: true` for a fixed TCP service.

| # | Goal | How |
|---|---|---|
| 21 | Let the agent read Home Assistant's API | a grant with target `http://ha.lan:8123`, paths `/api/*`, level `read` (see [grants.md](grants.md)) |
| 22 | Reach a database on the LAN | a service port: `{name: pg, listen: 15432, target: db.lan:5432, allow_private: true}`; the agent connects to `egress-gw:15432` |

## Checking a rule before relying on it

*Rules → Test a destination* with host and port shows:

- the decision (`ALLOW`, `DENY`, `ASK`),
- what decided: the hard deny (and which range), a rule (its number and pattern), or the mode,
- the resolved IPs, or "not resolved" when the decision was made on the name.

The same check is available as `POST /test` on the gateway API ([api.md](api.md)). It checks the rules, the
mode and the hard deny only: it never asks, and it does not take active grants, learning mode or the
`allow_private` exception of a service port into account.
