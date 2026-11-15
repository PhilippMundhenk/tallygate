# Rules by example

How the gateway decides a destination, and worked examples: what a rule matches, what it does not, and the
mistakes that are easy to make. This page is the reference for the decision itself; the other pages link here
instead of repeating it. The fields of a rule are in [configuration.md](configuration.md#policyyaml), the
decision behind the model in [ADR-0019](adr/0019-one-ordered-rule-list.md). For how rules fit together with
grants and the limits inside a destination, see [How access works](access.md).

- [How a destination is decided](#how-a-destination-is-decided)
- [Name rules and address rules](#name-rules-and-address-rules)
- [Why a name rule cannot open a blocked range](#why-a-name-rule-cannot-open-a-blocked-range)
- [Built-in blocks](#built-in-blocks)
- [Locked ranges](#locked-ranges)
- [Order of the list](#order-of-the-list)
- [Marks in the table](#marks-in-the-table)
- [Hosts](#hosts)
- [Ports](#ports)
- [IP addresses and ranges](#ip-addresses-and-ranges)
- [Time limits and the default](#time-limits-and-the-default)
- [The local network: worked examples](#the-local-network-worked-examples)
- [When a name is resolved](#when-a-name-is-resolved)
- [Checking a rule before relying on it](#checking-a-rule-before-relying-on-it)

## How a destination is decided

There is **one ordered rule list**. It is checked from top to bottom, the **first matching rule decides**, and
the **default** at the end applies when no rule matches. This is how pfSense, ufw, iptables and cloud security
groups work, and the *Destinations* tab shows the list in exactly this order:

| Position | What | Can you change it? |
|---|---|---|
| top | **Rules**: your own rules, approvals, shortcuts, rules saved from learning mode | add, edit, move, delete |
| below them | **Built-in blocks**: `deny` rules for the local network, loopback, cloud metadata and other special ranges, plus the `never` entries of the gateway config | they are ordinary rules: edit, move, delete, restore ([Built-in blocks](#built-in-blocks)) |
| last rows | **Locked ranges**: the tallygate stack's own networks and the gateway's own listeners | no ([Locked ranges](#locked-ranges)) |
| last line | **Default** ("Everything else"): `ask`, `deny` or `allow` | under *Settings → Mode* |

A destination is a name or an IP address, a port, and the addresses the name resolves to. The gateway
resolves the name itself and connects to exactly the address it checked.

1. **Locked ranges first.** An address in a locked range is denied before the list is looked at, whatever
   the list says.
2. **The list is walked once for every resolved address** (for an IP destination: for that address). A rule
   is skipped when its port does not match or its time limit has passed.
3. **The most restrictive result wins** over all addresses: `deny` before `ask` before `allow`. A name with
   one public and one local address is denied if the local one is blocked.
4. **Nothing matched: the default.** `ask` holds the connection and asks you, `deny` refuses it, `allow` lets
   it through (still logged).

Two things stand beside the list. An **active [grant](grants.md)** behaves like rules at the very top for
its targets. **Learning mode** replaces the default with "allow and record" for names on its ports; every
rule, the built-in blocks among them, still decides first.

## Name rules and address rules

A rule matches either a name or an address, never both, and the two kinds behave differently on purpose.

| | Address rule | Name rule |
|---|---|---|
| Matches | an IP address or a range (CIDR), e.g. `192.168.44.1/32`, `198.51.100.0/24` | a host pattern, e.g. `github.com`, `*.example.com`, `*` |
| Matches when | the address being checked is inside the range, however the destination was named (by IP, or by a name that resolves there) | the name the agent asked for matches the pattern |
| `deny` | final | final |
| `allow`, `ask` | **final**: the first matching address rule decides | **provisional**: the walk continues below it, looking only at address rules with `deny`. If one contains the address, the result is `deny` |

So, as in other firewalls:

- An address `allow` placed **above** a range block opens that address.
- A range block placed above it closes part of it again. Layers work ([example b](#b-open-a-24-but-keep-one-host-blocked)).
- A name rule decides whether the name may be used. It never decides that an address inside a blocked range
  may be reached.

One consequence to know: below a name rule that matched with `allow` or `ask`, an address `allow` no longer
counts, only address `deny` rules do. An address rule opens an address only when it stands **above every
name rule that matches the destination**. See [Order of the list](#order-of-the-list).

An IP address typed into the *Host* field of the rule form is stored as an address rule.

## Why a name rule cannot open a blocked range

A name points wherever the owner of its DNS zone says. If `allow *.example.com` could override the block of
`192.168.0.0/16`, whoever controls `example.com` could point `x.example.com` at `192.168.44.1` and walk the
agent into your local network (DNS rebinding). Only a rule that names the **address** opens it. Squid
(`dstdomain` against `dst`) and Smokescreen draw the same line.

When it happens the gateway says so, in the same words, in the log, in *Test a destination* and in the error
the agent gets (`egress policy: blocked (…)`):

```text
name allowed by rule 3f9a1c2e, but it resolves to 192.168.44.1, inside blocked range 192.168.0.0/16
(rule block-192.168.0.0_16): add an allow for the address above that rule
```

Variants of the same message:

| Part | When |
|---|---|
| `name matched by rule …` | the name rule says `ask` (or you approved the name and it still resolves into the block) |
| `the address 192.168.44.1 is inside blocked range …` | the destination was the IP itself and a `*` name rule matched it |
| `… the allow for the address (rule dev) stands below rule 3f9a1c2e: move it above` | an address rule for it exists, but below the name rule |
| `grant ha: name allowed by the grant, but it resolves to …: set a fixed address on the grant target` | a grant target that is only a name ([grants.md](grants.md#local-targets-and-name-only-targets)) |

What to do:

- **You want the agent to reach that address:** add an allow rule for the address and port
  ([example a](#a-allow-one-local-device)). New rules are added at the top, so it stands above the block and
  above the name rule. If the rule exists already, use *Move up* until it is above the name rule.
- **You did not expect the name to resolve there:** do nothing. The block did its job; look at who controls
  that name.

The *Destinations* table also [marks the name rule](#marks-in-the-table), so you see it without reading the
log.

## Built-in blocks

On the first start the gateway adds these ranges as ordinary `deny` rules at the bottom of the list (source
*built-in block*, ids like `block-192.168.0.0_16`). Together with the name/address distinction above they
keep the agent out of your network even when a rule such as `allow *:443` is active.

| Range | What it is | What the block protects |
|---|---|---|
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | private networks (RFC 1918) | your LAN: router, NAS, Home Assistant, other machines; Docker's default bridges are in `172.16.0.0/12` |
| `127.0.0.0/8`, `::/96` | loopback (`::/96` holds `::1`, the unspecified address and the old IPv4-compatible form) | services inside the gateway container |
| `0.0.0.0/8` | "this network"; `0.0.0.0` reaches the local machine on Linux | the same |
| `169.254.0.0/16`, `fe80::/10` | link-local | the cloud metadata address `169.254.169.254` (instance credentials), neighbours on the same segment |
| `100.64.0.0/10` | carrier-grade NAT; also used by overlay VPNs | your provider's internal network, VPN peers |
| `fc00::/7`, `fec0::/10` | IPv6 unique local and the old site-local range | an IPv6 LAN |
| `224.0.0.0/4`, `ff00::/8` | multicast | discovery protocols on the local segment |
| `240.0.0.0/4` | reserved, incl. broadcast | – |
| `64:ff9b::/96`, `64:ff9b:1::/48`, `2002::/16`, `2001::/32`, `::ffff:0:0/96` | NAT64, 6to4, Teredo, IPv4-mapped: IPv6 forms that embed an IPv4 address | a side door to the IPv4 ranges above |
| `192.0.0.0/24`, `192.88.99.0/24`, `198.18.0.0/15`, `100::/64` | protocol assignments, the old 6to4 relay, benchmarking, discard | not valid public destinations |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` | documentation ranges | not valid public destinations |

`never` entries in the gateway config ([configuration.md](configuration.md#configgatewayyaml)) are added the
same way (source *never (config file)*), for example the public address of a VPS that runs the stack.

They are rules like any other:

- **Edit, move or delete** them in the table. Deleting one asks for confirmation and names the consequence.
  A deleted block **stays deleted** across restarts and upgrades.
- **Restore built-in blocks** (button above the table) adds back, at the bottom, every built-in or config
  block that is no longer in the list as a permanent `deny` for exactly that range on every port. A block you
  narrowed (a port, a time limit, another action) counts as missing and gets a fresh rule next to it.
- They never show up as "unused" in *Rule usage*.

Prefer an allow rule above a block over deleting the block: without the block of `192.168.0.0/16`, every name
rule and the *Allow web* shortcut reach whatever a name resolves to in that range, and learning mode or the
default `allow` do too. See the [threat model](threat-model.md#residual-risks).

## Locked ranges

Two things are not in the list and cannot be opened by any rule, grant or API call:

- the **stack's own networks** (`GW_INTERNAL_NETS`, set in `compose.yaml`: the networks the three containers
  talk on), and
- the **gateway's own listeners** (management API, grant API, proxy and SOCKS ports).

They are checked before the list is walked, for every resolved address, on every path (proxy, SOCKS, service
ports, grants). The table shows them as the last rows before the default, marked *locked*, with no actions.
The reason is structural: an agent that could reach the gateway API or the control UI could delete every
other rule. A denial reads `locked: 172.31.11.2 belongs to the tallygate stack itself (172.31.11.0/24)` or
`locked: <address>:<port> is the gateway itself`.

## Order of the list

| What | Where it is added |
|---|---|
| a rule from the form on *Destinations*, a rule from the log (*allow / deny*) | top |
| an approval (*Allow for 5 min*, *Allow \*.domain permanently*, *Deny permanently*, …) | top |
| a shortcut (*Allow web for 15 min*, a tool ecosystem) and an accepted suggestion | top |
| rules saved from learning mode | below your rules, above the built-in blocks |
| built-in and config blocks, restored blocks | bottom |

**Move up** and **Move down** on a row move a rule one place in this order; every rule can be moved, the
built-in blocks too. The API equivalent is `POST /destinations/{id}/move` ([api.md](api.md)).

Because approvals and shortcuts are added at the top, they win over your own rules while they exist, name
`deny` rules included. Two things they cannot do:

- A name rule at the top still cannot open a blocked range below it.
- An approval for an **IP address** adds an address rule for exactly that address and port: a rule that
  names the address. An IP address inside a blocked range is denied without a prompt, so this only concerns
  addresses that no block covers.

And one thing to watch: a name rule at the top that matches a destination (an approval for the name, or
`allow *:443` from *Allow web*) makes an address `allow` further down stop counting for it. The connection is
then denied by the block with `… stands below rule …: move it above`. Move the address rule above the name
rule, or wait for the shortcut to end.

## Marks in the table

The *Destinations* table tells you when a rule cannot do what it says:

| Mark | Meaning | What to do |
|---|---|---|
| **blocked by a range rule below** (with *last:* address, range, blocking rule, time and count) | A name rule allowed or matched a name, but the address it resolved to is inside an address `deny` rule further down, so the connection was denied. Recorded from real traffic. | If the address should be reachable, add an allow rule for it. If not, nothing: the name resolved somewhere it should not. |
| **never reached** (*covered by rule … above it*) | An address rule that an earlier permanent address rule covers completely (range and ports), so it can never decide. Shown at once, without traffic. | Move it above the covering rule, or delete it. |

An address `deny` that stands below a wider address `allow` is not marked *never reached*: it still stops a
name rule above both of them.

## Hosts

| # | Goal | Rule | Matches | Does not match |
|---|---|---|---|---|
| 1 | One exact host | `allow github.com:443` | `github.com` | `api.github.com`, `github.com.evil.example` |
| 2 | A domain and all its subdomains | `allow *.github.com:443` | `github.com`, `api.github.com`, `a.b.github.com` | `notgithub.com`, `github.com.evil.example` |
| 3 | Only subdomains, not the domain | `allow ?*.github.com:443` | `api.github.com` | `github.com` |
| 4 | Every public host | `allow *:443` | any name or public IP on 443 | anything on another port; addresses inside a blocked range |
| 5 | Block a telemetry host quietly | `deny telemetry.example.org` (all ports) | that host on every port, no prompt | `www.example.org` |
| 6 | Block a whole domain except one host | 1. `allow docs.example.org:443`  2. `deny *.example.org` | `docs.example.org` is allowed (rule 1 comes first), the rest of `example.org` is denied | – |
| 7 | Ask every time for one domain, even with the default `allow` | `ask *.pastebin.com` | prompts for `pastebin.com` and its subdomains | – |

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

## IP addresses and ranges

| # | Goal | Rule | Effect |
|---|---|---|---|
| 13 | One public IP | `allow 198.51.100.10/32:443` | The agent may connect to `198.51.100.10:443`, by IP or through any name that resolves to it: an address rule names the address, not the name. |
| 14 | Block a hosting provider's range | `deny 198.51.100.0/24` | Refuses IPs in the range and every name that resolves into it, **for everything below this rule**. An address `allow` above it still opens its part; a name rule above it does not. |
| 15 | The same IP written as IPv6 | (nothing to do) | IPv4-mapped forms like `[::ffff:198.51.100.10]` are treated as the IPv4 address, so rules 13 and 14 cover them. tallygate has no IPv6 egress. |

The addresses in these examples are placeholders from the documentation ranges, which the built-in blocks
cover: put a real public address or range in their place (as written, rule 13 would open that one address of
the documentation range, because it stands above the block).

**Position decides** for address rules. To make a block win over everything, keep it above the address
`allow` rules; a name rule can stand anywhere, it never opens the range. To keep a block from being
overridden by a later approval of an IP address, remember that approvals are added at the top.

Give address `allow` rules a port. Besides being narrower, it keeps the gateway from resolving names it has
not decided yet on other ports ([When a name is resolved](#when-a-name-is-resolved)).

## Time limits and the default

| # | Goal | How |
|---|---|---|
| 16 | Allow something for one hour | add the rule with *TTL* `3600` (a UI field; the API takes `expires`, a unix time), or approve the prompt with *Allow for … min* and `60` |
| 17 | Open the web for 15 minutes during setup | *Quick settings → Internet → Allow web for 15 min* |
| 18 | Strict allowlist, no prompts | default `deny` (*Settings → Mode*), then allow rules for what is needed (or *Quick settings → Tool ecosystems*) |
| 19 | Everything public allowed, but logged | default `allow`; add `deny` or `ask` rules for exceptions. The built-in blocks still keep the local network closed |
| 20 | Let one rule win over another | it must be **above** it: *Move up* / *Move down* |

Rules from approvals are tagged `approval`, rules from shortcuts `preset:<name>`, rules saved from learning
mode `learning`, accepted suggestions `suggestion`, the blocks `builtin` and `config`. Expired rules are
ignored and cleaned up.

## The local network: worked examples

The local network is closed by the [built-in blocks](#built-in-blocks), not by a special mechanism. You open
exactly what you need with an address rule above the block, or with a [grant](grants.md) when the agent
should ask each time.

### a. Allow one local device

Goal: the agent may reach the web interface of a device at `192.168.44.1` on port 443, and nothing else in
the LAN.

*Destinations → Add rule*: `allow`, *CIDR*, `192.168.44.1`, port `443`. The rule is added at the top:

```text
1  allow  192.168.44.1/32 :443        ← decides for this address and port
…
   deny   192.168.0.0/16              built-in block: decides for the rest of the range
   Everything else  ask
```

| Connection | Result | Why |
|---|---|---|
| `192.168.44.1:443` | allow | rule 1 is the first match |
| a name that resolves to `192.168.44.1`, port 443 | allow | the address is what rule 1 names |
| `192.168.44.1:22` | deny | rule 1 does not match the port; the block does |
| `192.168.44.2:443` | deny | the block |

### b. Open a /24 but keep one host blocked

Three layers, from the top: one host stays closed, its /24 is open, the rest of the range stays closed.

```text
1  deny   192.168.44.10/32            ← the exception: stays closed
2  allow  192.168.44.0/24 :443        ← the open subnet
…
   deny   192.168.0.0/16              built-in block
```

Add rule 2 first and rule 1 second (new rules go on top), or use *Move up*. With the two the other way
round, `192.168.44.10:443` would be allowed by the /24 rule before the deny is reached.

### c. A public name that resolves into the LAN

You have `allow *.example.com:443`. Someone points `x.example.com` at `192.168.44.1`.

```text
1  allow  *.example.com :443          name rule: provisional
…
   deny   192.168.0.0/16              built-in block: contains 192.168.44.1 → deny
```

The connection is denied with the message from
[Why a name rule cannot open a blocked range](#why-a-name-rule-cannot-open-a-blocked-range), the agent gets
the same text, and rule 1 is marked *blocked by a range rule below — last: 192.168.44.1 in 192.168.0.0/16*.
Other hosts of `example.com` that resolve to public addresses keep working. If the name has one public and
one local address, it is denied as well (most restrictive wins).

### d. A local device by name, in a grant

Goal: the agent may read Home Assistant's API as `ha.lan`, on request, for a limited time. A grant target
that is only a name cannot open a blocked range either, so the target names the address:

```yaml
grants:
  homeassistant:
    description: Home Assistant REST API
    targets:
      - {host: ha.lan, address: 192.168.1.20, port: 8123, scheme: http, paths: ["/api/*"]}
    levels: [read]
```

With the fixed `address` the gateway does no lookup for `ha.lan`: it connects to `192.168.1.20`, and the
target counts as an address rule at the top of the list while the grant is active. Without `address`, saving
the grant in the UI is refused when `ha.lan` resolves into a blocked range, with the address to set. In the
UI this is the *Fixed IP* field of a target, or simply the IP as the host (*Quick settings → Local network*).
Details: [grants.md](grants.md#local-targets-and-name-only-targets).

| # | Goal | How |
|---|---|---|
| 21 | Let the agent read Home Assistant's API on request | a grant as in example d |
| 22 | Reach a database on the LAN from a client that cannot use a proxy | a service port: `{name: pg, listen: 15432, target: db.lan:5432, allow_private: true}`; the agent connects to `egress-gw:15432`. `allow_private` exempts exactly this target, on this service port, from the built-in and config blocks; your own rules and the locked ranges still apply |

## When a name is resolved

The agent must not be able to leak data through DNS lookups, so the gateway decides on the **name alone**
first and resolves it only when it has to:

- A name the list denies is refused without a lookup, and a name it would ask about is asked about before
  any lookup (`… (not resolved)` in the log).
- That short cut is only taken where no address could change the result. An address `allow` rule for the
  same port might allow one of the name's addresses, so with such a rule in the list **names on that port
  are resolved before they are denied or asked about** (for a name rule: when the address rule stands above
  it; for names no rule matches: wherever it stands). An address `ask` rule has the same effect on names
  that would be denied.
- A name that is allowed is always resolved, and the full list decides with its addresses.

This is why an address `allow` rule should carry a port, and why a [grant](grants.md) is the tighter choice
for a local device when lookups matter: grants do not change when names are resolved.

## Checking a rule before relying on it

*Destinations → Test a destination* with a host and a port shows what the gateway would decide if the agent
connected now:

- the decision (`ALLOW`, `DENY`, `ASK`) and the reason, in the words of the log,
- what decided: the rule with its position in the list (`Decided by rule #4 (…)`), the default, or a locked
  range,
- when a name rule was stopped by a blocked range: both rules, the address, and what to do,
- the resolved IPs, or "not resolved (decided on the name)".

The same check is available as `POST /test` on the gateway API ([api.md](api.md)). It runs the rule list as
a connection does, but it never asks, and it does not take active grants, learning mode or the
`allow_private` exception of a service port into account.
