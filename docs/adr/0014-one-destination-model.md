# ADR-0014: One destination model and one evaluation path

- Status: Accepted (see [Decisions](#decisions))
- Date: 2026-11-13
- Issue: #122

## Context

"What may the agent do at this destination, now?" is answered by four mechanisms that grew one after the
other:

| Mechanism | Defined in | Enforced in `gateway/egressgw/core.py` |
|---|---|---|
| Rules (`allow` / `ask` / `deny` per host or CIDR and port) | `policy.yaml`, UI, approvals | `server_connect` → `Policy.evaluate_name` / `evaluate` |
| Read-only hosts | `readonly` in the gateway config | `_intercepted`, `_host_checks` |
| Credential injection | `inject` in the gateway config | `_intercepted`, `_host_checks` |
| Repository limits | `github_repos` | `_intercepted`, `_checks` → `RepoScope.check` |
| Grants (on request, read/write, paths, LAN, TLS pinning, own injection) | `grants` in the config, UI | `_grant_connect`, `_grant_binding`, `_grant_checks` |

Each has its own definition format, its own matching (`policy.host_matches` and `grants.host_match` treat
`*.example.com` differently), its own place where a connection is recognised, and partly its own request
checks. Three lists say what is never reachable, with different semantics: the hard-deny floor (additive),
`grants_never` (replaces its default) and `GW_INTERNAL_NETS` (grants only).

The cost is visible in two places.

**Security.** The findings of the last weeks were all disagreements between two of these mechanisms about
the same connection:

- #9, #57, #108: whether a connection is intercepted was decided by name in one place and by SNI or IP in
  another, so an intercepted host could be reached without interception.
- #112: LAN grants skip the hard deny, and the list that replaces it for grants did not cover the stack.
- #119: a CIDR `deny` rule is skipped when a host `allow` rule sits above it.
- #58: "read-only" meant different methods for read-only hosts and for read-level grants.

Every fix added a cross-check between two paths. The number of pairs grows with every mechanism.

**Usability.** Step 1 (#121) hides the split in the UI: *What the agent can reach* shows each destination
once. Underneath, an operator who wants "github.com: allowed, read-only, with my token, only my repositories"
still edits four places in three formats.

## Decision

### 1. One model: destinations with properties

A **destination entry** has a match and properties. Everything that exists today is expressible in it.

```yaml
destinations:
  - match: {host: github.com, port: 443}        # host pattern or cidr, port spec as in rules today
    access: allow                               # allow | ask | deny | request
    methods: read                               # all (default) | read | read+post-as-write
    paths: ["/me/app/*", "/me/app.git/*"]       # default: everything
    credentials: {header: Authorization, value: "Bearer ${github_token}"}
    note: git and API
    expires: null

  - match: {host: ha.lan, port: 8123}
    access: request                             # today: a grant
    request: {name: homeassistant, levels: [read, write], approval: {read: auto, write: ask},
              default_ttl: 1h, max_ttl: 4h}
    scheme: http
    paths: ["/api/*"]
    lan: true                                   # exempt from the never-reachable floor, for this target only
    tls: {fingerprint: null, verify: true}
```

| Today | In the model |
|---|---|
| rule `allow` / `ask` / `deny` | `access` |
| grant | `access: request` plus `request:` (name, levels, approval, durations) |
| `readonly` entry, grant level `read` | `methods` |
| grant `paths`, `read_posts`, `github_repos` | `paths` (and `read_paths` for POSTs that only read) |
| `inject`, grant `inject` | `credentials` |
| grant `lan`, `address`, `tls_fingerprint`, `tls_verify` | `lan`, `address`, `tls` |
| mode | the last entry: `match: {host: "*"}` with `access: ask` (kept as `default` in the file for readability) |

One matcher is used for every entry. `*.example.com` means the same everywhere: the domain and its
subdomains, as in rules today.

### 2. One evaluation path

Two functions decide everything, and nothing else in the gateway looks at configuration lists.

- `decide_connection(name_or_ip, port, resolved_ips) -> Verdict`: the entry that applies, its access, whether
  the connection must be intercepted, which IP it is pinned to, which SNI is expected.
- `decide_request(verdict, method, host_header, path) -> allow | refuse(reason)`: Host binding, methods,
  paths, credential stripping and injection.

**Interception follows from the properties, not from the list an entry came from:** an entry with `methods`,
`paths` or `credentials` is intercepted; any other is passed through with the SNI bound to the checked name
(ADR-0013). The verdict is stored per connection, so the TLS and HTTP hooks read one object instead of asking
five helpers again.

**Reaching a destination by another route is handled in this one place.** A connection to an IP literal is
matched against the entries by the addresses their names resolve to. If it belongs to an entry that needs
interception, it is refused with "connect by name". That is the rule #108 needed three patches to reach.

Order of evaluation:

1. Never reachable (see 3), on the literal address, and again on every resolved address.
2. An **active** request entry (today: active grant) for the destination.
3. Entries top to bottom, on the name; then resolution; then again with the addresses. `deny` entries with a
   CIDR are checked against the resolved addresses **before** name entries (this fixes #119).
4. The mode.

### 3. One never-reachable list

One list, always additive, each entry with a scope:

```yaml
never:
  - {range: 10.0.0.0/8, scope: all}             # built in
  - {range: 203.0.113.7/32, scope: all}         # your additions
  - {range: 169.254.0.0/16, scope: all+lan}     # closed for LAN entries too (today: grants_never)
  - {range: 172.31.11.0/24, scope: all+lan}     # the stack itself (today: GW_INTERNAL_NETS)
```

`scope: all` can be exempted for one target by an entry with `lan: true`. `scope: all+lan` cannot.
`grants_never` stops replacing a default: the built-in `all+lan` entries always apply.

### 4. The trust split stays

Properties that can hand out secrets or open the local network are accepted **only from the read-only
config file**: `credentials`, `lan`, `tls.verify: false`, and `never` entries that are removed or narrowed.
The API and the UI can add entries and narrow existing ones (`methods: read`, fewer paths, shorter time).
An entry from the API that sets a file-only property is rejected, as UI grants with `inject` are today.

`lan: true` from the UI stays possible inside `grants_lan_allow` (renamed `lan_allow`), as today.

### 5. Migration

There are few deployments, so the old formats are not kept alive next to the new ones. What must keep working
is an **unattended image update** (for example by Watchtower): a stack that is running today has to come up
with the new images without anyone touching it.

- **State in the gateway's volume is migrated at start.** `policy.yaml` and `grants.yaml` in the old format
  are translated once and written back in the new format; the old files are kept next to them as
  `*.pre-0014`. A file that cannot be translated stops the gateway with a message that names the entry,
  as an invalid policy does today (fail closed).
- **The operator's `gateway.yaml` is read in both formats.** It is mounted read-only and belongs to the
  operator, so the gateway cannot rewrite it. The old keys (`readonly`, `inject`, `github_repos`, `grants`,
  `grants_never`, `hard_deny_floor`) are translated in memory at every start, and the log says once which
  keys to rename. `python -m egressgw.convert gateway.yaml` prints the file in the new format.
- **Environment variables keep their names.**
- **API:** the routes change with the model and the old ones are removed in the same release. The UI, the
  notifiers and the agent CLI are updated with it. Because the gateway and control images may be updated a
  few seconds apart, control treats an unknown-route answer from the gateway as "gateway is updating" and
  retries, instead of showing an error.

### 6. Intended behaviour changes

Everything else must behave as before for an unchanged configuration. These three change on purpose and are
listed in the changelog and upgrade notes:

| Change | Today | After |
|---|---|---|
| CIDR `deny` and a host `allow` above it (#119) | the host rule wins | the CIDR deny wins |
| `*.example.lan` in a grant target | subdomains only | the domain and its subdomains, as in rules |
| `grants_never` set in the config | replaces the built-in list | adds to it |

The second and third make existing configurations **stricter or equal** in what they forbid, with one
exception: a wildcard grant target would also cover the bare domain. The translation therefore keeps today's
meaning for translated grants (it writes the pattern so that the bare domain stays excluded) and only new
entries get the unified meaning.

## How it is built without breaking enforcement

The gateway's decision path is the product. The rewrite is staged so that every step can be verified against
the current behaviour and reverted on its own.

1. **Model and translation, no enforcement change.** `egressgw/model.py` with the entry types and
   `translate(config, policy, grants) -> Model`. Unit tests translate every policy and config used by the
   existing tests.
2. **Shadow evaluation.** The new `decide_connection` / `decide_request` run next to the current code on
   every connection and request, and only log when they disagree. The current code still decides. The whole
   unit and e2e suite runs with a flag that turns a disagreement into a test failure. This is the regression
   net: about 660 unit tests and the e2e suite exercise every edge that was ever a finding.
3. **Switch.** The new functions decide; the old helpers are removed in the same change so that there are not
   two paths. The three intended changes above get their own tests.
4. **Never-reachable list**, API, UI and docs.
5. **Security review** of the result by a fresh pass over the new path, with the earlier findings (#9, #56,
   #57, #108, #111, #112, #119) as explicit test cases.

Steps 1 and 2 change nothing for users and can be merged and released. Step 3 is the only risky merge.

## Progress

- 2026-11-13: the three intended behaviour changes that could be made in the old code were made first
  (#119: CIDR `deny`, `grants_never` additive).
- 2026-11-13: `model.py` was evaluated in shadow on every TLS handshake and request in the whole unit and e2e
  suite without a difference, and then took over: the hooks in `core.py` ask the model, and the helpers it
  replaced (`_intercepted`, `_sni_problem`, `_host_binding`, `_host_checks`, `_grant_binding`, `_grant_checks`)
  and the per-connection maps (`orig_host`, `conn_grant`) are gone.
- 2026-11-13: the connection decision moved into the model too (`on_name`, `on_addresses`, `grant_for`,
  `grant_problem`); `server_connect` only resolves, asks you and applies the verdict.
- 2026-11-13: one `never` list in the gateway config, with scopes `all` and `all+lan`; the old keys are read
  as `never` and `python -m egressgw.convert` prints a file in the new form.
- 2026-11-14: the destination model exists as data: `egressgw/destinations.py` with the `Destination`/`Match`/
  `Request`/`Model` entries, their file-format `to_dict`/`from_dict`/`validate`, and `translate(gw) -> Model`
  that lists a running gateway's rules, grants, read-only hosts, repository limits, credentials and
  never-reachable ranges as one ordered model. It is data only: nothing in the evaluation path reads it yet,
  so it changes no behaviour; `model.Access` still reads the old structures. Tests translate the fixtures and
  round-trip every entry through the format.
- Open: the file format (gateway reads and writes `destinations:`), migration, API and UI.

## Consequences

- ✅ One definition, one matcher, one place where a connection is recognised: the class of "two mechanisms
  disagree" findings has no second mechanism to disagree with.
- ✅ An operator edits one entry to say "allowed, read-only, with my token, only these repositories".
- ✅ #119 is fixed by the evaluation order instead of another cross-check.
- ⚠️ The largest change to the security-critical code so far. Mitigated by shadow evaluation before the
  switch and a security review after it.
- ⚠️ The gateway's state is rewritten in a new format on the first start (old files are kept as
  `*.pre-0014`), and `gateway.yaml` is read in both formats for as long as operators have old files.
- ⚠️ `core.py` (about 1100 lines) is restructured; open pull requests against it will conflict.

## Alternatives considered

- **Keep four mechanisms, keep adding cross-checks.** No migration, but every new feature multiplies the
  pairs, and step 1 already shows users a model the code does not have.
- **Unify only the definition format, keep the enforcement paths.** Fixes usability, leaves the security
  problem where it is.
- **Intercept everything.** One path by construction, but it puts every destination's traffic in clear inside
  the gateway and breaks clients that pin certificates. [ADR-0005](0005-credential-injection-by-tls-interception.md)
  chose selective interception for that reason, and it still holds.

## Decisions

Decided by the maintainer on 2026-11-13:

1. **Two files.** The read-only `gateway.yaml` holds the entries with file-only properties, `policy.yaml`
   the rest. The read-only mount is what makes the trust split hold.
2. **"Grant" stays as a word for the flow** (the agent requests, you approve, it ends by itself). It is no
   longer a separate kind of definition: it is a destination with `access: request`.
3. **A CIDR `deny` always wins over name entries** (#119). It is checked against the resolved addresses
   before the name entries.
4. **No deprecation period.** The old API routes and the old formats of the gateway's own state go in the
   same release; see [Migration](#5-migration) for what keeps an unattended update working.
