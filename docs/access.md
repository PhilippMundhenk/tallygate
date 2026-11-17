# How access works

The whole model on one page: what the agent can reach, who decides, and where you change it. The other
pages go into detail; this one is the map.

## The one question

For every connection the agent makes, the gateway answers one question: **may the agent do this, at this
destination, now?** The answer comes from **one ordered rule list**: it is checked from the top, the first
matching rule decides, and a default applies when none does. [Rules by example](rules.md) describes the
decision in full; this is the short form.

| | What it is | Who sets it | Where |
|---|---|---|---|
| **Locked ranges** | The tallygate stack's own networks and the gateway's own listeners. Checked before the list; no rule, grant or API call opens them. | fixed by the installation (`GW_INTERNAL_NETS` in `compose.yaml`) | shown as the last rows of the *Destinations* table |
| **On request** (grants) | Access the agent has to ask for by name, with a reason, for a limited time. While a grant is active it stands at the top of the list for its targets. | you define it, and you approve each use | *Grants* tab, *Quick settings → Local network*, or the gateway config file |
| **Rules** | Allow, ask or deny per destination and port, in an order you can change. The **built-in blocks** (your local network, loopback, cloud metadata and other special ranges) are ordinary `deny` rules at the bottom of this list. | you: by hand, by approving a prompt, with a shortcut, or from learning mode | *Destinations* tab |
| **Everything else** | The default for destinations no rule covers: ask you (default), deny, or allow and log. | you | *Settings → Mode* |

Two properties of the list are worth knowing before anything else:

- **The local network is closed by rules, not by a special mechanism.** To let the agent reach one device,
  add an allow rule for its address above the block, or define a grant for it. To close it again, delete the
  rule. Deleting a built-in block itself is possible and lowers the protection for that whole range.
- **A destination given by name passes two checks:** the name must be allowed (by a rule for the name, or by
  you), and every address it resolves to must be open. So a rule for a name never opens a blocked range: if
  an allowed name resolves into one, the connection is denied and the log says why. And an allow rule for an
  address lets no name through by itself. To reach a local device by name you need both.
  [Why](rules.md#why-a-name-rule-cannot-open-a-blocked-range).
- **A name is not looked up before it is allowed.** A name that is denied, or that you have not answered
  yet, never reaches a DNS resolver.

## Limits inside a destination

Allowing a destination does not have to mean "anything goes there". Three limits apply to single requests,
which is why the gateway opens the encrypted connection to those hosts (and only those):

| Limit | Effect | Set in |
|---|---|---|
| **Read-only** | Uploads and changes are refused; downloads work. Stops `npm publish` and the like. | gateway config file (`readonly`), or the *read* level of a grant |
| **Credentials added** | The gateway adds your token; the agent never sees it, and its own credentials for that host are removed. | gateway config file (`inject`); the token itself in *Setup* or *Grants → Secrets* |
| **Paths and repositories** | Only certain paths of an API, or only certain GitHub repositories. | a grant's paths; `github_repos` in the gateway config file |

## Who decides what

- **You, each time:** approval prompts (in the UI, on your phone, in Telegram or Matrix) and grant
  requests: allow for a while or permanently, or deny ([user guide](user-guide.md#approvals)).
- **You, in advance:** rules and their order, shortcuts, grant definitions, the default.
- **Nobody, at run time:** the locked ranges. The agent must never reach the gateway's management API or the
  control UI, because from there every other rule could be removed.
- **The agent:** nothing. It can ask for a connection or a grant, and say why. It cannot define, widen or
  approve anything.

## Why some settings are only in a file

Settings that could hand out secrets are read from the gateway config file, not from the UI: which hosts get
credentials, and switching off certificate checks. A stolen UI session can therefore add rules, but it cannot
send your token to a host of its choosing. The UI shows these settings read-only and says where they come
from.

The blocked ranges are **not** in this group: they are rules, and whoever holds a UI session can add an allow
rule for a local address or delete a block. That is deliberate (reaching one device should not need a file
edit), and it makes the UI login the protection of your local network. The
[threat model](threat-model.md#residual-risks) says what follows from it.

## Getting to a working setup

1. **Start with the default:** unknown destinations ask you.
2. **Run your first task in learning mode** (*Quick settings → Learning mode*). For a time you choose, the
   agent may reach any public host on the web ports and everything it uses is recorded. Then tick what to
   keep. That gives you a rule set in minutes instead of a prompt at a time.
3. **Use shortcuts** (*Quick settings*) for whole tool ecosystems (Python, Node.js, Go, …) or to open the web
   for 15 minutes.
4. **Define a grant** for each device or sensitive service the agent should reach on request, or add an allow
   rule for its address when it may always reach it.
5. **Look at the *Destinations* table** now and then, and remove what is no longer used (*Overview → Rule
   usage* lists rules that never matched). *Test a destination* shows what decides for one host and port.

## Where the details are

| Topic | Page |
|---|---|
| How a destination is decided: the list, name and address rules, built-in blocks, worked examples | [Rules by example](rules.md) |
| Grants: fields, levels, the CLI, enforcement | [Grants](grants.md) |
| Every setting and its default | [Configuration reference](configuration.md) |
| The UI, approvals on the phone, the cookbook | [User guide](user-guide.md) |
| What can go wrong, and what stops it | [Threat model](threat-model.md) |
