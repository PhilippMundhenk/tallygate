# How access works

The whole model on one page: what the agent can reach, who decides, and where you change it. The other
pages go into detail; this one is the map.

## The one question

For every connection the agent makes, the gateway answers one question: **may the agent do this, at this
destination, now?** Four things feed the answer, checked in this order.

| | What it is | Who sets it | Where |
|---|---|---|---|
| 1. **Never reachable** | Ranges that are always closed: your local network, the Docker host, cloud metadata addresses, the tallygate stack itself. Nothing is asked, and no rule opens them. | built in; you can add ranges | *Rules → Never reachable* |
| 2. **On request** (grants) | Access the agent has to ask for by name, with a reason, for a limited time. The only way to one device on the local network. | you define it, and you approve each use | *Grants* tab, or the gateway config file |
| 3. **Rules** | Allow, ask or block per host and port. The first rule that matches decides. | you: by hand, by approving a prompt, with a shortcut, or from learning mode | *Rules* tab |
| 4. **Everything else** | The mode for destinations no rule covers: ask you (default), block, or allow and log. | you | *Rules → Shortcuts → Unknown destinations* |

*Rules → What the agent can reach* shows the result: each destination once, with everything that applies
to it.

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
  requests. *Allow once*, *Always allow* or *Deny*; more choices are behind *More*.
- **You, in advance:** rules, shortcuts, grant definitions, the mode.
- **Nobody, at run time:** the never-reachable list. That is the point of it.
- **The agent:** nothing. It can ask for a connection or a grant, and say why. It cannot define, widen or
  approve anything.

## Why some settings are only in a file

Settings that could hand out secrets or open the local network are read from the gateway config file, not
from the UI: which hosts get credentials, switching off certificate checks, the never-reachable list
itself, and which local ranges grants made in the UI may reach. A stolen UI session can therefore add
rules, but it cannot send your token to a host of its choosing or reach your NAS. The UI shows these
settings read-only and says where they come from.

## Getting to a working setup

1. **Start with the default:** unknown destinations ask you.
2. **Run your first task in learning mode** (*Setup → Starting policy → Learn from a first task*). For a time
   you choose, the agent may reach any public host on the web ports and everything it uses is recorded.
   Then tick what to keep. That gives you a rule set in minutes instead of a prompt at a time.
3. **Use shortcuts** for whole tool ecosystems (Python, Node.js, Go, …) or to open the web for 15 minutes.
4. **Define a grant** for each device or sensitive service the agent should reach on request.
5. **Look at *What the agent can reach*** now and then, and remove what is no longer used (*Rule usage and
   suggestions* lists rules that never matched).

## Where the details are

| Topic | Page |
|---|---|
| How a connection is decided, with about twenty examples | [Rules by example](rules.md) |
| Grants: fields, levels, the CLI, enforcement | [Grants](grants.md) |
| Every setting and its default | [Configuration reference](configuration.md) |
| The UI, approvals on the phone, the cookbook | [User guide](user-guide.md) |
| What can go wrong, and what stops it | [Threat model](threat-model.md) |
