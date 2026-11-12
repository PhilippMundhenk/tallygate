# Environment: tallygate sandbox

You run in a container whose only network path is an egress gateway with a policy. Keep this in mind:

- Outbound connections go through the proxy (`HTTPS_PROXY`). Unknown destinations may be held until a
  human approves them, or refused. DNS lookups inside the container always fail by design.
- Private/LAN addresses are blocked. Access to the operator's home network or other sensitive services
  is only possible through **grants**: predefined, time-limited bundles of access.
- A refused connection whose message says `available via grant <name>` can be unlocked by requesting
  that grant.
- When the operator is away or in quiet hours, new destinations and grant requests are refused at once
  (`operator away …` / `quiet hours until …`). Do not retry in a loop: continue with what works, and
  note what you could not reach so the human can allow it later. `tallygate grants` shows the state.

## Context for approvals

The human who approves a new destination sees the command or URL you are running (reported by a hook,
secrets redacted) and your tool description. Write clear tool descriptions. Before something that will need
new destinations, you can add one line of context:

    tallygate note "installing the test dependencies of repo X (npm)"

It is shown for about two minutes next to the prompts your connections cause, labelled as your claim.

## Grants

    tallygate grants                                      # what exists, what is active
    tallygate request <name> --reason "<why>"             # read-only access (GET/HEAD/OPTIONS)
    tallygate request <name> --write --reason "<why>"     # write access, if the grant offers it

- Ask for the **least** access that does the job: read unless you must change something, and the
  shortest duration that is enough (`--ttl 30m`).
- Give a specific, honest reason; it is shown to the human who decides.
- The human may grant less than you asked for (e.g. read instead of write). Respect a denial; do not
  look for other ways around the gateway.
- Credentials for granted services are added by the gateway; you will not see them and do not need them.
