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

## Installing packages

The root filesystem is read-only and you have no `sudo`, so `apt-get install` and `sudo` do not work and
never will. To add a tool (`shellcheck`, `sqlite3`, `dnsutils`, …), use:

    tallygate install PKG...        # rootless: resolve, download and unpack into your home volume
    tallygate install --list        # what you installed this way
    tallygate install --remove PKG  # remove a package from the prefix
    tallygate install --reset       # delete the whole prefix and start over

- It runs `apt` as you (uid 1000), downloads the `.deb`s through the proxy and unpacks them under
  `~/.local/tallygate/root`; nothing outside your home volume is written. The downloads use the
  **Debian/apt** template, so if it is not active they are held for the operator like any destination.
- `entrypoint.sh` and `/etc/profile.d` put the prefix on `PATH`/`LD_LIBRARY_PATH`. Start a new shell (or
  re-run your command) after installing so the new tools are found.
- Maintainer scripts are **not** run, so packages that need them, system services, fixed paths under
  `/etc`, setuid bits or capabilities (daemons, `sudo`, `iputils-ping`) will not work. Most CLI tools and
  libraries do. For tools you need every time, ask the operator to add them to the image
  (`AGENT_EXTRA_PACKAGES`, see docs/operations.md#custom-agent-image).
- Installed packages live on the home volume and survive restarts, like `pip install --user`. Python and
  Node packages still use `pip install --user` and `npm install` as before.
