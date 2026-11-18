# tallygate agent: minimal Claude Code workspace. No route to the internet - all egress via egress-gw.
FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# Claude Code: the version and the integrity hashes of its packages are in claude-code/package.json and
# claude-code/package-lock.json (the single source; `npm ci` refuses a tarball with another hash). There is
# no auto-updater inside the agent; .github/workflows/claude-code.yml opens a PR when a new version is
# published. CLAUDE_VERSION is only for building another version yourself: it is then installed by
# version, WITHOUT a pinned hash.
ARG CLAUDE_VERSION=""
# Extra Debian packages for your toolchains, e.g. "build-essential golang-go"
ARG EXTRA_PACKAGES=""
# ttyd is not packaged for Debian trixie: pinned upstream static binary, checksum-verified.
ARG TTYD_VERSION=1.7.7
ARG TTYD_SHA256_AMD64=8a217c968aba172e0dbf3f34447218dc015bc4d5e59bf51db2f2cd12b7be4f55
ARG TTYD_SHA256_ARM64=b38acadd89d1d396a0f5649aa52c539edbad07f4bc7348b27b4f4b7219dd4165
# GitHub CLI apt keyring (rotated 2026, https://github.blog/changelog/2026-09-03-github-cli-linux-package-signing-key-expires-september-5/).
# Pinned twice: the file by its SHA-256, and its primary keys as the exact, sorted list of fingerprints (the
# key of 2022 and the key of 2026, both "GitHub CLI <opensource+cli@github.com>"). "Contains the pinned key"
# is not enough: apt trusts every key in the file. When GitHub publishes a new keyring the build stops and
# prints what it got: check the new fingerprints against GitHub's announcement before changing these.
# (The names avoid the word "key": the secret scanner takes NAME_WITH_KEY=<hex> for a credential.)
ARG GH_ARCHIVE_GPG_SHA256=6084d5d7bd8e288441e0e94fc6275570895da18e6751f70f057485dc2d1a811b
ARG GH_ARCHIVE_SIGNERS="2C6106201985B60E6C7AC87323F3D4EA75716059 7F38BBB59D064DBCB3D84D725612B36462313325"

ARG DEBIAN_FRONTEND=noninteractive
COPY claude-code/package.json claude-code/package-lock.json /usr/local/lib/claude-code/
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
 # GitHub CLI from GitHub's signed apt repo (Debian's trixie package is outdated)
 && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
 && k=/usr/share/keyrings/githubcli-archive-keyring.gpg \
 # the fingerprint line that follows each "pub" line is the primary key's (subkeys follow "sub")
 && fprs=$(gpg --show-keys --with-colons "$k" | awk -F: '$1=="pub"{p=1;next} $1=="fpr"&&p{print $10;p=0}' | sort | xargs) \
 && [ "$(sha256sum "$k" | cut -d' ' -f1)" = "${GH_ARCHIVE_GPG_SHA256}" ] && [ "$fprs" = "${GH_ARCHIVE_SIGNERS}" ] \
      || { echo "GitHub CLI keyring is not the pinned one: sha256 $(sha256sum "$k" | cut -d' ' -f1), primary keys: $fprs"; exit 1; } \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list \
 && apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      gh git jq less nano procps python3 python3-venv python3-pip ripgrep tini tmux unzip nodejs npm ${EXTRA_PACKAGES} \
 # ttyd (web terminal for the control UI console)
 && case "$(dpkg --print-architecture)" in \
      amd64) f=ttyd.x86_64;  sum=${TTYD_SHA256_AMD64} ;; \
      arm64) f=ttyd.aarch64; sum=${TTYD_SHA256_ARM64} ;; \
      *) echo "unsupported arch"; exit 1 ;; esac \
 && curl -fsSL -o /usr/local/bin/ttyd "https://github.com/tsl0922/ttyd/releases/download/${TTYD_VERSION}/${f}" \
 && echo "${sum}  /usr/local/bin/ttyd" | sha256sum -c - \
 && chmod 755 /usr/local/bin/ttyd \
 # Claude Code: the locked version with npm's integrity check, or the requested one without
 && locked=$(jq -er '.packages["node_modules/@anthropic-ai/claude-code"].version' /usr/local/lib/claude-code/package-lock.json) \
 && if [ -z "${CLAUDE_VERSION}" ] || [ "${CLAUDE_VERSION}" = "$locked" ]; then \
      (cd /usr/local/lib/claude-code && npm ci --no-fund --no-audit --omit=dev) \
      && ln -s /usr/local/lib/claude-code/node_modules/.bin/claude /usr/local/bin/claude; \
    else \
      echo "WARNING: Claude Code ${CLAUDE_VERSION} instead of the locked ${locked}: installed WITHOUT a pinned hash" \
      && npm install -g --no-fund --no-audit "@anthropic-ai/claude-code@${CLAUDE_VERSION}"; \
    fi \
 && npm cache clean --force \
 && apt-get purge -y gnupg && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* /root/.npm \
 && groupadd -g 1000 agent && useradd -m -u 1000 -g 1000 -s /bin/bash agent \
 && mkdir -p /etc/claude-code /workspace && chown agent:agent /workspace \
 && claude --version && gh --version | head -1 && ttyd --version

COPY managed-settings.json /etc/claude-code/managed-settings.json
# managed memory: tells Claude about the gateway and how to request grants
COPY CLAUDE.md /etc/claude-code/CLAUDE.md
COPY entrypoint.sh rc-loop.sh status.py /usr/local/bin/
COPY tallygate-cli.py /usr/local/bin/tallygate
# PreToolUse hook (managed-settings.json): tells the gateway what is about to run, shown next to approvals
COPY tallygate-hook.py /usr/local/bin/tallygate-hook
# `tallygate install` puts its rootless package prefix on PATH for every login shell (and entrypoint.sh)
COPY profile.d-tallygate-install.sh /etc/profile.d/tallygate-install.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/rc-loop.sh /usr/local/bin/status.py /usr/local/bin/tallygate /usr/local/bin/tallygate-hook \
 && chmod 644 /etc/profile.d/tallygate-install.sh

# The GitHub CLI reports usage to cafe.github.com and checks for updates at cli.github.com; the agent never asked
# for either, and each one is an approval request for a destination nobody needs. (Claude Code's own
# telemetry is NOT switched off here: CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC breaks Remote Control, see
# docs/operations.md. Deny those hosts instead.)
ENV HOME=/home/agent DISABLE_AUTOUPDATER=1 TERM=xterm-256color \
    GH_TELEMETRY=false GH_NO_UPDATE_NOTIFIER=1 GH_NO_EXTENSION_UPDATE_NOTIFIER=1
USER 1000:1000
WORKDIR /workspace
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --start-interval=3s \
  CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:7680/status', timeout=4)" || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
