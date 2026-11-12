# tallygate agent: minimal Claude Code workspace. No route to the internet - all egress via egress-gw.
FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# The single source of the Claude Code version. Bump deliberately: there is no auto-updater inside the agent.
# .github/workflows/claude-code.yml opens a PR when a new version is published.
ARG CLAUDE_VERSION=2.1.304
# Extra Debian packages for your toolchains, e.g. "build-essential golang-go"
ARG EXTRA_PACKAGES=""
# ttyd is not packaged for Debian trixie: pinned upstream static binary, checksum-verified.
ARG TTYD_VERSION=1.7.7
ARG TTYD_SHA256_AMD64=8a217c968aba172e0dbf3f34447218dc015bc4d5e59bf51db2f2cd12b7be4f55
ARG TTYD_SHA256_ARM64=b38acadd89d1d396a0f5649aa52c539edbad07f4bc7348b27b4f4b7219dd4165
# GitHub CLI apt signing key (rotated 2026, https://github.blog/changelog/2026-09-03-github-cli-linux-package-signing-key-expires-september-5/)
ARG GH_KEY_FPR=7F38BBB59D064DBCB3D84D725612B36462313325

ARG DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
 # GitHub CLI from GitHub's signed apt repo (Debian's trixie package is outdated)
 && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
 && gpg --show-keys --with-colons /usr/share/keyrings/githubcli-archive-keyring.gpg | grep -q "^fpr:::::::::${GH_KEY_FPR}:" \
      || { echo "GitHub CLI keyring does not contain the pinned key ${GH_KEY_FPR}"; exit 1; } \
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
 # Claude Code
 && npm install -g --no-fund --no-audit "@anthropic-ai/claude-code@${CLAUDE_VERSION:?CLAUDE_VERSION must not be empty}" \
 && npm cache clean --force \
 && apt-get purge -y gnupg && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* /root/.npm \
 && groupadd -g 1000 agent && useradd -m -u 1000 -g 1000 -s /bin/bash agent \
 && mkdir -p /etc/claude-code /workspace && chown agent:agent /workspace \
 && claude --version && gh --version | head -1 && ttyd --version

COPY managed-settings.json /etc/claude-code/managed-settings.json
# managed memory: tells Claude about the gateway and how to request grants
COPY CLAUDE.md /etc/claude-code/CLAUDE.md
COPY entrypoint.sh status.py /usr/local/bin/
COPY tallygate-cli.py /usr/local/bin/tallygate
RUN chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/status.py /usr/local/bin/tallygate

ENV HOME=/home/agent DISABLE_AUTOUPDATER=1 TERM=xterm-256color
USER 1000:1000
WORKDIR /workspace
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --start-interval=3s \
  CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:7680/status', timeout=4)" || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
