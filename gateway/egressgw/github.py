"""GitHub access per repository (#78).

With `github_repos` set, requests to the GitHub hosts must name an allowed repository in their path, or
they are refused with 403 before they reach GitHub (and before any token is added):

- API style (`api.github.com`, `uploads.github.com`, or a GitHub Enterprise path under `/api/v3`,
  `/api/uploads`): `/repos/<owner>/<repo>/...`. Besides that only `GET`/`HEAD` of a few harmless endpoints
  (`/`, `/user`, `/rate_limit`, `/meta`, `/versions`) and, only with `github_graphql: true`, `/graphql`
  (GraphQL can address any repository, so it is refused by default).
- git and web style (`github.com`): `/<owner>/<repo>[.git][/...]`.

Paths must be canonical (no `..`, `//`, encoded separators). An empty `github_repos` keeps the behaviour
without it: the injected token works for every repository it can reach.
"""

from __future__ import annotations

import re

from egressgw.grants import _BAD_PATH

DEFAULT_HOSTS = ("github.com", "api.github.com", "uploads.github.com")
API_READS = {"/", "/user", "/rate_limit", "/meta", "/versions"}  # GET/HEAD only
_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
_REPO = re.compile(r"[A-Za-z0-9._-]{1,100}")


def _name_ok(owner: str, repo: str) -> bool:
    return bool(_OWNER.fullmatch(owner)) and bool(_REPO.fullmatch(repo)) and repo not in (".", "..")


class RepoScope:
    def __init__(self, config: dict) -> None:
        entries = config.get("github_repos") or []
        if not isinstance(entries, list):
            raise ValueError("github_repos: expected a list of owner/repo or owner/*")
        self.patterns: list[tuple[str, str]] = []
        for e in entries:
            owner, _, repo = str(e).strip().partition("/")
            if not (_name_ok(owner, repo) or (repo == "*" and _OWNER.fullmatch(owner))):
                raise ValueError(f"github_repos: invalid entry {e!r} (owner/repo or owner/*)")
            self.patterns.append((owner.lower(), repo.lower()))
        hosts = config.get("github_hosts") or DEFAULT_HOSTS
        self.hosts = {str(h).lower().rstrip(".") for h in hosts}
        self.graphql = bool(config.get("github_graphql", False))

    def applies(self, host: str) -> bool:
        return bool(self.patterns) and host in self.hosts

    def allowed(self, owner: str, repo: str) -> bool:
        owner, repo = owner.lower(), repo.lower()
        return any(o == owner and r in ("*", repo) for o, r in self.patterns)

    def check(self, host: str, method: str, path: str) -> str | None:
        """The reason to refuse this request, or None. Only call it for hosts where `applies` is true."""
        raw = path.split("?", 1)[0].split("#", 1)[0] or "/"
        if not raw.startswith("/") or _BAD_PATH.search(raw):
            return "non-canonical path on a GitHub host"
        api = host.startswith(("api.", "uploads."))
        for prefix in ("/api/v3", "/api/uploads"):  # GitHub Enterprise Server
            if raw == prefix or raw.startswith(prefix + "/"):
                raw, api = raw[len(prefix) :] or "/", True
        if raw.rstrip("/") == "/api/graphql":
            raw, api = "/graphql", True
        segs = raw.split("/")[1:]
        if api:
            if segs[0] == "repos":
                owner, repo = [*segs, "", ""][1:3]
                return self._repo(owner, repo)
            if raw.rstrip("/") == "/graphql":
                return None if self.graphql else "GraphQL can reach any repository (github_graphql: true allows it)"
            if (raw.rstrip("/") or "/") in API_READS and method.upper() in ("GET", "HEAD"):
                return None
            return "only /repos/<owner>/<repo>/... of the repositories in github_repos is allowed"
        owner, repo = [*segs, "", ""][0:2]
        if repo.endswith(".git"):
            repo = repo[:-4]
        if repo.endswith(".wiki"):
            repo = repo[:-5]
        return self._repo(owner, repo)

    def _repo(self, owner: str, repo: str) -> str | None:
        if not _name_ok(owner, repo):
            return "not a repository path (github_repos is set)"
        if not self.allowed(owner, repo):
            return f"repository {owner}/{repo} is not in github_repos"
        return None
