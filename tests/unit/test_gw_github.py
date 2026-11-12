"""GitHub access per repository (#78): which requests name an allowed repository."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.github import RepoScope

SCOPE = RepoScope({"github_repos": ["Acme/App", "tools/*"]})


def test_empty_list_keeps_the_old_behaviour():
    s = RepoScope({})
    assert not s.applies("github.com") and not s.applies("api.github.com")
    assert SCOPE.applies("api.github.com") and not SCOPE.applies("example.org")


@pytest.mark.parametrize(
    ("host", "method", "path"),
    [
        ("github.com", "GET", "/acme/app.git/info/refs?service=git-upload-pack"),
        ("github.com", "POST", "/acme/app.git/git-receive-pack"),
        ("github.com", "GET", "/ACME/APP/archive/refs/heads/main.tar.gz"),
        ("github.com", "GET", "/acme/app.wiki.git/info/refs"),
        ("github.com", "GET", "/tools/anything"),
        ("api.github.com", "GET", "/repos/acme/app"),
        ("api.github.com", "POST", "/repos/acme/app/pulls"),
        ("api.github.com", "GET", "/repos/tools/x/issues?state=open"),
        ("api.github.com", "GET", "/user"),
        ("api.github.com", "HEAD", "/"),
        ("api.github.com", "GET", "/rate_limit"),
        ("uploads.github.com", "POST", "/repos/acme/app/releases/1/assets?name=a.zip"),
        ("ghes.example.org", "GET", "/api/v3/repos/acme/app/pulls"),
        ("ghes.example.org", "POST", "/api/uploads/repos/acme/app/releases/1/assets"),
        ("ghes.example.org", "GET", "/api/v3"),
    ],
)
def test_allowed(host, method, path):
    assert SCOPE.check(host, method, path) is None


@pytest.mark.parametrize(
    ("host", "method", "path", "why"),
    [
        ("github.com", "GET", "/evil/exfil.git/info/refs", "repository evil/exfil is not in github_repos"),
        ("github.com", "POST", "/acme/other.git/git-receive-pack", "repository acme/other"),
        ("github.com", "GET", "/", "not a repository path"),
        ("github.com", "GET", "/acme", "not a repository path"),
        ("github.com", "GET", "/acme/app/../../evil/x", "non-canonical"),
        ("github.com", "GET", "/acme/app%2f..%2fevil", "non-canonical"),
        ("github.com", "GET", "//evil/x", "non-canonical"),
        ("github.com", "GET", "relative/path", "non-canonical"),
        ("github.com", "GET", "/acme/a b", "non-canonical"),
        ("api.github.com", "GET", "/repos/evil/x", "repository evil/x"),
        ("api.github.com", "GET", "/repos/acme", "not a repository path"),
        ("api.github.com", "GET", "/repositories/123/contents", "only /repos/"),
        ("api.github.com", "POST", "/user/repos", "only /repos/"),
        ("api.github.com", "PATCH", "/user", "only /repos/"),
        ("api.github.com", "GET", "/search/code?q=x", "only /repos/"),
        ("api.github.com", "POST", "/gists", "only /repos/"),
        ("api.github.com", "POST", "/graphql", "GraphQL"),
        ("ghes.example.org", "POST", "/api/graphql", "GraphQL"),
        ("ghes.example.org", "GET", "/api/v3/orgs/evil", "only /repos/"),
        ("uploads.github.com", "POST", "/repos/evil/x/releases/1/assets", "repository evil/x"),
    ],
)
def test_refused(host, method, path, why):
    assert why in SCOPE.check(host, method, path)


def test_graphql_only_when_enabled_and_custom_hosts():
    s = RepoScope({"github_repos": ["acme/app"], "github_graphql": True, "github_hosts": ["GHES.example.org."]})
    assert s.check("api.github.com", "POST", "/graphql") is None
    assert s.applies("ghes.example.org") and not s.applies("github.com")


@pytest.mark.parametrize("bad", ["acme", "acme/", "/app", "ac me/app", "acme/a/b", "acme/..", "-acme/app", "acme/*x"])
def test_invalid_entries_stop_the_gateway(bad):
    with pytest.raises(ValueError, match="github_repos"):
        RepoScope({"github_repos": [bad]})
    with pytest.raises(ValueError):
        RepoScope({"github_repos": "acme/app"})
