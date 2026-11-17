"""control/app/notifyconfig.py: the notification settings the web UI may change (#201, ADR-0018).
Precedence (UI over environment, per field), write-only secrets, validation, and the read-only store."""

from __future__ import annotations

import json
import logging
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "control"))

from app import notifyconfig
from app.notifyconfig import ConfigError, NotifyConfig, ReadOnlyError

TOKEN = "123456:" + "A" * 30
ENV_VARS = [f.env for fields in notifyconfig.CHANNELS.values() for f in fields]


@pytest.fixture
def store(monkeypatch, tmp_path):
    def _store(**env):
        for k in ENV_VARS:
            monkeypatch.delenv(k, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        return NotifyConfig(tmp_path / "data" / "notify.json")

    return _store


def fields(cfg, channel):
    entry = next(c for c in cfg.public()["channels"] if c["channel"] == channel)
    return entry, {f["name"]: f for f in entry["fields"]}


# ---------------------------------------------------------------- precedence
def test_ui_value_wins_per_field_and_removing_falls_back_to_the_environment(store):
    cfg = store(TELEGRAM_BOT_TOKEN="env-token", TELEGRAM_CHAT_ID="777", TELEGRAM_ALLOWED_USER_IDS="1")
    assert cfg.source("telegram") == "environment" and cfg.effective("telegram")["chat_id"] == "777"
    assert cfg.update("telegram", {"chat_id": "555"}) == ["chat_id"]
    assert cfg.effective("telegram") == {"bot_token": "env-token", "chat_id": "555", "allowed_user_ids": "1"}
    entry, f = fields(cfg, "telegram")
    assert entry["source"] == "mixed" and entry["override"] is True
    assert (f["chat_id"]["source"], f["bot_token"]["source"]) == ("ui", "environment")
    assert cfg.update("telegram", {"chat_id": ""}) == ["chat_id"]  # a cleared field: back to the environment
    assert cfg.effective("telegram")["chat_id"] == "777" and cfg.overrides == {}
    cfg.update("telegram", {"bot_token": TOKEN, "chat_id": "555", "allowed_user_ids": "4, 5"})
    assert cfg.source("telegram") == "ui" and cfg.effective("telegram")["allowed_user_ids"] == "4,5"
    assert cfg.remove("telegram") is True and cfg.remove("telegram") is False
    assert cfg.source("telegram") == "environment" and cfg.effective("telegram")["bot_token"] == "env-token"
    assert cfg.source("ntfy") == "unset"


def test_saved_values_survive_a_restart_in_a_private_file(store, tmp_path):
    cfg = store()
    cfg.update("gotify", {"url": "https://gotify.example.org", "token": "app-token"})
    path = tmp_path / "data" / "notify.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and not path.with_name("notify.json.tmp").exists()
    assert json.loads(path.read_text())["channels"] == {
        "gotify": {"url": "https://gotify.example.org", "token": "app-token"}
    }
    again = NotifyConfig(path)
    assert again.effective("gotify")["token"] == "app-token" and again.writable


def test_unchanged_values_are_not_reported_as_changed(store):
    cfg = store()
    body = {"url": "https://ntfy.example.org/t", "token": "tk"}
    assert cfg.update("ntfy", body) == ["url", "token"] and cfg.update("ntfy", body) == []


# ---------------------------------------------------------------- write-only secrets
def test_secrets_are_never_returned_only_whether_they_are_set(store):
    cfg = store(MATRIX_ACCESS_TOKEN="env-secret-token", PUSHOVER_USER="env-user-key")
    cfg.update("pushover", {"token": "ui-app-token"})
    cfg.update("ntfy", {"url": "https://ntfy.example.org/topic", "token": "ui-ntfy-token"})
    public = cfg.public()
    text = json.dumps(public)
    for secret in ("env-secret-token", "env-user-key", "ui-app-token", "ui-ntfy-token"):
        assert secret not in text
    _, po = fields(cfg, "pushover")
    assert po["token"] == {**po["token"], "secret": True, "set": True, "source": "ui"} and "value" not in po["token"]
    assert (po["user"]["set"], po["user"]["source"]) == (True, "environment") and "value" not in po["user"]
    _, mx = fields(cfg, "matrix")
    assert mx["access_token"]["source"] == "environment" and mx["homeserver"]["source"] == "unset"
    _, ntfy = fields(cfg, "ntfy")
    assert ntfy["url"]["value"] == "https://ntfy.example.org/topic" and ntfy["token"]["required"] is False


def test_an_empty_secret_keeps_the_stored_one(store):
    cfg = store()
    cfg.update("gotify", {"url": "https://g.example.org", "token": "first"})
    assert cfg.update("gotify", {"url": "https://g.example.org", "token": ""}) == []
    assert cfg.update("gotify", {"token": "  "}) == [] and cfg.effective("gotify")["token"] == "first"
    assert cfg.update("gotify", {"token": "second"}) == ["token"] and cfg.effective("gotify")["token"] == "second"


def test_a_password_in_an_environment_url_is_masked(store):
    cfg = store(NTFY_URL="https://user:pw@ntfy.example.org/topic", GOTIFY_URL="https://g.example.org/")
    _, ntfy = fields(cfg, "ntfy")
    assert ntfy["url"]["value"] == "https://***@ntfy.example.org/topic" and "pw" not in json.dumps(cfg.public())
    assert fields(cfg, "gotify")[1]["url"]["value"] == "https://g.example.org/"


@pytest.mark.parametrize(
    ("env", "first", "change"),
    [
        ({}, {"url": "https://g.example.org", "token": "stored"}, {"url": "https://evil.example"}),
        ({"GOTIFY_URL": "https://g.example.org", "GOTIFY_TOKEN": "from-env"}, None, {"url": "https://evil.example"}),
        ({"GOTIFY_TOKEN": "from-env"}, None, {"url": "https://evil.example"}),  # a token waiting for its URL
    ],
)
def test_a_token_stays_with_its_server(store, env, first, change):
    """Otherwise a UI session could point a stored or environment token at its own server and read it."""
    cfg = store(**env)
    if first:
        cfg.update("gotify", first)
    with pytest.raises(ConfigError, match="enter the application token again"):
        cfg.update("gotify", change)
    assert "evil" not in json.dumps(cfg.overrides)
    assert cfg.update("gotify", {**change, "token": "new-token"})  # with the token entered again it is fine
    assert cfg.effective("gotify") == {"url": "https://evil.example", "token": "new-token"}
    assert cfg.update("gotify", {"url": "https://evil.example/"}) == ["url"]  # the same server: no re-entry


def test_matrix_homeserver_change_needs_the_token_again(store):
    cfg = store()
    full = {"homeserver": "https://hs.example", "access_token": "t", "room_id": "!r:hs", "allowed_users": "@a:hs"}
    cfg.update("matrix", full)
    with pytest.raises(ConfigError, match="Homeserver URL changed"):
        cfg.update("matrix", {"homeserver": "https://other.example"})
    cfg.update("matrix", {"room_id": "!other:hs"})  # everything else may change without the token


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize(
    ("channel", "body", "message"),
    [
        ("bogus", {}, "unknown channel"),
        ("webpush", {}, "unknown channel"),
        ("ntfy", None, "expected a JSON object"),
        ("ntfy", ["url"], "expected a JSON object"),
        ("ntfy", {"nope": "x"}, "unknown field: nope"),
        ("ntfy", {"url": 5}, "Topic URL: expected text"),
        ("ntfy", {"url": "ftp://ntfy.example.org/t"}, "http:// or https://"),
        ("ntfy", {"url": "https:///topic"}, "http:// or https://"),
        ("ntfy", {"url": "https://u:p@ntfy.example.org/t"}, "user name or password"),
        ("ntfy", {"url": "https://ntfy.example.org/t#x"}, "#fragment"),
        ("ntfy", {"url": "https://ntfy.example.org/a b"}, "not a valid URL"),
        ("ntfy", {"url": "https://ntfy.example.org:port/t"}, "not a valid URL"),
        ("ntfy", {"url": "https://" + "a" * 2100}, "not a valid URL"),
        ("ntfy", {"url": "https://ntfy.example.org/t", "token": "has space"}, "printable characters"),
        ("gotify", {"token": "x" * 1025}, "printable characters"),
        ("telegram", {"bot_token": "../../getMe"}, "does not look like a Telegram bot token"),
        ("telegram", {"chat_id": "my chat"}, "numeric chat id"),
        ("telegram", {"allowed_user_ids": "12,@name"}, "'@name' is not a valid entry"),
        ("telegram", {"allowed_user_ids": " , "}, "expected 1 to 50"),
        ("matrix", {"room_id": "#alias:hs"}, "starts with !"),
        ("matrix", {"allowed_users": "me"}, "Matrix user ids"),
    ],
)
def test_bad_input_is_refused_and_nothing_is_stored(store, channel, body, message):
    cfg = store()
    with pytest.raises(ConfigError, match=message):
        cfg.update(channel, body)
    assert cfg.overrides == {} and not cfg.path.exists()


def test_an_error_never_repeats_a_secret(store):
    cfg = store()
    with pytest.raises(ConfigError) as e:
        cfg.update("gotify", {"token": "super secret value"})
    assert "super" not in str(e.value)
    with pytest.raises(ConfigError, match="unknown channel"):
        cfg.remove("bogus")
    with pytest.raises(ConfigError, match="unknown channel"):
        cfg.effective("bogus")


@pytest.mark.parametrize(
    ("channel", "body", "message"),
    [
        ("telegram", {"bot_token": TOKEN, "chat_id": "5"}, "Allowed user ids are required"),
        ("matrix", {"homeserver": "https://hs", "access_token": "t", "room_id": "!r:hs"}, "Allowed users are required"),
    ],
)
def test_interactive_channels_are_refused_without_allowed_users(store, channel, body, message):
    """ADR-0010: without the allowlist anyone in the chat could approve."""
    cfg = store()
    with pytest.raises(ConfigError, match=message):
        cfg.update(channel, body)
    assert cfg.overrides == {}


def test_allowed_users_cannot_be_cleared_while_the_channel_is_on(store):
    cfg = store()
    cfg.update("telegram", {"bot_token": TOKEN, "chat_id": "-1005", "allowed_user_ids": "42"})
    with pytest.raises(ConfigError, match="required"):
        cfg.update("telegram", {"allowed_user_ids": ""})
    assert cfg.effective("telegram")["allowed_user_ids"] == "42"
    cfg.update("telegram", {"chat_id": "@channel_name"})  # the allowlist is not needed again
    env = store(TELEGRAM_ALLOWED_USER_IDS="7")
    env.update("telegram", {"bot_token": TOKEN, "chat_id": "5"})  # the environment's allowlist counts


# ---------------------------------------------------------------- the store itself
def test_unwritable_volume_is_environment_only(monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("NTFY_URL", "https://ntfy.example.org/t")
    blocker = tmp_path / "data"
    blocker.write_text("a file where the data directory should be")
    with caplog.at_level(logging.WARNING, logger="notify"):
        cfg = NotifyConfig(blocker / "notify.json")
    assert cfg.writable is False and cfg.public()["writable"] is False and "environment-only" in caplog.text
    assert cfg.effective("ntfy")["url"] == "https://ntfy.example.org/t"  # the environment still works
    with pytest.raises(ReadOnlyError, match="not writable"):
        cfg.update("ntfy", {"url": "https://other.example/t"})
    assert cfg.remove("ntfy") is False and cfg.overrides == {}


def test_without_a_path_the_store_is_environment_only(monkeypatch):
    monkeypatch.setenv("GOTIFY_URL", "http://g")
    cfg = NotifyConfig(None)
    assert cfg.writable is False and cfg.effective("gotify")["url"] == "http://g"
    with pytest.raises(ReadOnlyError):
        cfg.update("gotify", {"token": "t"})


def test_a_failing_write_changes_nothing(store, monkeypatch):
    cfg = store()
    cfg.update("pushover", {"token": "a", "user": "u"})

    def boom(*_a, **_k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(notifyconfig.os, "open", boom)
    with pytest.raises(ReadOnlyError, match="No space left"):
        cfg.update("pushover", {"token": "b"})
    with pytest.raises(ReadOnlyError):
        cfg.remove("pushover")
    assert cfg.effective("pushover") == {"token": "a", "user": "u"}


@pytest.mark.parametrize(
    "content", ["{not json", "[]", '{"channels": []}', '{"version": 1}', '{"channels": {"ntfy": "x", "gotify": {}}}']
)
def test_a_damaged_file_means_environment_only_values(store, tmp_path, caplog, content):
    path = tmp_path / "data" / "notify.json"
    path.parent.mkdir()
    path.write_text(content)
    with caplog.at_level(logging.ERROR, logger="notify"):
        cfg = store(NTFY_URL="https://ntfy.example.org/t")
    assert cfg.overrides == {} and cfg.source("ntfy") == "environment" and cfg.writable


def test_unknown_and_non_text_entries_in_the_file_are_ignored(store, tmp_path):
    path = tmp_path / "data" / "notify.json"
    path.parent.mkdir()
    path.write_text(
        json.dumps({"channels": {"ntfy": {"url": "https://n/t", "token": 5, "extra": "x"}, "other": {"a": "b"}}})
    )
    assert store().overrides == {"ntfy": {"url": "https://n/t"}}


# ---------------------------------------------------------------- notification buttons (#212)
def test_the_default_buttons_are_allow_once_and_deny(store):
    cfg = store()
    assert cfg.actions() == ("once", "deny") and cfg.ask_actions is None
    pub = cfg.public_actions()
    assert pub["value"] == ["once", "deny"] and pub["default"] == ["once", "deny"] and pub["custom"] is False
    assert pub["max"] == notifyconfig.MAX_ASK_ACTIONS == 4
    assert [c["action"] for c in pub["choices"]] == ["once", "hour", "always", "domain", "deny", "deny_always"]
    by = {c["action"]: c for c in pub["choices"]}
    assert by["always"] == {
        "action": "always",
        "label": "Allow host permanently",
        "effect": "a permanent allow rule for exactly this destination",
        "kind": "allow",
        "confirm": True,
    }
    assert [a for a, c in by.items() if c["confirm"]] == ["always", "domain"]  # the permanent allows
    assert [a for a, c in by.items() if c["kind"] == "deny"] == ["deny", "deny_always"]


def test_the_buttons_are_the_scopes_the_gateway_accepts_without_input():
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))
    from egressgw.policy import SCOPES

    assert set(notifyconfig.ASK_ACTIONS) == set(SCOPES) - {"allow"}  # `allow` needs a duration: UI only
    for action, (_, _, kind) in notifyconfig.ASK_ACTIONS.items():
        assert SCOPES[action][0] == kind  # a button labelled Deny never allows, and the other way round


def test_chosen_buttons_keep_their_order_and_survive_a_restart(store, tmp_path):
    cfg = store()
    assert cfg.set_actions(["deny_always", "always", "once"]) == ["deny_always", "always", "once"]
    assert cfg.actions() == ("deny_always", "always", "once") and cfg.public_actions()["custom"] is True
    path = tmp_path / "data" / "notify.json"
    assert json.loads(path.read_text())["ask_actions"] == ["deny_always", "always", "once"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert NotifyConfig(path).actions() == ("deny_always", "always", "once")
    # saving or removing a channel keeps the buttons, and saving the buttons keeps the channels
    cfg.update("ntfy", {"url": "https://ntfy.example.org/t"})
    cfg.set_actions(["deny"])
    cfg.remove("gotify")
    again = NotifyConfig(path)
    assert again.actions() == ("deny",) and again.effective("ntfy")["url"] == "https://ntfy.example.org/t"
    cfg.remove("ntfy")
    assert NotifyConfig(path).actions() == ("deny",)


def test_removing_the_chosen_buttons_returns_to_the_default(store, tmp_path):
    cfg = store()
    assert cfg.reset_actions() is False  # nothing saved: nothing written
    assert not (tmp_path / "data" / "notify.json").exists()
    cfg.set_actions(["always"])
    assert cfg.reset_actions() is True
    assert cfg.actions() == ("once", "deny") and cfg.ask_actions is None
    assert "ask_actions" not in json.loads((tmp_path / "data" / "notify.json").read_text())


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (None, "expected a list"),
        ("once", "expected a list"),
        ({"once": True}, "expected a list"),
        (["once", 1], "expected a list"),
        ([], "choose 1 to 4"),
        (["once", "hour", "always", "domain", "deny"], "choose 1 to 4"),
        (["once", "allow"], "unknown action 'allow'"),  # the free duration of the Approvals tab
        (["once", "everything"], "unknown action 'everything'"),
        (["Once"], "unknown action"),
        (["deny", "deny"], "each button can be chosen once"),
    ],
)
def test_bad_button_lists_are_refused_and_nothing_is_stored(store, tmp_path, value, message):
    cfg = store()
    cfg.set_actions(["deny"])
    with pytest.raises(ConfigError, match=message):
        cfg.set_actions(value)
    assert cfg.actions() == ("deny",) and NotifyConfig(tmp_path / "data" / "notify.json").actions() == ("deny",)


def test_an_unknown_action_is_not_echoed_at_length(store):
    with pytest.raises(ConfigError) as e:
        store().set_actions(["x" * 500])
    assert len(str(e.value)) < 200


@pytest.mark.parametrize("stored", [["always", "bogus"], "always", [], ["once"] * 2, None, ["a", "b", "c", "d", "e"]])
def test_invalid_stored_buttons_mean_the_default_never_more(store, tmp_path, caplog, stored):
    path = tmp_path / "data" / "notify.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({"version": 1, "channels": {"ntfy": {"url": "https://n.example.org/t"}}, "ask_actions": stored})
    )
    with caplog.at_level(logging.ERROR, logger="notify"):
        cfg = store()
    assert cfg.actions() == ("once", "deny") and cfg.ask_actions is None
    assert "notification buttons" in caplog.text and "using the default" in caplog.text
    assert cfg.effective("ntfy")["url"] == "https://n.example.org/t"  # the channels are still read


def test_buttons_cannot_be_saved_on_an_unwritable_volume(store, monkeypatch):
    cfg = store()
    cfg.set_actions(["deny"])
    cfg.writable = False
    with pytest.raises(ReadOnlyError):
        cfg.set_actions(["always"])
    with pytest.raises(ReadOnlyError):
        cfg.reset_actions()
    assert cfg.actions() == ("deny",)
    env_only = NotifyConfig(None)
    assert env_only.actions() == ("once", "deny")
    with pytest.raises(ReadOnlyError):
        env_only.set_actions(["deny"])


def test_the_domain_button_names_its_pattern():
    assert notifyconfig.ask_label("domain", "example.com") == "Allow *.example.com permanently"
    assert notifyconfig.ask_label("domain") == "Allow *.domain permanently"  # the name of the choice in Settings
    assert notifyconfig.ask_label("always", "example.com") == "Allow host permanently"
    assert notifyconfig.ask_label("deny_always", "example.com") == "Deny permanently"
