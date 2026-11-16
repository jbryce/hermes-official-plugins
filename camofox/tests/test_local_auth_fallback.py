"""Local daemon token-file fallback ported into the camofox plugin client (Step 2, item 3).

Mirrors the deleted core suite (tests/tools/test_browser_camofox_local_auth.py, preserved at
stash object 4e1c5ed6) against the plugin's own camofox_client module. Scoped-secret precedence,
fail-closed routed/multiplex profiles, literal-loopback-only resolution, and secret
containment (no file read on a routed-scope miss, no export to os.environ) are production
invariants this plugin must retain even though it now owns camofox_client itself.
"""
from __future__ import annotations

from unittest.mock import Mock

import pytest

from agent import secret_scope
from camofox_plugin import camofox_client as client
from hermes_constants import reset_hermes_home_override, set_hermes_home_override


@pytest.fixture(autouse=True)
def isolated_auth(_isolated_home, monkeypatch):
    monkeypatch.setenv("CAMOFOX_URL", "http://localhost:9223")
    monkeypatch.delenv("CAMOFOX_API_KEY", raising=False)
    monkeypatch.setattr(secret_scope, "_MULTIPLEX_ACTIVE", False)
    scope = secret_scope.set_secret_scope(None)
    multiplex = secret_scope.set_multiplex_context(False)
    home = set_hermes_home_override(None)
    yield _isolated_home
    reset_hermes_home_override(home)
    secret_scope.reset_multiplex_context(multiplex)
    secret_scope.reset_secret_scope(scope)


def write_token(home, name="camofox-auth.env", text="CAMOFOX_API_KEY=fixture-local\n"):
    directory = home / "secrets"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(text, encoding="utf-8")


def test_dedicated_file_precedes_daemon_file(isolated_auth):
    write_token(isolated_auth)
    write_token(isolated_auth, "web-access.env", "CAMOFOX_API_KEY=daemon-fixture\n")
    assert client._auth_headers() == {"Authorization": "Bearer fixture-local"}


def test_missing_dedicated_file_falls_back_to_daemon_file(isolated_auth):
    write_token(isolated_auth, "web-access.env", "CAMOFOX_API_KEY=daemon-fixture\n")
    assert client._auth_headers() == {"Authorization": "Bearer daemon-fixture"}


def test_missing_or_blank_files_leave_request_unauthenticated(isolated_auth):
    assert client._auth_headers() == {}
    write_token(isolated_auth, text="CAMOFOX_API_KEY=\" \"\n")
    write_token(isolated_auth, "web-access.env", "CAMOFOX_API_KEY=\n")
    assert client._auth_headers() == {}


def test_explicit_environment_key_wins_over_local_files(isolated_auth, monkeypatch):
    write_token(isolated_auth)
    monkeypatch.setenv("CAMOFOX_API_KEY", " explicit-fixture ")
    assert client._auth_headers() == {"Authorization": "Bearer explicit-fixture"}


def test_scoped_key_wins_over_environment_and_files(isolated_auth, monkeypatch):
    write_token(isolated_auth)
    monkeypatch.setenv("CAMOFOX_API_KEY", "environment-fixture")
    token = secret_scope.set_secret_scope({"CAMOFOX_API_KEY": "scope-fixture"})
    try:
        assert client._auth_headers() == {"Authorization": "Bearer scope-fixture"}
    finally:
        secret_scope.reset_secret_scope(token)


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]"])
def test_literal_loopback_hosts_read_local_files(isolated_auth, monkeypatch, host):
    write_token(isolated_auth)
    monkeypatch.setenv("CAMOFOX_URL", f"http://{host}:9223")
    assert client._auth_headers() == {"Authorization": "Bearer fixture-local"}


@pytest.mark.parametrize("url", [
    "https://remote.example", "http://localhost.evil.example:9223",
    "http://127.0.0.1.evil.example", "http://host.docker.internal:9223",
    "http://localhost.localdomain:9223", "http://127.1:9223",
    "http://2130706433:9223", "http://127.0.0.2:9223",
    "http://user@localhost:9223", "http://user:pass@localhost:9223",
    "ftp://localhost:9223", "http://localhost:bad", "http://localhost:65536",
    "", "localhost:9223", "http://[::1]evil:9223", "http://[::1]:",
    "http://localhost:", "http://local\nhost:9223", "http://localhost:9223?next=remote",
    "http://localhost:9223#fragment", "http://[::1", "http://localhost:0",
])
def test_nonliteral_or_invalid_endpoint_never_reads_local_files(isolated_auth, monkeypatch, url):
    write_token(isolated_auth)
    monkeypatch.setenv("CAMOFOX_URL", url)
    reader = Mock(side_effect=AssertionError("must not read credential files for a non-literal-loopback endpoint"))
    monkeypatch.setattr(client, "load_env_file", reader)
    assert client._auth_headers() == {}
    reader.assert_not_called()


def test_named_home_does_not_inherit_parent_token(isolated_auth, monkeypatch):
    write_token(isolated_auth)
    named = isolated_auth / "profiles" / "secondary"
    monkeypatch.setenv("HERMES_HOME", str(named))
    assert client._auth_headers() == {}
    write_token(named, text="CAMOFOX_API_KEY=secondary-fixture\n")
    assert client._auth_headers() == {"Authorization": "Bearer secondary-fixture"}


@pytest.mark.parametrize("routing", ["multiplex", "context", "override", "stamped-scope"])
def test_routed_scope_miss_never_reads_local_files_fail_closed(isolated_auth, monkeypatch, routing):
    write_token(isolated_auth)
    other = isolated_auth / "profiles" / "secondary"
    write_token(other, text="CAMOFOX_API_KEY=secondary-fixture\n")
    monkeypatch.setenv("CAMOFOX_API_KEY", "launch-fixture")
    token = secret_scope.set_secret_scope(
        {"CAMOFOX_URL": "http://localhost:9223"},
        profile_home=str(other) if routing == "stamped-scope" else None,
    )
    home = set_hermes_home_override(other if routing == "override" else None)
    context = secret_scope.set_multiplex_context(routing == "context")
    monkeypatch.setattr(secret_scope, "_MULTIPLEX_ACTIVE", routing == "multiplex")
    reader = Mock(side_effect=AssertionError("a routed scope miss must stay a miss, not fall through to local files"))
    monkeypatch.setattr(client, "load_env_file", reader)
    try:
        assert client._auth_headers() == {}
        reader.assert_not_called()
    finally:
        secret_scope.reset_multiplex_context(context)
        reset_hermes_home_override(home)
        secret_scope.reset_secret_scope(token)


def test_multiplex_without_scope_still_raises(isolated_auth, monkeypatch):
    write_token(isolated_auth)
    monkeypatch.setattr(secret_scope, "_MULTIPLEX_ACTIVE", True)
    with pytest.raises(secret_scope.UnscopedSecretError):
        client._auth_headers()


def test_requests_use_the_fallback_header_without_exporting_secrets_to_os_environ(isolated_auth, monkeypatch):
    import json
    import os
    from unittest.mock import Mock as _Mock

    write_token(isolated_auth, "web-access.env", "CAMOFOX_API_KEY=daemon-fixture\nUNRELATED_KEY=ignored\n")
    response = _Mock()
    response.json.return_value = {"tabs": []}
    response.raise_for_status = _Mock()
    get = _Mock(return_value=response)
    monkeypatch.setattr(client.requests, "get", get)
    assert client.get("/tabs", params={"userId": "fixture"}) == {"tabs": []}
    assert get.call_args.args[0] == "http://localhost:9223/tabs"
    assert get.call_args.kwargs["headers"] == {"Authorization": "Bearer daemon-fixture"}
    assert "CAMOFOX_API_KEY" not in os.environ
    assert "UNRELATED_KEY" not in os.environ
