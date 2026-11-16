"""Registered core vault handler -> canonical plugin -> real isolated sidecar HTTP.

All credentials and pages here are synthetic; no installed daemon/profile access.
"""
import json
from contextlib import contextmanager

import pytest
from test_sidecar_compat import backend, Page
from camofox_plugin.camofox_vault import make_page_backend

PASSWORD = 'invented-password-Step3-only'
CONTROLS = [{'index': 0, 'formIndex': 0, 'type': 'password',
             'autocomplete': 'current-password', 'name': 'password'}]


@pytest.fixture
def password_tool(backend, monkeypatch, tmp_path, write_config):
    write_config('browser:\n  camofox:\n    vault_transport: sidecar\n')
    from agent.vault_store import VaultStore
    from agent.vault_backends.local import LocalLoginBackend
    from agent import browser_page_registry, redact
    from tools import browser_vault_tool
    from tools.registry import registry

    pool, navigate = backend
    assert navigate('browser_navigate', {'url': 'https://example.test/login'})['success']
    page = next(iter(pool._tabs.values())).page
    page.writes = []
    async def evaluate(expression):
        if 'expectedOrigin' in expression:
            page.writes.append(expression)
            return {'filled': 1, 'untrusted_extra': PASSWORD}
        if 'window.location.href' in expression:
            return page.url
        return CONTROLS
    page.evaluate = evaluate
    store = VaultStore(base_dir=tmp_path / 'vault')
    meta = store.add_item('login', 'Synthetic', {'identifier_type': 'username',
        'identifier': 'fixture', 'password': PASSWORD}, origin='https://example.test')
    monkeypatch.setattr('agent.vault_store.get_vault_store', lambda: store)
    monkeypatch.setattr('agent.vault_backends.backend_for_handle', lambda _: LocalLoginBackend())
    page_backend = make_page_backend()
    monkeypatch.setattr(browser_page_registry, 'backend_for_task', lambda _: page_backend)
    monkeypatch.setattr(browser_vault_tool, '_ensure_supervisor', lambda _: pytest.fail('CDP fallback'))
    def fill():
        return json.loads(registry.get_entry('browser_vault').handler(
            {'action': 'fill', 'handle': meta.id}, task_id='fixture'))
    yield pool, page, page_backend, fill
    redact.clear_vault_redaction_values()


def test_registered_password_enters_one_operation_context(password_tool):
    """Narrow proof that core must delimit the complete inspection/fill lifecycle."""
    pool, page, page_backend, fill = password_tool
    events = []
    @contextmanager
    def operation(task_id):
        events.append('enter')
        try:
            yield page_backend
        finally:
            events.append('exit')
    page_backend.operation = operation
    fill()
    assert events == ['enter', 'exit']


def test_registered_password_uses_protected_binding_and_redaction(password_tool):
    pool, page, page_backend, fill = password_tool
    result = fill()
    assert result['success'] is True, result
    assert len(page.writes) == 1
    assert getattr(page, '_hermes_vault_sensitive', None) is not None
    from vault_redaction import redact_registered_vault_values
    assert PASSWORD not in redact_registered_vault_values(PASSWORD)
    assert PASSWORD not in json.dumps(result)


def test_registered_password_refusal_releases_unused_lease(password_tool, monkeypatch):
    pool, page, page_backend, fill = password_tool
    from camofox_plugin import camofox_vault_sidecar as transport
    calls = []
    post = transport._post
    def record(url, headers, path, payload):
        result = post(url, headers, path, payload)
        if path == '/vault/bind':
            calls.append((url, headers, result['lease']))
        return result
    monkeypatch.setattr(transport, '_post', record)
    async def no_controls(expression):
        return page.url if 'window.location.href' in expression else []
    page.evaluate = no_controls
    assert fill()['success'] is False
    url, headers, lease = calls[0]
    with pytest.raises(RuntimeError, match='refused'):
        post(url, headers, '/vault/evaluate', {'lease': lease,
             'expression': 'window.location.href', 'secret': False})


def test_registered_password_missing_session_never_falls_back(password_tool):
    pool, page, page_backend, fill = password_tool
    from camofox_plugin import camofox_client
    camofox_client._sessions.clear()
    assert page_backend.has_page('fixture') is False
    assert fill()['success'] is False
    assert page.writes == []


def test_registered_password_refuses_on_tab_rehome_during_fill(password_tool, monkeypatch):
    """Mid-operation the bound tab is swapped to a different page object (as a
    real rehome would do); the lease's bound-page identity check must refuse
    rather than writing the secret into the swapped-in page."""
    pool, page, page_backend, fill = password_tool
    from test_sidecar_compat import Page
    from agent import vault_login_classifier
    attacker_page = Page('https://attacker.test/')
    attacker_page.writes = []
    async def attacker_evaluate(expression):
        if 'expectedOrigin' in expression:
            attacker_page.writes.append(expression)
            return {'filled': 1}
        return page.url if 'window.location.href' in expression else []
    attacker_page.evaluate = attacker_evaluate
    real_build_fill_js = vault_login_classifier.build_fill_js
    rec = next(iter(pool._tabs.values()))

    def build_fill_js(*args, **kwargs):
        rec.page = attacker_page  # simulates a same-tab-id rehome mid-operation
        return real_build_fill_js(*args, **kwargs)
    monkeypatch.setattr(vault_login_classifier, 'build_fill_js', build_fill_js)
    result = fill()
    assert attacker_page.writes == []
    assert result['success'] is False
