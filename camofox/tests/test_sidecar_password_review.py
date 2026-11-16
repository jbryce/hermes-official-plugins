"""Independent Step3 regressions; real registered tool and isolated HTTP."""
import pytest
from agent.browser_page_registry import backend_for_task as real_lookup
from test_sidecar_password import password_tool
from test_sidecar_compat import backend


@pytest.mark.parametrize('missing', ['session', 'url'])
def test_unavailable_sidecar_with_real_registry_never_uses_cdp(password_tool, monkeypatch, missing):
    from agent import browser_page_registry
    from camofox_plugin import camofox_client
    pool, page, page_backend, fill = password_tool
    monkeypatch.setattr(browser_page_registry, 'backend_for_task', real_lookup)
    monkeypatch.setattr(browser_page_registry._registry, 'list_providers', lambda: [page_backend])
    if missing == 'session':
        camofox_client._sessions.clear()
    else:
        monkeypatch.setattr(camofox_client, 'get_camofox_url', lambda: '')
    assert fill()['success'] is False
    assert page.writes == []


@pytest.mark.parametrize('outcome', ['success', 'exception', 'cancel'])
def test_operation_http_lease_cleanup_and_replay(password_tool, monkeypatch, outcome):
    import asyncio
    from tools import browser_vault_tool
    from agent.browser_page_backend import active_operation_page
    from camofox_plugin import camofox_vault_sidecar as transport
    pool, page, page_backend, fill = password_tool
    bindings = []
    post = transport._post
    def record(url, headers, path, payload):
        result = post(url, headers, path, payload)
        if path == '/vault/bind':
            bindings.append((url, headers, result['lease']))
        return result
    monkeypatch.setattr(transport, '_post', record)
    if outcome != 'success':
        def fail(*args, **kwargs):
            raise (asyncio.CancelledError() if outcome == 'cancel' else RuntimeError('synthetic failure'))
        monkeypatch.setattr(browser_vault_tool, '_fill_bound_page', fail)
    if outcome == 'cancel':
        with pytest.raises(asyncio.CancelledError):
            fill()
    else:
        assert fill()['success'] is (outcome == 'success')
    assert active_operation_page.get() is None
    assert len(bindings) == 1
    url, headers, lease = bindings[0]
    with pytest.raises(RuntimeError, match='refused'):
        post(url, headers, '/vault/evaluate', {'lease':lease, 'expression':'location.href'})
    assert len(page.writes) == (1 if outcome == 'success' else 0)
