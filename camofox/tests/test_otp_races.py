"""Deterministic lifecycle races; no line numbers, live service or accounts."""
import threading
from types import SimpleNamespace

import pytest
from camofox_plugin import camofox_client as client
from camofox_plugin import camofox_vault_sidecar as transport
from test_otp_transport import otp as _otp_fixture

# Register the shared synthetic fixture without importing a test module plugin.
otp = _otp_fixture


@pytest.mark.parametrize('change', ['changed', 'removed', 'recreated', 'restored'])
@pytest.mark.parametrize('mode', ['password', 'code'])
def test_mapping_changes_during_bind_refused(otp, monkeypatch, change, mode):
    original = transport._post
    key = client._session_key('task')
    def post(url, headers, path, payload):
        if path == '/vault/bind':
            # Another thread must be able to finish cleanup during bind HTTP.
            def mutate():
                if change == 'restored':
                    state = client._sessions[key]
                    old = state['tab_id']
                    client.set_session_tab(state, 'replacement')
                    client.set_session_tab(state, old)
                    return
                with client._sessions_lock:
                    state = client._sessions[key]
                    if change == 'changed':
                        state['tab_id'] = 'replacement'
                    else:
                        client._sessions.pop(key)
                        if change == 'recreated':
                            client._sessions[key] = dict(state)
            worker = threading.Thread(target=mutate)
            worker.start()
            worker.join(2)
            assert not worker.is_alive(), 'mapping lock held during HTTP'
        return original(url, headers, path, payload)
    monkeypatch.setattr(transport, '_post', post)
    monkeypatch.setattr(transport.requests.Session, 'post', lambda *a, **kw: pytest.fail('stale dispatch'))
    operation = transport.operation if mode == 'password' else transport.code_operation
    with pytest.raises(RuntimeError):
        with operation('task'):
            pytest.fail('stale binding admitted')
    assert any(path == '/vault/release' for path, _ in otp)


@pytest.mark.parametrize('mode', ['password', 'code'])
def test_mapping_removed_after_bind_before_dispatch_refused(otp, monkeypatch, mode):
    monkeypatch.setattr(transport.requests.Session, 'post', lambda *a, **kw: pytest.fail('stale dispatch'))
    operation = transport.operation if mode == 'password' else transport.code_operation
    with operation('task') as bound:
        client.drop_session('task')
        if mode == 'password':
            with pytest.raises(RuntimeError, match='binding changed'):
                bound.evaluate('task', 'location.origin')
        else:
            assert bound.enter_code('task')['error_type'] == 'fill_outcome_unknown'
    assert not any(path == '/vault/evaluate' for path, _ in otp)


@pytest.mark.parametrize('success', [True, False])
def test_cancel_wins_response_classification(otp, monkeypatch, success):
    class ResponseData(dict):
        def get(self, key, default=None):
            if key == 'error_type':
                worker = threading.Thread(target=transport.cancel_code_task, args=('task',))
                worker.start()
                worker.join(2)
                assert not worker.is_alive(), 'response parsing holds lifecycle lock'
            return super().get(key, default)
    data = ResponseData(success=success, error_type='provider_not_applicable')
    monkeypatch.setattr(transport.requests.Session, 'post', lambda *a, **kw:
        SimpleNamespace(status_code=200, json=lambda: data))
    with transport.code_operation('task') as bound:
        assert bound.enter_code('task') == {'success': False, 'error_type': 'fill_outcome_unknown'}


@pytest.mark.parametrize('success', [True, False])
def test_completion_wins_before_finalization(otp, monkeypatch, success):
    data = {'success': success, 'error_type': 'provider_not_applicable'}
    monkeypatch.setattr(transport.requests.Session, 'post', lambda *a, **kw:
        SimpleNamespace(status_code=200, json=lambda: data))
    with transport.code_operation('task') as bound:
        result = bound.enter_code('task')
        transport.cancel_code_task('task')
        assert not bound.unknown
    assert result == ({'success': True, 'source': 'provider'} if success else data)
    assert not transport._code_pending
    assert not any(path == '/vault/cancel-code' for path, _ in otp)


def test_finalization_during_context_release_retains_unknown(otp, monkeypatch):
    original = transport._post
    def post(url, headers, path, payload):
        if path == '/vault/release':
            transport.cancel_code_task('task')
        return original(url, headers, path, payload)
    monkeypatch.setattr(transport, '_post', post)
    with transport.code_operation('task') as bound:
        pass
    assert bound.unknown
    assert transport._code_pending[client._session_key('task')][1] is bound


@pytest.mark.parametrize('revocation_fails', [False, True])
def test_cancelled_tombstone_does_not_retain_capabilities(otp, monkeypatch, revocation_fails):
    with transport.code_operation('task') as bound:
        bound.pending = True
    original = transport._post
    def revoke(url, headers, path, payload):
        if path == '/vault/cancel-code':
            assert headers['Authorization'] == 'Bearer fixture'
            assert payload['cancelToken'] == 'cancel-capability'
            if revocation_fails:
                raise TimeoutError()
        return original(url, headers, path, payload)
    monkeypatch.setattr(transport, '_post', revoke)
    transport.cancel_code_task('task')
    key = client._session_key('task')
    identity, tombstone = transport._code_pending[key]
    assert tombstone.unknown
    assert tombstone.headers == {}
    assert tombstone.lease is None
    assert tombstone.cancel_payload is None
    assert 'Bearer fixture' not in repr(identity)
    with transport.code_operation('task') as resumed:
        assert resumed.enter_code('task')['error_type'] == 'fill_outcome_unknown'
    assert sum(path == '/vault/cancel-code' for path, _ in otp) == (0 if revocation_fails else 1)
