"""Provider transport lifecycle with synthetic responses only."""
from types import SimpleNamespace
import pytest
from camofox_plugin import camofox_client as client
from camofox_plugin import camofox_vault_sidecar as transport


@pytest.fixture
def otp(monkeypatch):
    transport._code_pending.clear()
    transport._code_active.clear()
    monkeypatch.setattr(client, 'get_camofox_url', lambda: 'http://127.0.0.1:1')
    monkeypatch.setattr(client, '_auth_headers', lambda: {'Authorization':'Bearer fixture'})
    client._sessions[client._session_key('task')] = dict(tab_id='t', user_id='u', session_key='s')
    calls = []
    def post(url, headers, path, payload):
        calls.append((path, payload))
        return {'success': True, 'lease':'opaque', 'cancelToken':'cancel-capability'}
    monkeypatch.setattr(transport, '_post', post)
    yield calls
    transport._code_pending.clear()
    transport._code_active.clear()


def test_unknown_http_cancels_once_and_never_redispatches(otp, monkeypatch):
    dispatches = []
    def post(*a, **kw):
        dispatches.append(1)
        raise TimeoutError('must not appear')
    monkeypatch.setattr(transport.requests.Session, 'post', post)
    with transport.code_operation('task') as bound:
        assert bound.enter_code('task')['error_type'] == 'fill_outcome_unknown'
    assert [p for p, _ in otp].count('/vault/cancel-code') == 1
    with transport.code_operation('task') as bound:
        assert bound.enter_code('task')['error_type'] == 'fill_outcome_unknown'
    assert len(dispatches) == 1


def test_failed_resume_bind_does_not_lose_unknown_tombstone(otp, monkeypatch):
    monkeypatch.setattr(transport.requests.Session, 'post', lambda *a, **kw: (_ for _ in ()).throw(TimeoutError()))
    with transport.code_operation('task') as bound:
        bound.enter_code('task')
    original = transport._post
    monkeypatch.setattr(transport, '_post', lambda *a, **kw: (_ for _ in ()).throw(RuntimeError()))
    with pytest.raises(RuntimeError):
        with transport.code_operation('task'):
            pass
    monkeypatch.setattr(transport, '_post', original)
    with transport.code_operation('task') as resumed:
        assert resumed is bound
        assert resumed.unknown


def test_finalize_during_bind_prevents_provider_dispatch(otp, monkeypatch):
    original = transport._post
    def post(url, headers, path, payload):
        if path == '/vault/bind':
            transport.cancel_code_task('task')
        return original(url, headers, path, payload)
    monkeypatch.setattr(transport, '_post', post)
    with transport.code_operation('task') as bound:
        assert bound.unknown
    assert [p for p, _ in otp].count('/vault/cancel-code') == 1


def test_session_change_during_bind_refuses(otp, monkeypatch):
    from contextlib import contextmanager
    original = transport.operation
    @contextmanager
    def changed(task):
        client._sessions[client._session_key(task)]['tab_id'] = 'other'
        with original(task) as page:
            yield page
    monkeypatch.setattr(transport, 'operation', changed)
    with pytest.raises(RuntimeError):
        with transport.code_operation('task'):
            pass


def test_finalize_cancels_active_poll(otp):
    with transport.code_operation('task') as bound:
        transport.cancel_code_task('task')
        assert bound.unknown
    assert [p for p, _ in otp].count('/vault/cancel-code') == 1


def test_cancel_during_http_response_remains_unknown(otp, monkeypatch):
    def post(*a, **kw):
        transport.cancel_code_task('task')
        return SimpleNamespace(status_code=200, json=lambda: {'success':True})
    monkeypatch.setattr(transport.requests.Session, 'post', post)
    with transport.code_operation('task') as bound:
        assert bound.enter_code('task')['error_type'] == 'fill_outcome_unknown'


@pytest.mark.parametrize('kind', ['otp_outcome_unknown', 'fill_outcome_unknown'])
def test_provider_unknown_is_quarantined(otp, monkeypatch, kind):
    calls = []
    def post(*a, **kw):
        calls.append(1)
        return SimpleNamespace(status_code=200, json=lambda: {'success':False, 'error_type':kind})
    monkeypatch.setattr(transport.requests.Session, 'post', post)
    with transport.code_operation('task') as bound:
        assert bound.enter_code('task')['error_type'] == 'fill_outcome_unknown'
    with transport.code_operation('task') as bound:
        assert bound.enter_code('task')['error_type'] == 'fill_outcome_unknown'
    assert len(calls) == 1


def test_exception_in_operation_revokes_code_capability(otp):
    with pytest.raises(RuntimeError):
        with transport.code_operation('task'):
            raise RuntimeError('cancelled')
    assert [p for p, _ in otp].count('/vault/cancel-code') == 1


@pytest.mark.parametrize('status,data', [(409, {'success':True}), (200, {'error_type':'provider_not_applicable'}), (409, {'success':False, 'error_type':'provider_not_applicable'})])
def test_malformed_provider_response_never_allows_fallback(otp, monkeypatch, status, data):
    monkeypatch.setattr(transport.requests.Session, 'post', lambda *a, **kw: SimpleNamespace(status_code=status, json=lambda:data))
    with transport.code_operation('task') as bound:
        assert bound.enter_code('task')['error_type'] == 'fill_outcome_unknown'


def test_pending_singleflight_resume_no_token_in_result(otp, monkeypatch):
    results = iter([{'success':False, 'error_type':'otp_pending', 'secret':'not-output'}, {'success':True, 'code':'not-output'}])
    monkeypatch.setattr(transport.requests.Session, 'post', lambda *a, **kw: SimpleNamespace(status_code=200, json=lambda: next(results)))
    with transport.code_operation('task') as bound:
        assert bound.enter_code('task') == {'success':False, 'error_type':'otp_pending'}
        with pytest.raises(RuntimeError):
            with transport.code_operation('task'):
                pass
    with transport.code_operation('task') as resumed:
        assert resumed is bound
        assert resumed.enter_code('task') == {'success':True, 'source':'provider'}
    assert not transport._code_pending
