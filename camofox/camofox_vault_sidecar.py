"""Protected web-access transport. Reuses /vault/bind and /vault/evaluate.

No ordinary evaluate fallback, tab adoption, redirects, ambient proxies/netrc,
logging, or retries. Values and the opaque lease never enter model output.
"""
from contextlib import contextmanager
import hashlib
import threading
from urllib.parse import urlsplit

import requests

from . import camofox_client as client


def _post(url, headers, path, payload):
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.post(url + path, headers=headers, json=payload,
                                    timeout=20, allow_redirects=False)
            if response.status_code != 200:
                raise RuntimeError('vault transport refused')
            data = response.json()
            if not isinstance(data, dict) or data.get('success') is not True:
                raise RuntimeError('vault transport refused')
            return data
    except Exception:
        raise RuntimeError('vault transport refused') from None


def _identity(url, headers, state):
    # Compare transport identity without retaining a bearer in tombstone keys.
    bearer_id = hashlib.sha256(headers.get('Authorization', '').encode()).digest()
    return (url, bearer_id, state.get('tab_id'), state.get('user_id'), state.get('session_key'))


class BoundPage:
    name = 'camofox'

    def __init__(self, url, headers, lease):
        self.url, self.headers, self.lease = url, headers, lease

    def admit(self):
        with client._sessions_lock:
            if not client.binding_valid(self.task_id, self.snapshot):
                raise RuntimeError('vault binding changed')

    def evaluate(self, task_id, expression, *, secret=False):
        return self._evaluate(expression, secret=secret)

    def evaluate_secret(self, task_id, expression, *, redaction_values=()):
        return self._evaluate(expression, secret=True, redaction_values=redaction_values)

    def _evaluate(self, expression, *, secret, redaction_values=()):
        self.admit()
        if self.lease is None:
            raise RuntimeError('vault binding expired')
        lease = self.lease
        if secret:
            self.lease = None  # uncertain write outcomes must never be retried
        result = _post(self.url, self.headers, '/vault/evaluate', {
            'lease': lease, 'expression': expression, 'secret': secret,
            'redaction_values': list(redaction_values)})
        if 'result' not in result:
            raise RuntimeError('vault transport refused')
        return result['result']


# Continuations stay process-private, partitioned by task and immutable client
# identity. Server leases additionally bind Page, profile and origin.
_code_lock = threading.Lock()
_code_active = {}
_code_pending = {}
_code_cancelled = set()


class CodePage(BoundPage):
    pending = False
    unknown = False
    cancel_payload = None
    completed = False

    def _cancel_locked(self):
        if self.completed:
            return None
        self.unknown = True
        payload, self.cancel_payload = self.cancel_payload, None
        revocation = (self.url, self.headers, payload) if payload is not None else None
        self.headers = {}
        self.lease = None
        return revocation

    def _revoke(self, revocation):
        if revocation is not None:
            url, headers, payload = revocation
            try:
                _post(url, headers, '/vault/cancel-code', payload)
            except Exception:
                pass

    def cancel(self):
        # One cancellation dispatch, never a retry. Retain the unknown tombstone
        # even if revocation succeeds: it cannot undo an already-dispatched fill.
        with _code_lock:
            payload = self._cancel_locked()
        self._revoke(payload)

    def enter_code(self, task_id):
        with _code_lock:
            if self.unknown or self.completed:
                return {'success': False, 'error_type': 'fill_outcome_unknown'}
            headers, lease = self.headers, self.lease
        try:
            self.admit()
            with requests.Session() as session:
                session.trust_env = False
                response = session.post(self.url + '/vault/enter-code',
                    headers=headers, json={'lease': lease},
                    timeout=20, allow_redirects=False)
                data = response.json()
                if response.status_code not in (200, 403, 409) or not isinstance(data, dict):
                    raise ValueError('invalid provider response')
            kind = data.get('error_type')
            if (type(data.get('success')) is not bool
                    or (response.status_code != 200 and
                        (data['success'] or kind in ('provider_not_applicable', 'otp_pending')))):
                raise ValueError('invalid provider response')
            if kind in ('otp_outcome_unknown', 'fill_outcome_unknown'):
                self.cancel()
                return {'success': False, 'error_type': 'fill_outcome_unknown'}
            allowed = {'provider_not_applicable', 'otp_pending',
                'otp_poll_in_progress', 'challenge_binding_refused',
                'binding_expired', 'origin_changed', 'otp_provider_failed'}
            if kind not in allowed:
                kind = 'otp_provider_failed'
            success = data.get('success') is True
            # Response classification is outside the lock. Commit and finalization
            # have one linearization point, with no network I/O under this lock.
            with _code_lock:
                if self.unknown:
                    return {'success': False, 'error_type': 'fill_outcome_unknown'}
                self.pending = not success and kind == 'otp_pending'
                self.completed = not self.pending
                if success:
                    self.lease = None
                if self.completed:
                    self.cancel_payload = None
                return ({'success': True, 'source': 'provider'} if success else
                        {'success': False, 'error_type': kind})
        except Exception:
            # Never redispatch after an ambiguous transport outcome. Keep a
            # tombstone even if cancellation cannot reach the service.
            self.cancel()
            return {'success': False, 'error_type': 'fill_outcome_unknown'}


def cancel_code_task(task_id):
    """Session-finalization revocation, independent of password/turn cleanup."""
    key = client._session_key(task_id)
    with _code_lock:
        bound = _code_active.get(key)
        pending = _code_pending.get(key)
        if key in _code_active and bound is None:
            _code_cancelled.add(key)
        target = bound if bound is not None else (pending[1] if pending else None)
        payload = target._cancel_locked() if target is not None else None
    if target is not None:
        target._revoke(payload)


@contextmanager
def code_operation(task_id):
    key = client._session_key(task_id)
    snapshot = client.binding_snapshot(task_id)
    state = snapshot[1]
    identity = _identity(client.get_camofox_url(), client._auth_headers(), state)
    with _code_lock:
        if key in _code_active:
            raise RuntimeError('code operation in progress')
        _code_active[key] = None
        previous = _code_pending.get(key)
    bound = None
    try:
        with operation(task_id) as fresh:
            with client._sessions_lock:
                if fresh.identity != identity or not client.binding_valid(task_id, snapshot):
                    raise RuntimeError('code binding changed')
            if previous is not None and previous[0] != identity:
                previous[1].cancel()
            if previous is not None and previous[0] == identity:
                bound = previous[1]
            else:
                bound = CodePage(fresh.url, fresh.headers, fresh.lease)
                bound.task_id, bound.snapshot = task_id, snapshot
                bound.cancel_payload = fresh.cancel_payload
                if bound.cancel_payload is None:
                    raise RuntimeError('code cancellation capability required')
                fresh.lease = None
            with _code_lock:
                _code_active[key] = bound
                cancelled = key in _code_cancelled
            if cancelled:
                bound.cancel()
            try:
                yield bound
            except BaseException:
                bound.cancel()
                raise
            finally:
                if not (bound.pending or bound.unknown) and bound.lease is not None:
                    try:
                        _post(bound.url, bound.headers, '/vault/release', {'lease': bound.lease})
                    except Exception:
                        pass
                    bound.lease = None
    finally:
        with _code_lock:
            # Publish continuation/tombstone and retire active ownership together.
            # Finalization cannot land between a stale decision and removal.
            if bound is not None:
                if bound.pending or bound.unknown:
                    _code_pending[key] = (identity, bound)
                else:
                    _code_pending.pop(key, None)
            _code_active.pop(key, None)
            _code_cancelled.discard(key)


@contextmanager
def operation(task_id):
    url = client.get_camofox_url()
    parsed = urlsplit(url)
    if (parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', '::1')
            or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment
            or any(ord(c) <= 32 or ord(c) == 127 for c in url)):
        raise RuntimeError('vault local transport required')
    headers = client._auth_headers()
    if not headers.get('Authorization'):
        raise RuntimeError('vault authentication required')
    snapshot = client.binding_snapshot(task_id)
    state = snapshot[1]
    if not all(state.get(k) for k in ('tab_id', 'user_id', 'session_key')):
        raise RuntimeError('vault binding required')
    result = _post(url, headers, '/vault/bind', {
        'tabId': state['tab_id'], 'userId': state['user_id'],
        'listItemId': state['session_key']})
    if not isinstance(result.get('lease'), str) or not result['lease']:
        raise RuntimeError('vault binding refused')
    bound = BoundPage(url, headers, result['lease'])
    bound.task_id, bound.snapshot = task_id, snapshot
    bound.identity = _identity(url, headers, state)
    bound.cancel_payload = None
    if isinstance(result.get('cancelToken'), str) and result['cancelToken']:
        bound.cancel_payload = {'lease': result['lease'], 'cancelToken': result['cancelToken'],
            'tabId': state['tab_id'], 'userId': state['user_id'], 'listItemId': state['session_key']}
    try:
        bound.admit()
        yield bound
    finally:
        lease, bound.lease = bound.lease, None
        if lease is not None:
            try:
                _post(url, headers, '/vault/release', {'lease': lease})
            except Exception:
                # No retry, no error-body diagnostics. Server TTL remains the
                # backstop if transport loss prevents explicit cancellation.
                pass
