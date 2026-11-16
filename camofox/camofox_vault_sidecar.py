"""Protected web-access transport. Reuses /vault/bind and /vault/evaluate.

No ordinary evaluate fallback, tab adoption, redirects, ambient proxies/netrc,
logging, or retries. Values and the opaque lease never enter model output.
"""
from contextlib import contextmanager
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


class BoundPage:
    name = 'camofox'

    def __init__(self, url, headers, lease):
        self.url, self.headers, self.lease = url, headers, lease

    def evaluate(self, task_id, expression, *, secret=False):
        return self._evaluate(expression, secret=secret)

    def evaluate_secret(self, task_id, expression, *, redaction_values=()):
        return self._evaluate(expression, secret=True, redaction_values=redaction_values)

    def _evaluate(self, expression, *, secret, redaction_values=()):
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
    with client._sessions_lock:
        state = dict(client._sessions.get(client._session_key(task_id), {}))
    if not all(state.get(k) for k in ('tab_id', 'user_id', 'session_key')):
        raise RuntimeError('vault binding required')
    result = _post(url, headers, '/vault/bind', {
        'tabId': state['tab_id'], 'userId': state['user_id'],
        'listItemId': state['session_key']})
    if not isinstance(result.get('lease'), str) or not result['lease']:
        raise RuntimeError('vault binding refused')
    bound = BoundPage(url, headers, result['lease'])
    try:
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
