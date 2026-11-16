"""Registered plugin handlers -> real HTTP -> sidecar middleware, synthetic pages only."""
import asyncio
import json
import threading
import time

import pytest
from aiohttp import web
import camofox_plugin
from camofox_plugin import camofox_client as client
from test_plugin_registration import _Ctx
import server_camofox as server


class Page:
    def __init__(self, url):
        self.url = url
        self.holding = False
        self.title_value = 'Fixture title'
        self.title_hook = None
    async def title(self):
        if self.title_hook:
            self.title_hook(self)
        return self.title_value
    async def aria_snapshot(self, **kw):
        return '- heading "Fixture" [ref=e1]'
    async def evaluate(self, expr):
        if self.holding == 'error':
            raise RuntimeError('fixture probe failure')
        return self.holding


class Pool:
    def __init__(self):
        self._tabs = {}
        self.landed = None
        self.open_error = False
    async def open_tab(self, *, url, user_id, list_item_id):
        if self.open_error:
            raise server.NavigationError('fixture load failed')
        tid = f'tab-{len(self._tabs)+1}'
        page = Page(self.landed if self.landed is not None else url)
        self._tabs[tid] = server.TabRecord(tid, user_id, list_item_id, 'fixture-profile', page)
        return tid, page
    def get_tab(self, tid):
        return self._tabs.get(tid)
    def tabs_for_user(self, user):
        return [r for r in self._tabs.values() if r.user_id == user]
    async def navigate_tab(self, tid, url):
        if tid not in self._tabs:
            raise server.TabNotFound()
        if self.open_error:
            raise server.NavigationError('fixture load failed')
        self._tabs[tid].page.url = self.landed if self.landed is not None else url
        return self._tabs[tid].page


@pytest.fixture
def backend(monkeypatch):
    pool = Pool()
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    state = {}
    async def start():
        runner = web.AppRunner(server.make_app(pool=pool, started_at=time.monotonic()), access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', 0)
        await site.start()
        state.update(runner=runner, port=site._server.sockets[0].getsockname()[1])
    def serve():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(start())
        ready.set()
        loop.run_forever()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(10)
    monkeypatch.setenv('CAMOFOX_URL', f'http://127.0.0.1:{state["port"]}')
    monkeypatch.setenv('CAMOFOX_API_KEY', 'invented-fixture-bearer')
    ctx = _Ctx()
    camofox_plugin.register(ctx)
    def tool(name, args=None, task='fixture'):
        return json.loads(ctx.tools[name]['handler'](args or {}, task_id=task))
    yield pool, tool
    asyncio.run_coroutine_threadsafe(state['runner'].cleanup(), loop).result(10)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(10)
    loop.close()


def test_registered_handlers_use_file_fallback_against_authenticated_sidecar(backend, _isolated_home):
    from agent import secret_scope
    directory = _isolated_home / 'secrets'
    directory.mkdir()
    (directory / 'camofox-auth.env').write_text('CAMOFOX_API_KEY=invented-fixture-bearer\n')
    # The server reads its synthetic environment bearer; the client scope masks
    # that env value so its real requests must resolve the isolated token file.
    scope = secret_scope.set_secret_scope({'CAMOFOX_API_KEY': ''})
    try:
        pool, tool = backend
        result = tool('browser_navigate', {'url': 'https://example.test/account'})
        assert result['success'] is True
        assert tool('browser_snapshot')['session_identity']['tabId'] in pool._tabs
        (directory / 'camofox-auth.env').write_text('CAMOFOX_API_KEY=wrong-fixture\n')
        assert tool('browser_snapshot')['success'] is False
    finally:
        secret_scope.reset_secret_scope(scope)


def test_registered_new_tab_reports_actual_landed_url(backend):
    pool, tool = backend
    pool.landed = 'https://example.test/redirected'
    result = tool('browser_navigate', {'url': 'https://example.test/requested'})
    assert result['success'] is True
    assert result['url'] == pool.landed
    assert result['title'] == 'Fixture title'
    assert result['tab_created'] is True


def test_existing_tab_reuse_reports_navigated_url_and_title(backend):
    pool, tool = backend
    pool.landed = 'https://example.test/first'
    first = tool('browser_navigate', {'url': 'https://example.test/first'})
    assert first['success'] is True
    pool.landed = 'https://example.test/second'
    second = tool('browser_navigate', {'url': 'https://example.test/second'})
    assert second['success'] is True
    assert second['url'] == 'https://example.test/second'
    assert second['title'] == 'Fixture title'
    assert 'tab_created' not in second
    rec = next(iter(pool._tabs.values()))
    listing = client.get('/tabs', params={'userId': rec.user_id})
    assert listing == {'tabs': [{'tabId': rec.tab_id, 'listItemId': rec.list_item_id,
                                'url': second['url'], 'title': second['title']}]}


def test_navigate_load_failure_surfaces_as_failed_tool_result(backend):
    pool, tool = backend
    pool.open_error = True
    result = tool('browser_navigate', {'url': 'https://example.test/down'})
    assert result['success'] is False
    assert 'error' in result


def test_blank_target_after_navigation_is_reported_as_failure(backend):
    pool, tool = backend
    pool.landed = 'about:blank'
    result = tool('browser_navigate', {'url': 'https://example.test/blank-trap'})
    assert result['success'] is False
    assert 'still blank' in result['error']


def test_registered_value_in_new_tab_title_is_redacted(backend, monkeypatch):
    """Registered whole values are redacted even on ordinary, unbound pages."""
    pool, tool = backend
    from vault_redaction import register_vault_redaction_value
    secret_title = 'OTP-998877-secret'
    register_vault_redaction_value('998877')
    pool.landed = 'https://example.test/otp'

    def hook(page):
        page.title_value = secret_title
    orig_open = pool.open_tab
    async def open_and_mark(*, url, user_id, list_item_id):
        tid, page = await orig_open(url=url, user_id=user_id, list_item_id=list_item_id)
        page.title_hook = hook
        return tid, page
    monkeypatch.setattr(pool, 'open_tab', open_and_mark)
    result = tool('browser_navigate', {'url': 'https://example.test/otp'})
    assert result['success'] is True
    assert '998877' not in json.dumps(result)
