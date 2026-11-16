"""Sidecar-only HTTP-level regression: new /tabs response fields (url, title) added for
plugin compatibility must still go through server_vault's existing sensitive-page output
restrictions, never leak secret-bearing title/url text raw."""
import time

import pytest
from aiohttp.test_utils import AioHTTPTestCase

import server_camofox as server
from vault_redaction import register_vault_redaction_value


class Page:
    def __init__(self, url):
        self.url = url
        self.title_value = 'Fixture title'

    async def title(self):
        return self.title_value

    async def aria_snapshot(self, **kw):
        return '- heading "Fixture" [ref=e1]'

    async def evaluate(self, expr):
        return False


class Pool:
    def __init__(self):
        self._tabs = {}

    async def open_tab(self, *, url, user_id, list_item_id):
        tid = f'tab-{len(self._tabs)+1}'
        page = Page(url)
        self._tabs[tid] = server.TabRecord(tid, user_id, list_item_id, 'fixture-profile', page)
        return tid, page

    def get_tab(self, tid):
        return self._tabs.get(tid)

    def tabs_for_user(self, user):
        return [r for r in self._tabs.values() if r.user_id == user]

    async def navigate_tab(self, tid, url):
        rec = self._tabs[tid]
        rec.page.url = url
        return rec.page


class VaultSensitiveResponseFieldsTests(AioHTTPTestCase):
    async def get_application(self):
        self._pool = Pool()
        return server.make_app(pool=self._pool, started_at=time.monotonic())

    async def test_sensitive_tab_title_in_new_tab_fields_is_redacted(self):
        create = await self.client.post('/tabs', json={
            'userId': 'u1', 'listItemId': 'l1', 'url': 'https://otp.example/login'})
        tab_id = (await create.json())['tabId']
        self._pool.get_tab(tab_id).page.title_value = 'code is OTP-554433'
        register_vault_redaction_value('554433')

        bind = await self.client.post('/vault/bind', json={
            'tabId': tab_id, 'userId': 'u1', 'listItemId': 'l1'},
            headers={'Authorization': 'Bearer fixture-vault-key'})
        assert bind.status == 403, 'this fixture app has no CAMOFOX_API_KEY set; bind must refuse, not silently pass'

    async def test_new_tab_response_fields_are_never_raw_secret_bypassing_redaction(self):
        register_vault_redaction_value('778899')
        create = await self.client.post('/tabs', json={
            'userId': 'u2', 'listItemId': 'l2', 'url': 'https://example.test/778899'})
        body = await create.text()
        assert '778899' not in body

    async def test_list_tabs_fields_are_never_raw_secret_bypassing_redaction(self):
        register_vault_redaction_value('334455')
        create = await self.client.post('/tabs', json={
            'userId': 'u3', 'listItemId': 'l3', 'url': 'https://example.test/x'})
        tab_id = (await create.json())['tabId']
        self._pool.get_tab(tab_id).page.title_value = 'secret 334455 in title'
        listing = await self.client.get('/tabs', params={'userId': 'u3'})
        body = await listing.text()
        assert '334455' not in body
