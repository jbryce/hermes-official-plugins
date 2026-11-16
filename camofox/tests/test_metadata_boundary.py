"""Metadata must not bypass the real vault boundary, including await/rehome races."""
import asyncio
import json

import pytest
from test_sidecar_compat import backend, Page
from camofox_plugin import camofox_client as client


def bind(rec):
    result = client.post('/vault/bind', {'tabId': rec.tab_id, 'userId': rec.user_id,
                                        'listItemId': rec.list_item_id})
    assert result['success'] is True


@pytest.mark.parametrize('race', ['before', 'during-title', 'later-title', 'rehome'])
def test_listing_sensitive_metadata_is_not_page_output(backend, race, monkeypatch):
    monkeypatch.setenv('CAMOFOX_USER_ID', 'metadata-fixture-user')
    pool, tool = backend
    tool('browser_navigate', {'url': 'https://example.test/account'}, task='a')
    tool('browser_navigate', {'url': 'https://example.test/other'}, task='b')
    first, second = pool._tabs.values()
    original = first.page
    original.title_value = 'split 1 8 2 7 3 6'
    if race == 'before':
        bind(first)
    async def title():
        # Exercise the actual bind route on the other server thread.
        await asyncio.to_thread(bind, first)
        original.url = 'https://example.test/1/8/2/7/3/6'
        if race == 'rehome':
            first.page = Page('https://ordinary.test/')
        return original.title_value
    if race in ('during-title', 'rehome'):
        original.title = title
    elif race == 'later-title':
        second.page.title = title
    result = client.get('/tabs', params={'userId': first.user_id})
    serialized = json.dumps(result)
    assert '1 8 2 7 3 6' not in serialized
    assert '/1/8/2/7/3/6' not in serialized
    assert result['tabs'][0]['tabId'] == first.tab_id


def test_new_sensitive_tab_does_not_expose_split_metadata(backend):
    pool, tool = backend
    tool('browser_navigate', {'url': 'https://example.test/account'})
    bind(next(iter(pool._tabs.values())))
    original_open = pool.open_tab
    async def open_tab(**kwargs):
        tid, page = await original_open(**kwargs)
        page.title_value = 'split 9 2 8 3 7 4'
        page.url = 'https://example.test/9/2/8/3/7/4'
        page.holding = True
        return tid, page
    pool.open_tab = open_tab
    result = client.post('/tabs', {'url': 'https://example.test/account',
                                  'userId': 'another', 'listItemId': 'new'})
    assert '9 2 8 3 7 4' not in json.dumps(result)
    assert '/9/2/8/3/7/4' not in json.dumps(result)


@pytest.mark.parametrize('holding', [True, 'error', False])
def test_registered_snapshot_identity_only_on_permitted_result(backend, holding):
    pool, tool = backend
    tool('browser_navigate', {'url': 'https://example.test/account'})
    rec = next(iter(pool._tabs.values()))
    bind(rec)
    rec.page.holding = holding
    result = tool('browser_snapshot')
    if holding is False:
        assert result['success'] is True
        assert result['session_identity'] == {'tabId': rec.tab_id, 'userId': rec.user_id,
                                              'listItemId': rec.list_item_id}
    else:
        assert result['success'] is False
        assert 'session_identity' not in result
