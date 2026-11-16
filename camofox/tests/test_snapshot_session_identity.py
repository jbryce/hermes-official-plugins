"""session_identity restoration in browser_snapshot (registered plugin path)."""
import json

import pytest

import camofox_plugin
from test_plugin_registration import _Ctx


def test_snapshot_includes_session_identity_tab_user_list_item(camofox):
    ctx = _Ctx()
    camofox_plugin.register(ctx)
    nav = json.loads(ctx.tools['browser_navigate']['handler']({'url': 'https://example.com'}, task_id='ident-1'))
    assert nav['success'] is True
    result = json.loads(ctx.tools['browser_snapshot']['handler']({}, task_id='ident-1'))
    assert result['success'] is True
    identity = result['session_identity']
    assert identity['tabId'] and isinstance(identity['tabId'], str)
    assert identity['userId'].startswith('hermes_')
    assert identity['listItemId'] == 'task_ident-1'


def test_session_identity_is_only_routing_metadata_never_the_raw_session_dict(camofox):
    ctx = _Ctx()
    camofox_plugin.register(ctx)
    json.loads(ctx.tools['browser_navigate']['handler']({'url': 'https://example.com'}, task_id='ident-2'))
    result = json.loads(ctx.tools['browser_snapshot']['handler']({}, task_id='ident-2'))
    identity = result['session_identity']
    assert set(identity) == {'tabId', 'userId', 'listItemId'}
    assert 'managed' not in identity and 'adopt_existing_tab' not in identity
