"""Real JS + registered core handler + real registry + protected sidecar HTTP.
All browser traffic fulfilled locally; no live daemon, profile or accounts.
"""
import asyncio
import json
import tempfile
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

from aiohttp.test_utils import TestClient, TestServer
from camoufox.async_api import AsyncCamoufox
import pytest
import server_camofox
from camofox_plugin import camofox_client
from camofox_plugin.camofox_vault import make_page_backend

ORIGINS = ('https://password-fixture.example', 'https://second-fixture.example')
PASSWORD = 'synthetic-password-step3-browser'


@pytest.mark.parametrize('case', ['primary', 'secondary', 'untrusted', 'drift', 'rehome'])
def test_registered_password_real_browser(monkeypatch, write_config, case):
    from agent import browser_page_registry, vault_login_classifier, redact
    from agent.vault_store import VaultItemMeta
    from tools import browser_vault_tool
    from tools.registry import registry
    write_config('browser:\n  camofox:\n    vault_transport: sidecar\n')
    meta = VaultItemMeta(id='fixture:1', kind='login', label='Fixture', origin=ORIGINS[0],
                        created_at='2026-01-01T00:00:00Z', allowed_origins=ORIGINS)
    class Credentials:
        name, display_name, needs_unlock = 'fixture', 'Fixture', False
        def get_meta(self, handle): return meta
        def fill_context(self): return nullcontext()
        def resolve_password(self, handle): return PASSWORD
    monkeypatch.setattr('agent.vault_backends.backend_for_handle', lambda _: Credentials())
    page_backend = make_page_backend()
    monkeypatch.setattr(browser_page_registry._registry, 'list_providers', lambda: [page_backend])
    monkeypatch.setattr(browser_vault_tool, '_ensure_supervisor', lambda _: pytest.fail('CDP fallback'))

    async def run():
        async def route(r):
            await r.fulfill(body='<form><label>Password<input type="password" autocomplete="current-password"></label></form>', content_type='text/html')
        with tempfile.TemporaryDirectory(prefix='step3-browser-') as profile:
            async with AsyncCamoufox(headless=True, persistent_context=True, user_data_dir=profile) as context:
                await context.route('**/*', route)
                page = await context.new_page()
                origin = ORIGINS[1] if case == 'secondary' else ORIGINS[0]
                if case == 'untrusted': origin = 'https://untrusted-fixture.example'
                await page.goto(origin + '/login')
                rec = SimpleNamespace(tab_id='t', user_id='u', list_item_id='s', profile='fixture', page=page)
                pool = SimpleNamespace(get_tab={'t': rec}.get)
                monkeypatch.setenv('CAMOFOX_API_KEY', 'synthetic-browser-bearer')
                async with TestClient(TestServer(server_camofox.make_app(pool, started_at=0))) as http:
                    monkeypatch.setenv('CAMOFOX_URL', str(http.make_url('')).rstrip('/'))
                    monkeypatch.setattr(camofox_client, '_sessions', {camofox_client._session_key('fixture'):{'tab_id':'t','user_id':'u','session_key':'s'}})
                    original_build = vault_login_classifier.build_fill_js
                    loop = asyncio.get_running_loop()
                    replacement = None
                    if case == 'rehome':
                        replacement = await context.new_page()
                        await replacement.goto('https://untrusted-fixture.example/login')
                    built = []
                    def build(*args, **kwargs):
                        built.append(kwargs["expected_origin"])
                        if case == 'drift':
                            asyncio.run_coroutine_threadsafe(page.goto('https://untrusted-fixture.example/login'), loop).result(10)
                        elif case == 'rehome':
                            rec.page = replacement
                        return original_build(*args, **kwargs)
                    monkeypatch.setattr(vault_login_classifier, 'build_fill_js', build)
                    output = await asyncio.to_thread(registry.get_entry('browser_vault').handler,
                        {'action':'fill','handle':meta.id}, task_id='fixture')
                    result = json.loads(output)
                    assert PASSWORD not in output
                    assert built == ([] if case == 'untrusted' else [origin])
                    assert result['success'] is (case in ('primary', 'secondary')), result
                    filled = await page.locator('input').evaluate('(el) => el.value !== ""')
                    assert filled is (case in ('primary', 'secondary'))
                    if replacement:
                        assert not await replacement.locator('input').evaluate('(el) => el.value !== ""')
                    if filled:
                        assert await page.locator('input').evaluate('(el) => el.value === '+json.dumps(PASSWORD))
                        assert getattr(page, '_hermes_vault_sensitive', None) is not None
                        from vault_redaction import redact_registered_vault_values
                        assert PASSWORD not in redact_registered_vault_values(PASSWORD)
                        # Actual protected snapshot middleware must not disclose the field value.
                        r = await http.get('/tabs/t/snapshot', headers={'Authorization':'Bearer synthetic-browser-bearer'})
                        assert r.status == 200
                        assert PASSWORD not in await r.text()
    try:
        asyncio.run(run())
    finally:
        redact.clear_vault_redaction_values()
