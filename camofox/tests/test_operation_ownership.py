"""Operation routing must not leak through nested tasks or copied contexts."""
import asyncio
import contextvars
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest


@pytest.fixture
def routing(monkeypatch):
    from agent import browser_page_registry
    from tools import browser_vault_tool as tool
    events = []
    bound = SimpleNamespace(name='bound')
    @contextmanager
    def operation(task):
        events.append(('enter', task))
        try:
            yield bound
        finally:
            events.append(('exit', task))
    backend = SimpleNamespace(operation=operation)
    monkeypatch.setattr(browser_page_registry, 'backend_for_task', lambda task: backend)
    return tool, backend, bound, events


@pytest.mark.parametrize('task', ['outer', 'other'])
def test_nested_fill_task_ownership(routing, monkeypatch, task):
    tool, backend, bound, events = routing
    nested = False
    observed = []
    def lookup(handle):
        nonlocal nested
        if not nested:
            nested = True
            observed.extend([tool._page_backend('outer'), tool._page_backend('other')])
            tool.browser_vault_fill('fixture', task_id=task)
            observed.append(tool._page_backend('outer'))
        return None
    monkeypatch.setattr('agent.vault_backends.backend_for_handle', lookup)
    tool.browser_vault_fill('fixture', task_id='outer')
    assert observed == [bound, backend, bound]
    assert events == ([('enter', 'outer'), ('exit', 'outer')] if task == 'outer' else
                      [('enter', 'outer'), ('enter', 'other'), ('exit', 'other'), ('exit', 'outer')])
    assert tool._page_backend('outer') is backend


@pytest.mark.parametrize('failure', [RuntimeError, asyncio.CancelledError])
def test_operation_restored_on_exception_and_cancel(routing, monkeypatch, failure):
    tool, backend, bound, events = routing
    def lookup(handle):
        assert tool._page_backend('outer') is bound
        raise failure()
    monkeypatch.setattr('agent.vault_backends.backend_for_handle', lookup)
    if failure is asyncio.CancelledError:
        with pytest.raises(failure):
            tool.browser_vault_fill('fixture', task_id='outer')
    else:
        tool.browser_vault_fill('fixture', task_id='outer')
    assert tool._page_backend('outer') is backend
    assert events == [('enter', 'outer'), ('exit', 'outer')]


def test_copied_context_cannot_reuse_in_other_thread_or_after_exit(routing, monkeypatch):
    tool, backend, bound, events = routing
    saved, observed = [], []
    def lookup(handle):
        ctx = contextvars.copy_context()
        saved.append(ctx)
        thread = threading.Thread(target=lambda: observed.append(ctx.run(tool._page_backend, 'outer')))
        thread.start()
        thread.join()
        return None
    monkeypatch.setattr('agent.vault_backends.backend_for_handle', lookup)
    tool.browser_vault_fill('fixture', task_id='outer')
    assert observed == [backend]
    assert saved[0].run(tool._page_backend, 'outer') is backend


def test_copied_async_task_cannot_reuse_active_binding(routing, monkeypatch):
    tool, backend, bound, events = routing
    async def run():
        from agent.browser_page_backend import active_operation_page
        # Capture the real binding while the synchronous handler is inside it,
        # then keep the owning call active in the child coroutine's copied context.
        tasks = []
        def lookup(handle):
            async def inspect():
                return tool._page_backend('outer')
            tasks.append(asyncio.create_task(inspect()))
            return None
        monkeypatch.setattr('agent.vault_backends.backend_for_handle', lookup)
        tool.browser_vault_fill('fixture', task_id='outer')
        assert await tasks[0] is backend
        from agent.browser_page_backend import bind_operation_page
        with bind_operation_page('outer', bound):
            async def inspect_active():
                return tool._page_backend('outer')
            assert await asyncio.create_task(inspect_active()) is backend
            assert tool._page_backend('outer') is bound
        assert active_operation_page.get() is None
    asyncio.run(run())
