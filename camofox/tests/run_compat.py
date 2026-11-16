#!/usr/bin/env python3
"""Offline compatibility suite with explicit source roots and a disposable Hermes home.

Use a Python environment containing both projects' test dependencies. Example:
  python camofox/tests/run_compat.py --core-root ../hermes-agent \
      --web-access-root ../hermes-skills/skills/operations/web-access
Add --sidecar to run the complete sidecar suite (use xvfb-run on Linux).
No installed plugin/skill discovery, daemon calls, or production credentials.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core-root', required=True, type=Path)
    parser.add_argument('--web-access-root', required=True, type=Path)
    parser.add_argument('--sidecar', action='store_true')
    args, pytest_args = parser.parse_known_args()
    core = args.core_root.resolve()
    sidecar = args.web_access_root.resolve()
    plugin = Path(__file__).resolve().parents[1]
    for source in (core / 'agent/__init__.py', sidecar / 'scripts/server_camofox.py'):
        if not source.is_file():
            parser.error(f'missing required source: {source}')
    # Preserve runtime/dependency/display locations, never ambient service secrets.
    allowed = ('PATH', 'HOME', 'TMPDIR', 'DISPLAY', 'XAUTHORITY', 'LANG', 'PYTHONPATH')
    env = {name: os.environ[name] for name in allowed if name in os.environ}
    env.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', PYTHONDONTWRITEBYTECODE='1',
               WEB_ACCESS_TEST_ROOT=str(sidecar))
    env['PYTHONPATH'] = os.pathsep.join([str(core), str(sidecar / 'scripts'), env.get('PYTHONPATH', '')])
    with tempfile.TemporaryDirectory(prefix='camofox-compat-') as temporary:
        env['HERMES_HOME'] = str(Path(temporary) / 'home')
        Path(env['HERMES_HOME']).mkdir()
        target = sidecar / 'scripts' if args.sidecar else plugin / 'tests'
        print(f'Core source: {core}\nPlugin source: {plugin}\nSidecar source: {sidecar}', flush=True)
        command = [sys.executable, '-m', 'pytest', '-o', 'addopts=',
                   '--basetemp', str(Path(temporary) / 'pytest'), str(target), *pytest_args]
        return subprocess.call(command, cwd=sidecar if args.sidecar else plugin.parent, env=env)


if __name__ == '__main__':
    raise SystemExit(main())
