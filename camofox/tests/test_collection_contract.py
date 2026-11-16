"""Exercise optional-sidecar discovery in a fresh interpreter, not cached imports."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


SIDECAR_MODULES = {
    "test_sidecar_compat.py", "test_metadata_boundary.py",
    "test_sidecar_tab_field_redaction.py", "test_sidecar_password.py",
    "test_sidecar_password_browser.py", "test_sidecar_password_review.py",
}


@pytest.mark.parametrize("with_sidecar", [False, True])
def test_optional_sidecar_collection(request, tmp_path, with_sidecar):
    root = request.config.getoption("--web-access-root")
    if with_sidecar and not root:
        pytest.skip("explicit sidecar checkout required for opt-in collection")
    # Keep dependency/core paths but remove the optional checkout and its opt-in.
    env = {key: os.environ[key] for key in (
        "PATH", "HOME", "TMPDIR", "LANG", "PYTHONPATH",
    ) if key in os.environ}
    if root:
        scripts = (Path(root).expanduser().resolve() / "scripts").resolve()
        env["PYTHONPATH"] = os.pathsep.join(
            p for p in env.get("PYTHONPATH", "").split(os.pathsep)
            if p and Path(p).resolve() != scripts
        )
    env.update(HERMES_HOME=str(tmp_path / "home"),
               PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1")
    command = [sys.executable, "-m", "pytest", "-o", "addopts=",
               "camofox/tests", "--collect-only", "-q", "--tb=short"]
    if with_sidecar:
        command.extend(["--web-access-root", str(root)])
    result = subprocess.run(command, cwd=Path(__file__).resolve().parents[2],
                            env=env, capture_output=True, text=True, timeout=60)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    collected = {line.split("::", 1)[0].rsplit("/", 1)[-1]
                 for line in result.stdout.splitlines() if "::" in line}
    assert "test_operation_ownership.py" in collected
    assert "test_camofox_tools.py" in collected
    if with_sidecar:
        assert SIDECAR_MODULES <= collected
    else:
        assert SIDECAR_MODULES.isdisjoint(collected)
