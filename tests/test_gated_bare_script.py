"""The gate daemon runs as a bare script beside a checkout.

Running the daemon script directly from a checkout (`python3 <path>/gated.py
...`) is a documented way to start it, and the script carries a fallback for it: when `ztipgate` is not importable it puts
the checkout root on sys.path and retries. One `ztipgate` import sat ABOVE that
fallback, so on a Python without the package the daemon died with
ModuleNotFoundError before the fallback ever ran.

The rest of this suite could not see it: conftest puts the repository root on
sys.path for every test, so `ztipgate` is always importable in-process. These
tests run the script in a SUBPROCESS with site-packages switched off (-S) and
only the open `ztip` runtime made importable, so the checkout fallback is the
only way `ztipgate` can load — whatever happens to be installed on this machine.
"""

import importlib.util
import os
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The daemon script sits in a different directory in this repository and in
# the public client repository; this file is synced there verbatim, so it looks
# in both layouts.
_LAYOUTS = (ROOT / "core" / "hook" / "gated.py", ROOT / "hooks" / "claude-code" / "gated.py")
GATED = next((p for p in _LAYOUTS if p.is_file()), None)
assert GATED is not None, f"gated.py not found in either layout: {_LAYOUTS}"


def _bare_env(tmp_path):
    """PYTHONPATH holding ONLY the ztip runtime (gate.py's one third-party
    dependency); no repository root, no site-packages."""
    spec = importlib.util.find_spec("ztip")
    assert spec is not None and spec.submodule_search_locations, "ztip runtime not importable"
    pp = tmp_path / "pp"
    pp.mkdir(exist_ok=True)
    if not (pp / "ztip").exists():
        (pp / "ztip").symlink_to(Path(list(spec.submodule_search_locations)[0]))
    env = {k: v for k, v in os.environ.items()
           if k not in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP")}
    env["PYTHONPATH"] = str(pp)
    env.pop("ZTI_ENROLL_TOKEN", None)
    env.pop("ZTI_ALLOW_INSECURE_HTTP", None)
    env["ZTI_GATE_SESSION_FILE"] = str(tmp_path / "gated.session")
    return env


def _run(tmp_path, *args, plane=None):
    env = _bare_env(tmp_path)
    if plane is not None:
        env["ZTI_PLANE_URL"] = plane
    return subprocess.run([sys.executable, "-S", str(GATED), *args],
                          cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)


def test_precondition_ztipgate_is_not_importable_without_the_fallback(tmp_path):
    """Pins the test's own premise: in this environment the checkout fallback
    is the only route to `ztipgate`, so the tests below exercise it."""
    r = subprocess.run([sys.executable, "-S", "-c", "import ztipgate"],
                       cwd=tmp_path, env=_bare_env(tmp_path), capture_output=True, text=True)
    assert r.returncode != 0 and "ModuleNotFoundError" in r.stderr, r.stderr
    r = subprocess.run([sys.executable, "-S", "-c", "import ztip.hashing"],
                       cwd=tmp_path, env=_bare_env(tmp_path), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_bare_script_reaches_argument_parsing(tmp_path):
    r = _run(tmp_path, "--help")
    assert "ModuleNotFoundError" not in r.stderr, r.stderr
    assert r.returncode == 0, r.stderr
    assert "--repo-root" in r.stdout and "--repo-name" in r.stdout


def test_bare_script_applies_the_transport_policy(tmp_path):
    """The import that used to fail is the transport policy's. A plaintext
    off-box plane must be refused by it, before any request is made."""
    r = _run(tmp_path, "--repo-root", str(tmp_path), "--repo-name", "bare",
             plane="http://10.0.0.5:8100")
    assert "ModuleNotFoundError" not in r.stderr, r.stderr
    assert r.returncode == 1
    assert "gated: cannot start" in r.stderr and "refusing plaintext http" in r.stderr, r.stderr


def test_bare_script_reaches_the_plane_connect_step(tmp_path):
    """A loopback plane passes the policy, so the daemon goes on to register —
    against a port nothing listens on, so the register request itself fails."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]
    r = _run(tmp_path, "--repo-root", str(tmp_path), "--repo-name", "bare",
             plane=f"http://127.0.0.1:{dead_port}")
    assert "ModuleNotFoundError" not in r.stderr, r.stderr
    assert r.returncode == 1
    assert f"gated: cannot start — plane unreachable at http://127.0.0.1:{dead_port}" in r.stderr, r.stderr
