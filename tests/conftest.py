"""Test path wiring: the repo root (for `ztipgate` / `zticli` when running
from a checkout without an install) and the Claude Code hook directory (for
`gated`, which ships as a script, not a package) go on sys.path."""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _p in (_ROOT, _ROOT / "hooks" / "claude-code"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
