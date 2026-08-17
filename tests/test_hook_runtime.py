"""Dedicated suite for the runtime hook (hooks/claude-code/pretooluse.py) and
the gate daemon's decision mapping (hooks/claude-code/gated.py).

Pins the fail-closed contract:
  - F4: an unreachable gate OR any alive-but-malformed response BLOCKS (exit 2).
        Before the fix a 200 with a bad shape raised → exit 1 → tool proceeded.
  - F1(enf) defense-in-depth: a path that escapes the repo root is denied at the
        daemon boundary (rel() returns the absolute path → out of scope).
"""

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import gated
from ztipgate.gate import ALLOW, DENY, Contract, Gate

HOOK = str(Path(gated.__file__).resolve().parent / "pretooluse.py")


class _Stub(HTTPServer):
    """One-shot stub gate returning a canned (raw_body) for any POST."""
    body = b'{"decision":"allow"}'


def _handler_for(body_bytes):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body_bytes)))
            self.end_headers()
            self.wfile.write(body_bytes)

        def log_message(self, *a):
            pass
    return H


def _run_hook(gate_url, tool_input=None):
    """Run pretooluse.py as a subprocess; return (exit_code, stdout)."""
    stdin = json.dumps({"tool_name": "Bash",
                        "tool_input": tool_input or {"command": "rm -rf /important"}})
    p = subprocess.run([sys.executable, HOOK], input=stdin, capture_output=True,
                       text=True, env={"ZTI_GATE_URL": gate_url, "PATH": "/usr/bin:/bin"})
    return p.returncode, p.stdout


def _serve(body_bytes):
    srv = HTTPServer(("127.0.0.1", 0), _handler_for(body_bytes))
    threading.Thread(target=srv.handle_request, daemon=True).start()
    port = srv.server_address[1]
    return f"http://127.0.0.1:{port}/evaluate"


# --- pretooluse.py fail-closed contract (F4) --------------------------------

def test_hook_blocks_when_gate_unreachable():
    # Nothing listening on this port → connection refused → BLOCK (exit 2).
    code, _ = _run_hook("http://127.0.0.1:9/evaluate")
    assert code == 2


def test_hook_allows_on_clean_allow():
    code, out = _run_hook(_serve(b'{"decision":"allow"}'))
    assert code == 0 and out.strip() == ""   # allow = exit 0, no deny payload


def test_hook_denies_on_clean_deny():
    code, out = _run_hook(_serve(b'{"decision":"deny","reason":"FORBIDDEN_PATH_WRITE: db/"}'))
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("body", [
    b'{}',                    # no decision key
    b'null',                  # non-dict
    b'{"decision": 123}',     # non-string decision
    b'not json at all',       # unparseable
    b'[]',                    # wrong type
])
def test_hook_fails_closed_on_malformed_200(body):
    # F4 regression: an alive gate returning garbage must BLOCK, not pass through.
    code, _ = _run_hook(_serve(body))
    assert code == 2, f"malformed body {body!r} did not fail closed"


def test_hook_blocks_unknown_decision():
    # Any decision other than "allow" (e.g. an escalate leaking through) → block.
    code, out = _run_hook(_serve(b'{"decision":"escalate","reason":"UNSCOPED_ACTION"}'))
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("url", [
    "file:///etc/hostname",              # 2A: non-http scheme (a planted allow file)
    "http://evil.example.com/evaluate",  # 2A: non-loopback host
    ":::bad",                            # 2B: malformed URL (raises at construction)
])
def test_hook_refuses_non_loopback_gate_url(url):
    # 2A/2B regression: the gate is always local. A poisoned ZTI_GATE_URL that points
    # off-loopback or is malformed must BLOCK, never redirect the check and proceed.
    code, _ = _run_hook(url)
    assert code == 2


def test_hook_blocks_on_malformed_stdin():
    # 1b regression: a non-JSON stdin envelope must fail closed, not exit 1 → proceed.
    p = subprocess.run([sys.executable, HOOK], input="not json at all",
                       capture_output=True, text=True,
                       env={"ZTI_GATE_URL": _serve(b'{"decision":"allow"}'), "PATH": "/usr/bin:/bin"})
    assert p.returncode == 2


def test_daemon_forbidden_symlink_by_name_is_denied(tmp_path, monkeypatch):
    # Probe-4 regression: an in-repo symlink pointing OUTSIDE, named in forbidden_paths,
    # must still be caught by name (the rel() change resolves it to an absolute path,
    # which _forbidden_token also checks lexically).
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "key").write_text("secret")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "secrets_link").symlink_to(outside)

    d = gated.Daemon.__new__(gated.Daemon)
    d.repo_root = repo.resolve()
    d.observe = False
    d.contract = Contract(work_id="w", allowed_paths=["**"],
                          forbidden_paths=["secrets_link", "secrets_link/**"], required_checks=["true"])
    d.gate = Gate(d.contract)
    d.gate_id, d.key = "g1", "k"
    monkeypatch.setattr(d, "ship", lambda *a, **k: None)
    monkeypatch.chdir(repo)
    _, dec = d.evaluate("Bash", {"command": "cat secrets_link/key"})
    assert dec.decision == DENY and dec.reason_code == "FORBIDDEN_PATH_WRITE"


# --- daemon evaluate(): scope enforcement + repo escape (F1) ----------------

@pytest.fixture
def daemon(tmp_path, monkeypatch):
    """A Daemon wired to a real Gate but with no network (register/ship stubbed)."""
    d = gated.Daemon.__new__(gated.Daemon)
    d.repo_root = tmp_path.resolve()
    d.observe = False
    d.contract = Contract(work_id="w", allowed_paths=["src/**"], forbidden_paths=["db/**"],
                          required_checks=["true"])
    d.gate = Gate(d.contract)
    d.gate_id, d.key = "g1", "k"
    monkeypatch.setattr(d, "ship", lambda *a, **k: None)  # never touch the plane
    return d


def test_daemon_allows_in_scope_write(daemon):
    path = str(daemon.repo_root / "src" / "app.py")
    _, d = daemon.evaluate("Write", {"file_path": path})
    assert d.decision == ALLOW


def test_daemon_denies_forbidden_write(daemon):
    path = str(daemon.repo_root / "db" / "schema.sql")
    _, d = daemon.evaluate("Write", {"file_path": path})
    assert d.decision == DENY and d.reason_code == "FORBIDDEN_PATH_WRITE"


def test_daemon_denies_repo_escape_write(daemon):
    # F1 defense-in-depth: an absolute path outside the repo is out of scope.
    _, d = daemon.evaluate("Write", {"file_path": "/etc/passwd"})
    assert d.decision == DENY


def test_daemon_blocks_irreversible_bash(daemon):
    _, d = daemon.evaluate("Bash", {"command": "rm -fr /data"})
    assert d.decision == DENY and d.reason_code == "IRREVERSIBLE_ACTION_BLOCKED"


def test_daemon_bash_passthrough_is_benign_only(daemon):
    _, d = daemon.evaluate("Bash", {"command": "echo hello"})
    assert d.decision == ALLOW and d.reason_code == "BASH_PASSTHROUGH"
