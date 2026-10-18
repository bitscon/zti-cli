"""Dedicated suite for the runtime hook (hooks/claude-code/pretooluse.py) and
the gate daemon's decision mapping (hooks/claude-code/gated.py).

Pins the fail-closed contract:
  - an unreachable gate OR any alive-but-malformed response BLOCKS (exit 2).
    Before the fix a 200 with a bad shape raised → exit 1 → tool proceeded.
  - defense-in-depth: a path that escapes the repo root is denied at the
    daemon boundary (rel() returns the absolute path → out of scope).
  - an allow counts only when it is authenticated with an HMAC under the
    per-session secret the daemon shares with the hook.
"""

import hashlib
import hmac
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


def _run_hook(gate_url, tool_input=None, session_file=None, tool_name="Bash"):
    """Run pretooluse.py as a subprocess; return (exit_code, stdout).

    `session_file`, when given, is exported as ZTI_GATE_SESSION_FILE so the hook
    reads this session's daemon secret from a known path."""
    stdin = json.dumps({"tool_name": tool_name,
                        "tool_input": tool_input or {"command": "rm -rf /important"}})
    env = {"ZTI_GATE_URL": gate_url, "PATH": "/usr/bin:/bin"}
    if session_file is not None:
        env["ZTI_GATE_SESSION_FILE"] = str(session_file)
    p = subprocess.run([sys.executable, HOOK], input=stdin, capture_output=True,
                       text=True, env=env)
    return p.returncode, p.stdout


def _serve(body_bytes):
    srv = HTTPServer(("127.0.0.1", 0), _handler_for(body_bytes))
    threading.Thread(target=srv.handle_request, daemon=True).start()
    port = srv.server_address[1]
    return f"http://127.0.0.1:{port}/evaluate"


def _auth_handler_for(decision, reason, secret):
    """Stub daemon that authenticates its answer the way the real one does: mac
    over the EXACT request bytes + decision + reason, keyed by the session
    secret (gated._mac). Proves the real daemon still works end to end."""
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            mac = gated._mac(secret, raw, decision, reason)
            body = json.dumps({"decision": decision, "reason": reason,
                               "mac": mac}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    return H


def _serve_authed(decision, reason, secret):
    srv = HTTPServer(("127.0.0.1", 0), _auth_handler_for(decision, reason, secret))
    threading.Thread(target=srv.handle_request, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}/evaluate"


# --- pretooluse.py fail-closed contract -------------------------------------

def test_hook_blocks_when_gate_unreachable():
    # Nothing listening on this port → connection refused → BLOCK (exit 2).
    code, _ = _run_hook("http://127.0.0.1:9/evaluate")
    assert code == 2


def test_hook_allows_on_authenticated_allow(tmp_path):
    # The real daemon signs its allow with this session's secret; the hook
    # verifies it and passes the tool (exit 0, no deny payload).
    secret = "s3cret-session-value"
    sf = tmp_path / ".zti" / "gated.session"
    sf.parent.mkdir(parents=True)
    sf.write_text(secret)
    code, out = _run_hook(_serve_authed("allow", "not gated", secret), session_file=sf)
    assert code == 0 and out.strip() == ""


def test_hook_blocks_unauthenticated_allow(tmp_path):
    # THE REPRODUCTION: an impostor kills the daemon, squats its port and
    # answers a bare allow with NO mac. Before daemon answers were authenticated
    # the hook accepted it (exit 0); it must now be REFUSED and fail closed (exit 2).
    # The real daemon's session file is present (it wrote the real secret before
    # being killed); the impostor does not know it, so no valid mac can be formed.
    sf = tmp_path / ".zti" / "gated.session"
    sf.parent.mkdir(parents=True)
    sf.write_bytes(b"the-real-secret-the-impostor-never-read")
    code, _ = _run_hook(_serve(b'{"decision":"allow"}'), session_file=sf)
    assert code == 2


def test_hook_blocks_allow_with_wrong_mac(tmp_path):
    # An impostor that guesses the wire shape but signs with the wrong key is
    # still refused: the mac is over the session secret it does not hold.
    sf = tmp_path / ".zti" / "gated.session"
    sf.parent.mkdir(parents=True)
    sf.write_bytes(b"real-secret")
    code, _ = _run_hook(_serve_authed("allow", "not gated", "WRONG-secret"),
                        session_file=sf)
    assert code == 2


def test_hook_blocks_allow_with_non_ascii_mac(tmp_path):
    # REGRESSION GUARD (found in review): hmac.compare_digest
    # RAISES TypeError on a non-ASCII str mac, and the impostor controls the mac.
    # That raise must be caught by the fail-closed guard (exit 2), never escape as
    # exit 1 (which Claude Code treats as non-blocking -> the tool PROCEEDS).
    sf = tmp_path / ".zti" / "gated.session"
    sf.parent.mkdir(parents=True)
    sf.write_text("real-secret")

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            body = json.dumps({"decision": "allow", "reason": "not gated",
                               "mac": "\u00e9" * 64}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/evaluate"
    code, _ = _run_hook(url, session_file=sf)
    assert code == 2


def test_hook_blocks_allow_when_secret_unreadable(tmp_path):
    # An unreadable/missing session secret is a DENY, never a bypass: the hook
    # cannot authenticate any allow, so it fails closed.
    missing = tmp_path / "does" / "not" / "exist"
    code, _ = _run_hook(_serve_authed("allow", "not gated", "whatever"),
                        session_file=missing)
    assert code == 2


def test_hook_sends_a_fresh_nonce_each_call(tmp_path):
    # The per-request nonce is the replay defence: it makes each request's bytes
    # unique, so a captured (allow, mac) cannot be replayed for the SAME action on
    # a later request. Pin that the nonce actually varies (a constant nonce would
    # reopen same-action replay). Also proves a valid authenticated allow passes.
    secret = "nonce-fresh-secret"
    sf = tmp_path / ".zti" / "gated.session"
    sf.parent.mkdir(parents=True)
    sf.write_text(secret)
    seen = tmp_path / "nonces.txt"

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            nonce = json.loads(raw)["nonce"]
            with open(seen, "a") as fh:
                fh.write(nonce + "\n")
            mac = gated._mac(secret, raw, "allow", "not gated")
            body = json.dumps({"decision": "allow", "reason": "not gated",
                               "mac": mac}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=lambda: [srv.handle_request() for _ in range(2)],
                     daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/evaluate"
    c1, _ = _run_hook(url, session_file=sf)
    c2, _ = _run_hook(url, session_file=sf)
    assert c1 == 0 and c2 == 0
    nonces = seen.read_text().split()
    assert len(nonces) == 2 and nonces[0] != nonces[1], "the per-request nonce did not vary"


def test_hook_authenticated_allow_not_replayable_across_requests(tmp_path):
    # A captured (allow, mac) for one request must not authenticate a DIFFERENT
    # one: the mac binds to the request bytes, which carry a fresh nonce, so a
    # replay stub returning a fixed prior mac fails verification.
    secret = "replay-secret"
    sf = tmp_path / ".zti" / "gated.session"
    sf.parent.mkdir(parents=True)
    sf.write_text(secret)
    # A stub that echoes a mac computed over a FIXED (different) request body.
    stale = gated._mac(secret, b'{"stolen":"body"}', "allow", "not gated")

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            body = json.dumps({"decision": "allow", "reason": "not gated",
                               "mac": stale}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/evaluate"
    code, _ = _run_hook(url, session_file=sf)
    assert code == 2


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
    # Regression: an alive gate returning garbage must BLOCK, not pass through.
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


# --- daemon evaluate(): scope enforcement + repo escape ---------------------

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
    # Defense-in-depth: an absolute path outside the repo is out of scope.
    _, d = daemon.evaluate("Write", {"file_path": "/etc/passwd"})
    assert d.decision == DENY


def test_daemon_blocks_irreversible_bash(daemon):
    _, d = daemon.evaluate("Bash", {"command": "rm -fr /data"})
    assert d.decision == DENY and d.reason_code == "IRREVERSIBLE_ACTION_BLOCKED"


def test_daemon_bash_passthrough_is_benign_only(daemon):
    _, d = daemon.evaluate("Bash", {"command": "echo hello"})
    assert d.decision == ALLOW and d.reason_code == "BASH_PASSTHROUGH"


# --- end to end through the REAL daemon server (make_server) + pretooluse.py,
#     proving the mac the daemon actually attaches is the one the hook accepts
#     Guards against the daemon's _respond wiring regressing. -----------------

def _real_daemon(tmp_path, secret):
    d = gated.Daemon.__new__(gated.Daemon)
    d.repo_root = tmp_path.resolve()
    d.observe = False
    d.contract = Contract(work_id="w", allowed_paths=["src/**"], forbidden_paths=["db/**"],
                          required_checks=["true"])
    d.gate = Gate(d.contract)
    d.gate_id, d.key = "g1", "k"
    d.hook_secret = secret
    return d


def _serve_daemon(daemon):
    srv = gated.make_server(daemon, 0)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}/evaluate"


def test_real_daemon_authenticated_allow_end_to_end(tmp_path, monkeypatch):
    secret = "real-daemon-secret"
    d = _real_daemon(tmp_path, secret)
    monkeypatch.setattr(d, "ship", lambda *a, **k: None)
    sf = tmp_path / ".zti" / "gated.session"
    sf.parent.mkdir(parents=True)
    sf.write_text(secret)
    url = _serve_daemon(d)
    # An in-scope write the daemon ALLOWS, authenticated by the real _respond mac.
    code, out = _run_hook(url, tool_name="Write",
                          tool_input={"file_path": str(tmp_path / "src" / "app.py")},
                          session_file=sf)
    assert code == 0 and out.strip() == ""


def test_daemon_requires_a_hook_secret_to_start(monkeypatch, tmp_path):
    # An old plane that issues no session secret leaves the daemon unable to
    # authenticate itself to the hook. That must be a fail-CLOSED start (PlaneError),
    # never a silent downgrade to an unauthenticated daemon.
    def _fake_api(path, body=None, key=None, enroll=False):
        if path == "/v1/gates/register":
            return {"gate_id": "g1", "api_key": "k"}      # NO hook_secret
        return {"contract": {"work_id": "w", "allowed_paths": []}, "etag": "e"}
    monkeypatch.setattr(gated, "api", _fake_api)
    monkeypatch.setenv("ZTI_GATE_SESSION_FILE", str(tmp_path / "gated.session"))
    with pytest.raises(gated.PlaneError):
        gated.Daemon(tmp_path, "demo")


def test_daemon_writes_session_secret_0600(monkeypatch, tmp_path):
    # The daemon hands the hook this session's secret through a same-user 0600
    # file, holding the plane-minted value verbatim.
    def _fake_api(path, body=None, key=None, enroll=False):
        if path == "/v1/gates/register":
            return {"gate_id": "g1", "api_key": "k", "hook_secret": "sekret-value"}
        return {"contract": {"work_id": "w", "allowed_paths": []}, "etag": "e"}
    monkeypatch.setattr(gated, "api", _fake_api)
    monkeypatch.delenv("ZTI_GATE_SESSION_FILE", raising=False)
    d = gated.Daemon(tmp_path, "demo")
    sf = tmp_path / ".zti" / "gated.session"
    assert sf.read_text() == "sekret-value"
    assert (sf.stat().st_mode & 0o777) == 0o600
    assert d.session_file == sf


def test_real_daemon_deny_end_to_end(tmp_path, monkeypatch):
    secret = "real-daemon-secret"
    d = _real_daemon(tmp_path, secret)
    monkeypatch.setattr(d, "ship", lambda *a, **k: None)
    sf = tmp_path / ".zti" / "gated.session"
    sf.parent.mkdir(parents=True)
    sf.write_text(secret)
    url = _serve_daemon(d)
    code, out = _run_hook(url, tool_name="Write",
                          tool_input={"file_path": str(tmp_path / "db" / "x.sql")},
                          session_file=sf)
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_blocks_allow_with_empty_secret(tmp_path):
    # DEFENCE IN DEPTH (a gap mutation testing found): the daemon never writes
    # an empty secret (that is pinned elsewhere), but if the
    # session file existed yet were EMPTY the "secret" would be the PUBLIC empty
    # key -- an impostor could sign a valid mac with hmac(b"", ...). The `if not
    # secret` guard must treat an empty secret as unreadable and fail CLOSED,
    # before computing a mac the impostor can also compute. Distinct from the
    # missing-file case (secret is None), which blocks via the hmac.new(None)
    # TypeError regardless of the guard -- so only THIS case pins the guard.
    sf = tmp_path / ".zti" / "gated.session"
    sf.parent.mkdir(parents=True)
    sf.write_bytes(b"")   # exists, but empty
    # The impostor's best move: sign with the empty key it can guess is empty.
    code, _ = _run_hook(_serve_authed("allow", "not gated", ""), session_file=sf)
    assert code == 2
