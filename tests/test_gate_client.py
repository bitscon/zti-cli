"""The gate daemon's plane client (hooks/claude-code/gated.py), driven without
a plane.

The client halves of the upstream enrollment fail-closed suite and the
approval suite's terminal guard: every refusal, outage and hostile reply from
the plane becomes one sanitised operator line, never a traceback or a forged
"enforcing" line, and the enrollment token is never sent malformed or echoed.
The plane halves of those suites stay in the ZTI Core product tree. Plus the
daemon's liveness heartbeat and the session file's symlink refusal, pinned
here because their plane halves live upstream.
"""

import sys
import time
from pathlib import Path

import pytest

import gated



def test_gate_client_reports_the_planes_coded_refusal(monkeypatch):
    """The 503 is only useful if the operator can read it. urllib raises before the
    body is read, so the shipped gate daemon used to discard the plane's `detail`
    and exit on a raw HTTPError traceback — which reads as "the plane is down",
    the opposite of what happened."""
    import io
    import urllib.error


    def _raise(*_a, **_kw):
        raise urllib.error.HTTPError(
            "http://plane/v1/gates/register", 503, "Service Unavailable", {},
            io.BytesIO(b'{"detail":"gate enrollment unavailable: '
                       b'the enrollment token is misconfigured"}'))

    monkeypatch.setattr(gated.urllib.request, "urlopen", _raise)
    with pytest.raises(gated.PlaneError) as ei:
        gated.api("/v1/gates/register", {"gate_id": "g", "repo": "r", "agent": "a"},
                  enroll=True)
    assert "503" in str(ei.value)
    assert "enrollment token is misconfigured" in str(ei.value)


def test_gate_client_survives_a_refusal_with_no_readable_body(monkeypatch):
    import io
    import urllib.error


    def _raise(*_a, **_kw):
        raise urllib.error.HTTPError("http://plane/v1/gates/register", 502,
                                     "Bad Gateway", {}, io.BytesIO(b"<html>nope"))

    monkeypatch.setattr(gated.urllib.request, "urlopen", _raise)
    with pytest.raises(gated.PlaneError) as ei:
        gated.api("/v1/gates/register", {"gate_id": "g", "repo": "r", "agent": "a"})
    assert "502" in str(ei.value)


def _http_error(code, phrase, body: bytes):
    import io
    import urllib.error
    return urllib.error.HTTPError("http://plane/v1/gates/register", code, phrase,
                                  {}, io.BytesIO(body))


@pytest.mark.parametrize("code,phrase,body,expected", [
    (503, "Service Unavailable",
     b'{"detail":"gate enrollment unavailable: the enrollment token is misconfigured"}',
     "enrollment token is misconfigured"),
    (401, "Unauthorized", b'{"detail":"gate enrollment token required"}',
     "gate enrollment token required"),
    # The licensing refusal is emitted verbatim with no "detail" key — this is the
    # one refusal every customer eventually meets, at trial expiry.
    (402, "Payment Required",
     b'{"decision":"REJECT","reason":"LICENSE_REQUIRED","module":"base",'
     b'"contact":"licensing@zerotrustintelligence.io"}', "LICENSE_REQUIRED"),
    (500, "Internal Server Error",
     b'{"decision":"REJECT","reason":"internal_error"}', "internal_error"),
    (502, "Bad Gateway", b"<html>nope", "502"),
    # FastAPI's validation envelope: `detail` is a LIST. Uncoerced this raised
    # TypeError from inside the HTTPError handler — a traceback, which is the
    # exact failure class PlaneError exists to remove.
    (422, "Unprocessable Entity", b'{"detail":[{"msg":"field required"}]}', "field required"),
])
def test_gate_client_reports_every_refusal_envelope(monkeypatch, code, phrase, body, expected):
    monkeypatch.setattr(gated.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(_http_error(code, phrase, body)))
    with pytest.raises(gated.PlaneError) as ei:
        gated.api("/v1/gates/register", {"gate_id": "g", "repo": "r", "agent": "a"})
    assert str(code) in str(ei.value)
    assert expected in str(ei.value)


def test_gate_client_names_the_contact_the_plane_supplied(monkeypatch):
    body = (b'{"decision":"REJECT","reason":"LICENSE_REQUIRED","module":"base",'
            b'"contact":"licensing@zerotrustintelligence.io"}')
    monkeypatch.setattr(gated.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(_http_error(402, "Payment Required", body)))
    with pytest.raises(gated.PlaneError) as ei:
        gated.api("/v1/gates/register", {})
    assert "licensing@zerotrustintelligence.io" in str(ei.value)


def test_gate_client_caps_the_body_it_reads(monkeypatch):
    """A hostile or MITM'd plane must not be able to OOM the daemon at startup;
    ZTI_PLANE_URL defaults to plain http, so an on-path attacker suffices.

    The size argument is recorded and asserted OUTSIDE the fake read: an assert
    raised inside it is swallowed by _refusal's `except Exception`, which made an
    earlier version of this test pass whether or not the cap was there."""

    reads = []

    def _read(n=-1):
        reads.append(n)
        return b"x" * (n if n and n > 0 else 1024)

    err = _http_error(500, "Internal Server Error", b"")
    monkeypatch.setattr(err, "read", _read, raising=False)
    monkeypatch.setattr(gated.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(err))
    with pytest.raises(gated.PlaneError):
        gated.api("/v1/gates/register", {})
    assert reads, "the refusal body was never read"
    assert all(n is not None and 0 < n <= 1 << 20 for n in reads), f"uncapped read: {reads}"


def test_gate_client_says_unreachable_when_the_plane_is_down(monkeypatch):
    """Plane refused and plane down must read differently — the second used to be
    a raw traceback, which is exactly what the first was mistaken for."""
    import urllib.error

    monkeypatch.setattr(
        gated.urllib.request, "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("[Errno 111] Connection refused")))
    with pytest.raises(gated.PlaneError) as ei:
        gated.api("/v1/gates/register", {})
    assert "unreachable" in str(ei.value)


def test_gate_client_refuses_an_unsendable_token_without_a_traceback(monkeypatch):
    """http.client latin-1-encodes header values, so a token above U+00FF used to
    raise UnicodeEncodeError ten frames down — a traceback, which is exactly what
    PlaneError exists to remove."""
    monkeypatch.setenv("ZTI_ENROLL_TOKEN", "パスワード")
    with pytest.raises(gated.PlaneError) as ei:
        gated.api("/v1/gates/register", {"gate_id": "g", "repo": "r", "agent": "a"}, enroll=True)
    assert "HTTP header" in str(ei.value)


def test_gate_client_strips_terminal_escapes_from_a_plane_reply(monkeypatch):
    """_refusal renders remote text into a terminal and ZTI_PLANE_URL defaults to
    plain http, so a hostile or on-path plane could clear the screen and print a
    forged 'contract loaded — enforcing' line over the real failure."""
    # Padding stays under the 64 KB read cap on purpose: over it the body no longer
    # parses as JSON and the helper falls back to the bare status line, which would
    # make this test pass without ever exercising the filter.
    hostile = (b'{"detail":"\\u001b[2J\\u001b[H\\u001b[32mgated: contract loaded'
               b' \\u2014 enforcing\\u001b[0m\\r' + b'PAD' * 2000 + b'"}')
    monkeypatch.setattr(gated.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(_http_error(503, "x", hostile)))
    with pytest.raises(gated.PlaneError) as ei:
        gated.api("/v1/gates/register", {})
    message = str(ei.value)
    assert "\x1b" not in message and "\r" not in message
    assert len(message) < 400


def test_gate_daemon_entry_point_reports_a_refusal_as_one_line(monkeypatch, capsys):
    """main() is where a PlaneError becomes an operator message instead of a
    traceback — the stated point of the change, previously untested at the entry."""
    monkeypatch.setattr(sys, "argv",
                        ["gated.py", "--repo-root", ".", "--repo-name", "demo"])

    def _boom(*_a, **_kw):
        # Escapes in the message too: PlaneError text is sanitised at construction,
        # so this pins main()'s own filter as defence in depth.
        raise gated.PlaneError("plane refused /v1/gates/register: HTTP 503 Service "
                               "Unavailable\x1b[2J\x1b[H — gate enrollment unavailable")

    monkeypatch.setattr(gated, "Daemon", _boom)
    with pytest.raises(SystemExit) as ei:
        gated.main()
    assert ei.value.code == 1
    err = capsys.readouterr().err
    assert "gated: cannot start" in err and "Traceback" not in err
    assert "\x1b" not in err


def test_the_gate_client_never_echoes_the_token_either(monkeypatch):
    monkeypatch.setenv("ZTI_ENROLL_TOKEN", "s3cr3t\n")
    with pytest.raises(gated.PlaneError) as ei:
        gated.api("/v1/gates/register", {"gate_id": "g", "repo": "r", "agent": "a"}, enroll=True)
    assert "s3cr3t" not in str(ei.value)
    assert "Traceback" not in str(ei.value)


def test_the_client_rejects_a_token_the_plane_would_reject(monkeypatch):
    """A trailing newline is latin-1 encodable, so an encodability check waves it
    through and http.client raises ValueError ten frames down — with the secret in
    the message. The client applies the plane's rule instead."""
    for token in ("s3cr3t\n", "s3cr3t\r", " s3cr3t", "s3cr3t ", "sécret", "パスワード"):
        monkeypatch.setenv("ZTI_ENROLL_TOKEN", token)
        with pytest.raises(gated.PlaneError) as ei:
            gated.api("/v1/gates/register", {"gate_id": "g"}, enroll=True)
        # Assert the REASON, not just the type: without this, a leading-space token
        # is sent for real, the connection is refused, and the resulting
        # "plane unreachable" PlaneError satisfies a bare raises() just as well.
        assert "HTTP header" in str(ei.value), f"{token!r} was sent: {ei.value}"


def test_escapes_in_the_status_phrase_are_stripped(monkeypatch):
    """Only the body half was filtered at first. The HTTP reason phrase is chosen by
    the plane too, and http.client will carry about 64 KB of it."""
    phrase = "\x1b[2J\x1b[H\x1b[32mgated: contract loaded — enforcing\x1b[0m" + "P" * 5000
    monkeypatch.setattr(gated.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(_http_error(503, phrase, b"{}")))
    with pytest.raises(gated.PlaneError) as ei:
        gated.api("/v1/gates/register", {})
    message = str(ei.value)
    assert "\x1b" not in message
    assert len(message) < 400, f"unbounded message: {len(message)} chars"


@pytest.mark.parametrize("hostile", [
    "\x1b[2J\x1b[H\x1b[32mgated: contract loaded — enforcing\x1b[0m",
    "deadbeef\r\x1b[Agated: ALLOW  [BASH_PASSTHROUGH] rm -rf /",
])
def test_plane_chosen_strings_cannot_forge_the_enforcing_line(hostile):
    """The success line is the better attack position: it is the line the operator
    reads to confirm enforcement is live."""
    out = gated._safe(hostile)
    assert "\x1b" not in out and "\r" not in out


def test_the_daemon_sanitises_every_string_the_plane_chose(monkeypatch, capsys, tmp_path):
    """gate_id and etag are both picked by the plane. gate_id is interpolated into
    every later request path, and the etag line is the one the operator reads to
    confirm enforcement is live — the best line to forge over."""
    forged = "\x1b[2J\x1b[H\x1b[32mgated: contract loaded — enforcing\x1b[0m"

    def _fake_api(path, body=None, key=None, enroll=False):
        if path == "/v1/gates/register":
            return {"gate_id": "g" + forged, "api_key": "k", "hook_secret": "s"}
        return {"contract": {"work_id": "w", "allowed_paths": []}, "etag": forged}

    monkeypatch.setattr(gated, "api", _fake_api)
    monkeypatch.setenv("ZTI_GATE_SESSION_FILE", str(tmp_path / "gated.session"))
    daemon = gated.Daemon(Path("/tmp"), "demo")
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\r" not in out, "a forged enforcing line reached the terminal"
    assert "\x1b" not in daemon.gate_id, "gate_id carries control characters into request paths"


def test_a_malformed_status_line_cannot_paint_the_terminal(monkeypatch):
    """http.client raises HTTPException outside urllib's OSError wrapper, so a
    hostile plane's status line reached the terminal as a raw traceback — bypassing
    both the printable filter and the cap."""
    import http.client

    forged = "\x1b[2J\x1b[H\x1b[41mFORGED gated: contract loaded — enforcing\x1b[0m\r" + "P" * 5000
    monkeypatch.setattr(gated.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(http.client.BadStatusLine(forged)))
    with pytest.raises(gated.PlaneError) as ei:
        gated.api("/v1/gates/register", {})
    message = str(ei.value)
    assert "\x1b" not in message and "\r" not in message
    assert "FORGED" not in message, "the plane's bytes reached the message"
    assert len(message) < 200


def test_an_unreadable_body_is_a_message_not_a_traceback(monkeypatch):

    class _Resp:
        def read(self): return b"<html>not json"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(gated.urllib.request, "urlopen", lambda *a, **k: _Resp())
    with pytest.raises(gated.PlaneError) as ei:
        gated.api("/v1/gates/register", {})
    assert "unreadable response" in str(ei.value)


def test_the_decision_line_cannot_erase_itself(monkeypatch, capsys):
    """action['command'] arrives from the local hook port. A governed agent could
    embed a cursor-up-and-erase sequence to remove the DENY line its own command
    just produced — inside this product's threat model."""
    hostile = "rm -rf /\x1b[1A\x1b[2Kgated: ALLOW  [OK] harmless"
    line = gated._decision_line("deny", "IRREVERSIBLE\x1b[2J", hostile)
    assert "\x1b" not in line and "\r" not in line
    assert line.startswith("gated: DENY") and "rm -rf /" in line


def test_the_daemon_still_routes_its_decision_line_through_the_filter():
    """Pin the gate's WIRING, not just its logic, because a control can be
    unwired with every suite still green: `_decision_line` is tested directly, so nothing else proves the shipped
    handler still calls it.

    Repointed when the handler was lifted out of `main()` into `make_server` so
    it could be driven by a test at all. Both halves of the chain are pinned now
    — the handler calls the filter, and `main` still reaches the handler through
    the function that builds it — because repointing a wiring pin at whatever the
    code happens to do is how a wiring pin stops meaning anything.
    """
    import ast
    import inspect
    import textwrap

    handler = ast.parse(textwrap.dedent(inspect.getsource(gated.make_server)))
    called = {ast.unparse(n.func) for n in ast.walk(handler) if isinstance(n, ast.Call)}
    assert "_decision_line" in called, \
        f"the handler no longer calls it; calls {sorted(called)}"

    entry = ast.parse(textwrap.dedent(inspect.getsource(gated.main)))
    built = {ast.unparse(n.func) for n in ast.walk(entry) if isinstance(n, ast.Call)}
    assert "make_server" in built, \
        f"main() no longer builds the gated handler; calls {sorted(built)}"


def test_an_unencodable_line_is_degraded_not_dropped():
    """Found in review: swallowing an unencodable line was
    quieter than the crash it replaced, and quiet in the wrong direction.

    Both mode banners carry an em dash, so on a non-UTF-8 terminal ENFORCING
    became indistinguishable from OBSERVE — and because the per-action line
    embeds the agent's own path, a governed agent could suppress its own DENY
    line by putting one non-ASCII character in a filename. The action was still
    blocked and the plane still heard it, but the operator's terminal stopped
    saying so, which is this product's own worst defect class pointed at the
    console.
    """
    written = []

    class AsciiOnly:
        encoding = "ascii"

        def write(self, s):
            s.encode("ascii")          # raises on the em dash, as a real one does
            written.append(s)

        def flush(self):
            pass

    gated._announce("gated: contract for demorepo loaded (etag abc) — enforcing",
                    stream=AsciiOnly())
    out = "".join(written)
    assert "enforcing" in out                 # the line still arrives
    assert "—" not in out                     # with the character replaced

    class DeadPipe:
        encoding = "utf-8"

        def write(self, *_a):
            raise BrokenPipeError(32, "Broken pipe")

        def flush(self):
            raise BrokenPipeError(32, "Broken pipe")

    gated._announce("anything", stream=DeadPipe())   # unwritable: dropped, never raised


def test_every_operator_facing_line_goes_through_the_guard():
    """Found in review: two prints were missed by the sweep that introduced the
    guard, and one of them mattered — a dead stdout killed the daemon AFTER it
    had registered and pulled its contract, so the plane listed the gate as
    online while nothing was listening on its port. The per-action decision line
    in the request handler was converted but pinned by nothing.

    A source-level pin. It greps
    this file for the literal token, so it catches a raw print added at module
    level, in a nested function, in a class body or on a continuation line — and
    deliberately not `sys.stdout.write`, an aliased print, or the stdlib's own
    writes, which are pinned by behaviour instead (see the malformed-request
    test below).
    """
    lines = Path(gated.__file__).read_text(encoding="utf-8").splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("def _announce("))
    end = next(i for i in range(start + 1, len(lines))
               if lines[i] and not lines[i][0].isspace())
    offenders = [f"{i + 1}: {l.strip()}" for i, l in enumerate(lines)
                 if "print(" in l and not start <= i < end]
    assert offenders == [], offenders


def test_the_last_resort_swallow_is_on_the_failure_path():
    """This guard was once documented as unreachable. It is reachable — a
    stream can fail BOTH ways: the line is unencodable, and by the time the
    lossy retry runs the reader is gone. Unguarded, that raises straight out of
    `evaluate()` and the plane hears nothing about the denial."""
    class FailsBothWays:
        encoding = "ascii"

        def __init__(self):
            self.calls = 0

        def write(self, s):
            self.calls += 1
            if self.calls == 1:
                s.encode("ascii")                    # unencodable: em dash
            raise BrokenPipeError(32, "Broken pipe")  # retry: reader gone

        def flush(self):
            pass

    stream = FailsBothWays()
    gated._announce("gated: contract loaded (etag abc) — enforcing", stream=stream)
    assert stream.calls == 2                          # it really did try twice


# --- liveness heartbeat, client half -----------------------------------------

def _heartbeat_daemon(monkeypatch, tmp_path, fail_first=0):
    """A real Daemon against a stand-in plane, with the beat interval shrunk.
    Returns (daemon, calls) where `calls` lists every plane path hit."""
    calls = []
    failures = {"left": fail_first}

    def fake_api(path, body=None, key=None, enroll=False):
        calls.append((path, key))
        if path == "/v1/gates/register":
            return {"gate_id": "g1", "api_key": "k1", "hook_secret": "s"}
        if path.endswith("/heartbeat") and failures["left"] > 0:
            failures["left"] -= 1
            raise gated.PlaneError("plane unreachable at stub")
        if path.endswith("/policy"):
            return {"contract": {"work_id": "w", "allowed_paths": ["**"]}, "etag": "e1"}
        return {}

    monkeypatch.setattr(gated, "api", fake_api)
    monkeypatch.setattr(gated, "HEARTBEAT_INTERVAL_SECONDS", 0.01)
    monkeypatch.setenv("ZTI_GATE_SESSION_FILE", str(tmp_path / "gated.session"))
    return gated.Daemon(tmp_path, "demo"), calls


def _wait_for_beats(calls, n, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        beats = [c for c in calls if c[0].endswith("/heartbeat")]
        if len(beats) >= n:
            return beats
        time.sleep(0.01)
    raise AssertionError(f"only {len(beats)} heartbeat(s) in {timeout}s")


def test_daemon_heartbeats_with_its_gate_key(monkeypatch, tmp_path):
    """A quiet session must never read as a disarm: the daemon proves life on a
    timer, authenticated with the api key the plane issued at register."""
    daemon, calls = _heartbeat_daemon(monkeypatch, tmp_path)
    daemon.start_heartbeat()
    beats = _wait_for_beats(calls, 3)
    assert all(path == "/v1/gates/g1/heartbeat" and key == "k1" for path, key in beats)


def test_a_failed_heartbeat_never_stops_the_beat(monkeypatch, tmp_path):
    """The plane is never in the evaluation path: a beat that fails is swallowed
    and the next one still goes out (the plane records the gap as darkness)."""
    daemon, calls = _heartbeat_daemon(monkeypatch, tmp_path, fail_first=2)
    daemon.start_heartbeat()
    _wait_for_beats(calls, 4)


# --- the session file is never written through a planted symlink ------------

def test_the_session_secret_is_not_written_through_a_symlink(monkeypatch, tmp_path):
    """An agent that plants a symlink at the session-file path must not get the
    daemon to write this session's secret somewhere it chose. The daemon
    refuses to start instead."""
    target = tmp_path / "elsewhere"
    target.write_text("untouched")
    link = tmp_path / "gated.session"
    link.symlink_to(target)

    def fake_api(path, body=None, key=None, enroll=False):
        return {"gate_id": "g1", "api_key": "k", "hook_secret": "the-secret"}

    monkeypatch.setattr(gated, "api", fake_api)
    monkeypatch.setenv("ZTI_GATE_SESSION_FILE", str(link))
    with pytest.raises(gated.PlaneError) as ei:
        gated.Daemon(tmp_path, "demo")
    assert "cannot write the hook session file" in str(ei.value)
    assert target.read_text() == "untouched"
    assert "the-secret" not in str(ei.value)
