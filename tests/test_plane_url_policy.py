"""zti:fix-planeapi item 5 — the plane transport policy (ADR-0016).

`ZTI_PLANE_URL` defaulted to plaintext http with no enforcement anywhere, on
the channel that carries contracts, decisions, escalation releases and — since
ADR-0015 — the hook session secret. The operator's decision (2026-09-12):
plaintext http is accepted ONLY to a loopback host; any other plaintext plane
is REFUSED at startup unless `ZTI_ALLOW_INSECURE_HTTP` is set explicitly, in
which case the client proceeds with a loud warning. https is always accepted.

The policy lives once, in the open gate library (`ztipgate.transport`), and
both plane clients apply it before their first request: the gate daemon
refuses to start, the `zti` CLI exits 4 (usage / environment).
"""

import os
import sys

import pytest

from ztipgate import transport


# --- the policy itself -----------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://demo.zerotrustintelligence.io",
    "https://10.0.0.5:8100",
    "http://127.0.0.1:8100",
    "http://localhost:8100",
    "http://LOCALHOST:8100/",
    "http://[::1]:8100",
    "http://127.0.0.2:8100",          # whole 127/8 is loopback
])
def test_accepted_silently(url):
    assert transport.check_plane_url(url, env={}) is None


@pytest.mark.parametrize("url", [
    "http://10.0.0.5:8100",
    "http://plane.lan:8100",
    "http://0.0.0.0:8100",            # binds everywhere; not a loopback address
    "http://127.1:8100",              # shorthand the parser will not vouch for
    "http://localhost.:8100",         # not the literal loopback name
    "http://localhost@10.0.0.5:8100", # userinfo trick: the host is 10.0.0.5
    "http://localhost.evil.example:8100",
])
def test_plaintext_off_box_is_refused(url):
    with pytest.raises(transport.PlaneURLRefused) as exc:
        transport.check_plane_url(url, env={})
    msg = str(exc.value)
    assert "plaintext" in msg and transport.INSECURE_OVERRIDE in msg


@pytest.mark.parametrize("url", [
    "ftp://127.0.0.1:8100",
    "file:///tmp/plane",
    "127.0.0.1:8100",                 # no scheme at all
    "http://",                        # no host
    "",
    "http://[::1:8100",               # unparsable bracket
])
def test_anything_that_is_not_http_or_https_is_refused(url):
    with pytest.raises(transport.PlaneURLRefused):
        transport.check_plane_url(url, env={})


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes"])
def test_override_admits_plaintext_with_a_warning(value):
    warning = transport.check_plane_url("http://10.0.0.5:8100",
                                        env={transport.INSECURE_OVERRIDE: value})
    assert warning is not None
    assert "plaintext" in warning and "10.0.0.5" in warning


@pytest.mark.parametrize("value", ["", "0", "false", "no", "maybe"])
def test_override_must_be_explicit(value):
    with pytest.raises(transport.PlaneURLRefused):
        transport.check_plane_url("http://10.0.0.5:8100",
                                  env={transport.INSECURE_OVERRIDE: value})


def test_override_never_admits_a_non_http_scheme():
    with pytest.raises(transport.PlaneURLRefused):
        transport.check_plane_url("ftp://10.0.0.5", env={transport.INSECURE_OVERRIDE: "1"})


def test_override_is_silent_where_it_is_not_needed():
    # No spurious warning on https or loopback just because the variable is set.
    env = {transport.INSECURE_OVERRIDE: "1"}
    assert transport.check_plane_url("https://plane.example", env=env) is None
    assert transport.check_plane_url("http://127.0.0.1:8100", env=env) is None


def test_default_env_is_the_process_environment(monkeypatch):
    monkeypatch.delenv(transport.INSECURE_OVERRIDE, raising=False)
    with pytest.raises(transport.PlaneURLRefused):
        transport.check_plane_url("http://10.0.0.5:8100")
    monkeypatch.setenv(transport.INSECURE_OVERRIDE, "1")
    assert transport.check_plane_url("http://10.0.0.5:8100") is not None


# --- plaintext never rides an environment proxy -----------------------------

@pytest.fixture
def local_plane():
    """A real loopback HTTP server standing in for the plane: answers any
    request with a JSON body. If a client routed via a proxy, the request
    would go to the proxy address instead and never reach this."""
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def _ok(self):
            body = json.dumps({"reached": "plane", "path": self.path}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        do_GET = _ok
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self._ok()
        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


def _proxy_env(monkeypatch):
    # A proxy address nothing listens on: if a request is proxied, it fails.
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)


@pytest.fixture
def default_opener_restored():
    import urllib.request
    yield
    urllib.request.install_opener(urllib.request.build_opener())


def test_daemon_plaintext_bypasses_an_environment_proxy(local_plane, monkeypatch,
                                                        default_opener_restored):
    """Round finding: urllib's default opener honours http_proxy, so a request
    the policy judged loopback went in plaintext to the proxy address."""
    import urllib.request
    import gated
    _proxy_env(monkeypatch)
    monkeypatch.setattr(gated, "PLANE", local_plane)
    # With urllib's DEFAULT opener the request is proxied — and fails. Installed
    # explicitly so the precondition does not depend on what ran before.
    urllib.request.install_opener(urllib.request.build_opener())
    with pytest.raises(gated.PlaneError):
        gated.api("/v1/health")
    assert transport.apply_transport(local_plane) is None
    assert gated.api("/v1/health")["reached"] == "plane"
    assert gated.api("/v1/gates/register", {"gate_id": "g"}, enroll=True)["reached"] == "plane"


def test_cli_plaintext_bypasses_an_environment_proxy(local_plane, monkeypatch,
                                                     default_opener_restored):
    import zticli.main as cli
    _proxy_env(monkeypatch)
    monkeypatch.setenv("ZTI_PLANE_URL", local_plane)
    plane_url, _, _ = cli.load_config(__import__("pathlib").Path("/tmp"))   # installs the opener
    status, body = cli.Plane(plane_url, "k").verify_by_tree("deadbeef")
    assert status == 200 and body["reached"] == "plane"


def test_opener_choice_is_by_scheme(monkeypatch):
    import urllib.request
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    plain = transport.opener_for("http://127.0.0.1:8100")
    # Plaintext: no proxy handler carries a proxy (an empty ProxyHandler adds
    # no methods, so build_opener drops the default one and adds nothing).
    assert not any(isinstance(h, urllib.request.ProxyHandler) and h.proxies
                   for h in plain.handlers)
    tls = next(h for h in transport.opener_for("https://plane.example").handlers
               if isinstance(h, urllib.request.ProxyHandler))
    assert tls.proxies.get("https")                   # https: CONNECT tunnel is fine


# --- the gate daemon applies it before touching the plane -------------------

def test_gated_refuses_to_start_on_a_plaintext_off_box_plane(monkeypatch, capsys):
    import gated
    monkeypatch.setattr(gated, "PLANE", "http://10.0.0.5:8100")
    monkeypatch.delenv(transport.INSECURE_OVERRIDE, raising=False)

    def never(*a, **k):
        raise AssertionError("the daemon must not contact the plane before the transport check")
    monkeypatch.setattr(gated, "api", never)
    monkeypatch.setattr(sys, "argv", ["gated", "--repo-root", "/tmp", "--repo-name", "r"])
    with pytest.raises(SystemExit) as exc:
        gated.main()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "cannot start" in err and "plaintext" in err


def test_gated_warns_and_proceeds_under_the_override(monkeypatch, capsys):
    import gated
    monkeypatch.setattr(gated, "PLANE", "http://10.0.0.5:8100")
    monkeypatch.setenv(transport.INSECURE_OVERRIDE, "1")
    reached = {}

    def stop(*a, **k):
        reached["plane"] = True
        raise gated.PlaneError("stub: stop here")
    monkeypatch.setattr(gated, "api", stop)
    monkeypatch.setattr(sys, "argv", ["gated", "--repo-root", "/tmp", "--repo-name", "r"])
    with pytest.raises(SystemExit):
        gated.main()
    assert reached.get("plane") is True
    assert "plaintext" in capsys.readouterr().err


# --- the CLI applies it when it loads its config ----------------------------

def test_cli_refuses_a_plaintext_off_box_plane(tmp_path, monkeypatch):
    import zticli.main as cli
    monkeypatch.setenv("ZTI_PLANE_URL", "http://10.0.0.5:8100")
    monkeypatch.delenv(transport.INSECURE_OVERRIDE, raising=False)
    with pytest.raises(RuntimeError) as exc:
        cli.load_config(tmp_path)
    assert "plaintext" in str(exc.value)


def test_cli_loads_a_loopback_or_https_plane(tmp_path, monkeypatch):
    import zticli.main as cli
    monkeypatch.delenv("ZTI_PLANE_URL", raising=False)
    assert cli.load_config(tmp_path)[0] == cli.DEFAULT_PLANE      # loopback default
    monkeypatch.setenv("ZTI_PLANE_URL", "https://plane.example")
    assert cli.load_config(tmp_path)[0] == "https://plane.example"


def test_cli_warns_under_the_override(tmp_path, monkeypatch, capsys):
    import zticli.main as cli
    monkeypatch.setenv("ZTI_PLANE_URL", "http://10.0.0.5:8100")
    monkeypatch.setenv(transport.INSECURE_OVERRIDE, "yes")
    assert cli.load_config(tmp_path)[0] == "http://10.0.0.5:8100"
    assert "plaintext" in capsys.readouterr().err
