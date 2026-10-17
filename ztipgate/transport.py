"""Plane transport policy (ADR-0016, card zti:fix-planeapi).

The channel between a client (the gate daemon, the `zti` CLI) and the plane
carries contracts, decisions, escalation releases and — since ADR-0015 — the
per-session hook secret. `ZTI_PLANE_URL` defaulted to plaintext http and nothing
anywhere refused it, so a LAN plane was one ARP spoof away from an attacker
holding every gate key minted since.

The rule, applied by every client BEFORE its first request:

* `https://…`                      — accepted, silently.
* `http://` to a LOOPBACK host      — accepted, silently. The local-first dev
                                      default (`http://127.0.0.1:8100`) is
                                      load-bearing for the demo and never
                                      leaves the machine.
* `http://` to any other host       — REFUSED, unless `ZTI_ALLOW_INSECURE_HTTP`
                                      is set to an explicit affirmative
                                      (`1`/`true`/`yes`), in which case the
                                      client proceeds and the caller prints
                                      the returned WARNING.
* anything else (no scheme, other scheme, no host, unparsable) — refused; the
  override does not reach it.

"Loopback" is decided by the parsed host alone: the literal name `localhost`
(case-insensitive, no trailing dot, no suffix) or an address `ipaddress`
classifies as loopback (all of 127/8, `::1`). Shorthand the parser will not
vouch for (`127.1`) is refused — fail closed on ambiguity; write it out.
"""

from __future__ import annotations

import ipaddress
import os
import urllib.request
from collections.abc import Mapping
from urllib.parse import urlsplit

INSECURE_OVERRIDE = "ZTI_ALLOW_INSECURE_HTTP"
_AFFIRMATIVE = {"1", "true", "yes"}


class PlaneURLRefused(ValueError):
    """The plane URL fails the transport policy. The message is operator-facing."""


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_plane_url(url: str, env: Mapping[str, str] | None = None) -> str | None:
    """Apply the policy. Returns None when the URL is acceptable as-is, a WARNING
    line when a plaintext off-box plane is admitted under the override, and
    raises PlaneURLRefused otherwise."""
    if env is None:
        env = os.environ
    try:
        parts = urlsplit(url or "")
        host = parts.hostname   # lowercased; brackets stripped; userinfo removed
    except ValueError:
        raise PlaneURLRefused(f"plane URL is not parseable: {url!r}") from None
    if parts.scheme not in ("http", "https") or not host:
        raise PlaneURLRefused(
            f"plane URL must be http(s)://host[:port], got {url!r}")
    if parts.scheme == "https" or _is_loopback(host):
        return None
    if env.get(INSECURE_OVERRIDE, "").strip().lower() in _AFFIRMATIVE:
        return (f"WARNING: talking to the plane at {host} over plaintext http "
                f"because {INSECURE_OVERRIDE} is set — contracts, decisions and "
                f"the hook session secret are readable and forgeable on the wire")
    raise PlaneURLRefused(
        f"refusing plaintext http to a non-loopback plane ({host}): use https, "
        f"or set {INSECURE_OVERRIDE}=1 to accept the risk explicitly")


def opener_for(url: str) -> urllib.request.OpenerDirector:
    """The opener plane requests must go through.

    urllib's default opener honours `http_proxy` / `HTTP_PROXY` from the
    environment, and its bypass list is only `no_proxy` — so on a box with a
    corporate or CI proxy a request the policy judged LOOPBACK went, in
    plaintext, to the proxy address instead (found by the fix-planeapi
    round). Plaintext plane traffic therefore NEVER uses a proxy: the policy
    admitted it on the strength of where it goes. https keeps the default
    opener — through a proxy it is a CONNECT tunnel and stays end-to-end TLS.
    """
    if urlsplit(url or "").scheme == "http":
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener()


def apply_transport(url: str, env: Mapping[str, str] | None = None) -> str | None:
    """Check the plane URL (raises PlaneURLRefused) AND install the opener it
    calls for as the process's `urllib.request.urlopen` opener. Process-wide on
    purpose: the gate daemon and the `zti` CLI are single-purpose processes whose
    only outbound HTTP is the plane, and every request in them goes through
    `urlopen`. Returns the override warning, if any, for the caller to print."""
    warning = check_plane_url(url, env)
    urllib.request.install_opener(opener_for(url))
    return warning
