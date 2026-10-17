#!/usr/bin/env python3
"""Claude Code PreToolUse hook -> ZTI gate daemon. Fail-closed.

Wire-up in the governed repo's .claude/settings.json:
  {"hooks": {"PreToolUse": [{"matcher": "Write|Edit|NotebookEdit|Bash",
    "hooks": [{"type": "command", "command": "python3 /path/to/pretooluse.py"}]}]}}

Reads the PreToolUse JSON on stdin, asks the local daemon, denies on "deny".
Daemon unreachable = exit 2 = tool call blocked with the reason fed back to
the agent. A dead gate can never silently allow.

Daemon authentication (ADR-0015, card zti:fix-hookimp). The port is local and
predictable, so any local process can squat it and answer "allow" -- ADR-0013's
reproduction proved the whole kill surface is open to a governed agent. So an
"allow" is trusted ONLY when it carries a valid message authentication code the
real daemon computed with this session's secret (written by the daemon to the
session file below). An allow with a missing or wrong mac, or a session secret
we cannot read, fails CLOSED -- an unreadable secret is a DENY, never a bypass.

This raises the local bar against an impostor that has not read the session
secret; it does NOT stop an agent that reads its own same-user session file and
feeds the secret to its impostor. That residual is the gate-key custody limit
ADR-0013 Decision 3 records, and only off-machine signing (Tier 4) closes it.
A deny/escalate/unknown answer blocks regardless of the mac -- only a forged
allow is dangerous, and only an allow is authenticated.
"""
import hashlib
import hmac
import json
import os
import secrets
import sys
import urllib.parse
import urllib.request

GATE = os.environ.get("ZTI_GATE_URL", "http://127.0.0.1:18790/evaluate")
SESSION_FILE = os.environ.get("ZTI_GATE_SESSION_FILE", ".zti/gated.session")
_LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _fail_closed(reason: str):
    # exit 2 is the ONLY exit code Claude Code treats as a block; ANY other non-zero
    # exit is a non-blocking error and the tool PROCEEDS (fail-OPEN). So every path
    # that isn't an explicit, AUTHENTICATED gate "allow" must land here. Nothing
    # outside this guard may raise -- a malformed stdin envelope, a bad ZTI_GATE_URL,
    # an unreachable or misbehaving gate, an unreadable session secret, or an
    # unauthenticated allow all block.
    print(f"zti-gate: {reason}; failing closed", file=sys.stderr)
    sys.exit(2)


def _session_secret():
    """This session's daemon secret, or None if it cannot be read. Missing or
    unreadable is NOT an error here -- it becomes a DENY at the one place it
    matters (authenticating an allow), never a bypass."""
    try:
        with open(SESSION_FILE, "rb") as fh:
            return fh.read().strip()
    except OSError:
        return None


try:
    # The gate is always local. Pin ZTI_GATE_URL to loopback http(s) so a poisoned
    # env can't redirect the check to file:// or an attacker host that just answers
    # "allow" -- that would bypass the gate entirely.
    parsed = urllib.parse.urlparse(GATE)
    if parsed.scheme not in ("http", "https") or (parsed.hostname or "") not in _LOOPBACK:
        _fail_closed(f"refusing non-loopback gate url {GATE!r}")

    data = json.load(sys.stdin)
    # A fresh, single-use nonce binds the daemon's authenticated answer to THIS
    # request: a captured allow cannot be replayed for a later, different action
    # because the mac is over the exact bytes that carry this nonce.
    nonce = secrets.token_hex(16)
    payload = {"tool_name": data.get("tool_name", ""),
               "tool_input": data.get("tool_input") or {},
               "nonce": nonce}
    raw = json.dumps(payload).encode()
    req = urllib.request.Request(GATE, data=raw,
                                 headers={"Content-Type": "application/json"})
    resp = json.load(urllib.request.urlopen(req, timeout=3))
    decision = resp["decision"]  # KeyError if shape is wrong -> caught below
    if not isinstance(decision, str):
        raise ValueError(f"non-string decision: {decision!r}")
except SystemExit:
    raise  # _fail_closed already exited 2 -- don't swallow it
except Exception as exc:
    _fail_closed(f"gate unreachable or bad response ({exc})")

if decision == "allow":
    # An allow is trusted only if the daemon proved it holds this session's
    # secret. Recompute the mac over the exact request bytes + decision + reason
    # and compare in constant time. No secret, no mac, or a wrong mac -> block.
    #
    # The WHOLE verification is inside the fail-closed guard: any raise on this
    # one enforcement-critical path must BLOCK (exit 2), never escape as an
    # uncaught exception (exit 1 = non-blocking = the tool PROCEEDS = fail OPEN).
    # In particular hmac.compare_digest RAISES TypeError on a non-ASCII str mac,
    # and an impostor controls the mac -- so an unguarded compare would fail
    # OPEN on a mac of one non-ASCII byte, defeating the whole scheme without
    # the secret. Guard the thing that can fail, not one level inside it.
    try:
        secret = _session_secret()
        if not secret:
            _fail_closed("cannot read the gate session secret -- an unauthenticated "
                         "allow is refused")
        reason = resp.get("reason", "")
        if not isinstance(reason, str):
            _fail_closed("gate answer carried a non-string reason")
        msg = raw + b"\x00" + decision.encode() + b"\x00" + reason.encode()
        expected = hmac.new(secret, msg, hashlib.sha256).hexdigest()
        got = resp.get("mac")
        if not isinstance(got, str) or not hmac.compare_digest(expected, got):
            _fail_closed("gate allow failed authentication -- refusing a possibly "
                         "impersonated allow")
    except SystemExit:
        raise  # a _fail_closed above already exited 2 -- preserve it
    except Exception as exc:
        _fail_closed(f"gate allow authentication raised ({exc})")
    sys.exit(0)

# deny, escalate, or ANY unrecognised decision -> block, reason surfaced to the agent.
# Not authenticated on purpose: a forged deny only over-blocks, never bypasses.
print(json.dumps({
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": f"ZTI gate: {resp.get('reason', decision)}",
    }
}))
sys.exit(0)
