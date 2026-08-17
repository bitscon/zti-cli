#!/usr/bin/env python3
"""Claude Code PreToolUse hook → ZTI gate daemon. Fail-closed.

Wire-up in the governed repo's .claude/settings.json:
  {"hooks": {"PreToolUse": [{"matcher": "Write|Edit|NotebookEdit|Bash",
    "hooks": [{"type": "command", "command": "python3 /path/to/pretooluse.py"}]}]}}

Reads the PreToolUse JSON on stdin, asks the local daemon, denies on "deny".
Daemon unreachable = exit 2 = tool call blocked with the reason fed back to
the agent. A dead gate can never silently allow.
"""
import json
import os
import sys
import urllib.parse
import urllib.request

GATE = os.environ.get("ZTI_GATE_URL", "http://127.0.0.1:18790/evaluate")
_LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _fail_closed(reason: str):
    # exit 2 is the ONLY exit code Claude Code treats as a block; ANY other non-zero
    # exit is a non-blocking error and the tool PROCEEDS (fail-OPEN). So every path
    # that isn't an explicit gate "allow" must land here. Nothing outside this
    # guard may raise — a malformed stdin envelope, a bad ZTI_GATE_URL, an
    # unreachable or misbehaving gate all block.
    print(f"zti-gate: {reason}; failing closed", file=sys.stderr)
    sys.exit(2)


try:
    # The gate is always local. Pin ZTI_GATE_URL to loopback http(s) so a poisoned
    # env can't redirect the check to file:// or an attacker host that just answers
    # "allow" — that would bypass the gate entirely.
    parsed = urllib.parse.urlparse(GATE)
    if parsed.scheme not in ("http", "https") or (parsed.hostname or "") not in _LOOPBACK:
        _fail_closed(f"refusing non-loopback gate url {GATE!r}")

    data = json.load(sys.stdin)
    payload = {"tool_name": data.get("tool_name", ""),
               "tool_input": data.get("tool_input") or {}}
    req = urllib.request.Request(GATE, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    resp = json.load(urllib.request.urlopen(req, timeout=3))
    decision = resp["decision"]  # KeyError if shape is wrong → caught below
    if not isinstance(decision, str):
        raise ValueError(f"non-string decision: {decision!r}")
except SystemExit:
    raise  # _fail_closed already exited 2 — don't swallow it
except Exception as exc:
    _fail_closed(f"gate unreachable or bad response ({exc})")

if decision != "allow":
    # deny, escalate, or ANY unrecognised decision → block, reason surfaced to the agent.
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"ZTI gate: {resp.get('reason', decision)}",
        }
    }))
sys.exit(0)
