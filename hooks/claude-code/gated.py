"""ZTI gate daemon — governs a live coding-agent session in one repo.

Runs beside the repo, loads its contract from the control plane, and answers
the Claude Code PreToolUse hook (pretooluse.py, beside this file) in-process
using the SAME enforcement code the product ships (ztipgate/gate.py): irreversible
patterns, forbidden paths, scope, exact reason codes. Every decision is shipped
to the plane; if the plane is down the daemon keeps enforcing on the cached
contract — the plane is never in the evaluation path.

v0 honesty note: Bash commands are screened for irreversible patterns and for
tokens that resolve into forbidden paths, then passed through (logged +
shipped). Full command scoping is a roadmap item, not a claim.

Usage:
    python3 path/to/gated.py --repo-root /path/to/repo --repo-name NAME
"""

import argparse
import json
import os
import re
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

try:
    from ztipgate.gate import Contract, Gate, _match, is_irreversible
except ImportError:  # bare script beside a checkout, nothing installed
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from ztipgate.gate import Contract, Gate, _match, is_irreversible

PLANE = os.environ.get("ZTI_PLANE_URL", "http://127.0.0.1:8100")
PORT = 18790


def api(path, body=None, key=None, enroll=False):
    req = urllib.request.Request(PLANE + path, method="POST" if body is not None else "GET")
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    token = os.environ.get("ZTI_ENROLL_TOKEN")
    if enroll and token:
        req.add_header("X-ZTI-Enroll", token)
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(req, data, timeout=5) as resp:
        return json.loads(resp.read())


class Daemon:
    def __init__(self, repo_root: Path, repo_name: str, observe: bool = False):
        self.repo_root = repo_root
        self.observe = observe
        reg = api("/v1/gates/register", {"gate_id": f"gate-{repo_name}",
                                         "repo": repo_name, "agent": "claude-code"}, enroll=True)
        self.gate_id, self.key = reg["gate_id"], reg["api_key"]
        if observe:
            # No contract needed — we're here to learn what the agent does so a
            # contract can be written. Allow everything; record every action.
            self.contract = Contract(work_id=f"observe-{repo_name}", allowed_paths=[])
            self.gate = Gate(self.contract)
            print(f"gated: OBSERVING {repo_name} — allowing all, recording every action. "
                  f"Nothing is blocked. Ctrl-C when done; contractgen (ships with the "
                  f"ZTI Core plane) drafts a contract from what was observed.", flush=True)
            return
        pol = api(f"/v1/gates/{self.gate_id}/policy", key=self.key)
        self.contract = Contract(**pol["contract"])
        self.gate = Gate(self.contract)
        print(f"gated: contract for {repo_name} loaded (etag {pol['etag']}) — enforcing", flush=True)

    def ship(self, action, decision):
        kind = "observation" if self.observe else "decision"
        try:
            api(f"/v1/gates/{self.gate_id}/events",
                {"events": [{"kind": kind, "action": action,
                             "decision": decision.decision,
                             "reason_code": decision.reason_code,
                             "detail": decision.detail}]}, self.key)
        except Exception:
            pass  # plane down → keep enforcing; evidence ships when it returns

    def rel(self, p: str) -> str:
        resolved = Path(p).resolve()
        try:
            return str(resolved.relative_to(self.repo_root))
        except ValueError:
            # Target escaped the repo root. Return the ABSOLUTE resolved path so the
            # gate's scope check treats it as out-of-scope (an absolute path matches
            # no repo-relative pattern) — never a repo-relative-looking string that
            # could slip an allowed glob. Fail-closed at the daemon boundary.
            return str(resolved)

    def _observe(self, action, irreversible: bool):
        # Learn mode: record the action, flag only the contract-independent signal
        # (irreversible), never block. Scope is unknown yet — that's what we're
        # here to learn.
        from ztipgate.gate import ALLOW, Decision
        code = "IRREVERSIBLE_SEEN" if irreversible else "OBSERVED"
        return Decision(ALLOW, code, action.get("command", ""))

    def evaluate(self, tool: str, tool_input: dict):
        if tool in ("Write", "Edit", "NotebookEdit"):
            path = self.rel(tool_input.get("file_path", ""))
            action = {"type": "write", "path": path, "command": f"{tool} {path}"}
            # A file write is never an irreversible *command* — irreversibility is a
            # property of Bash commands, not path names (a file named truncate.md is
            # not a truncate). Observe mode records the write without that flag.
            d = self._observe(action, False) if self.observe \
                else self.gate.check_action(action)
        elif tool == "Bash":
            cmd = tool_input.get("command", "")
            action = {"type": "exec", "path": "", "command": cmd}
            if self.observe:
                d = self._observe(action, is_irreversible(cmd))
            elif is_irreversible(cmd):
                d = self.gate.check_action({"type": "exec", "path": "irreversible",
                                            "command": cmd})
            else:
                hit = self._forbidden_token(cmd)
                if hit:
                    d = self.gate.check_action({"type": "exec", "path": hit, "command": cmd})
                else:
                    from ztipgate.gate import ALLOW, Decision
                    d = Decision(ALLOW, "BASH_PASSTHROUGH",
                                 "no irreversible pattern, no forbidden path token (v0 screening)")
        else:
            return None, None
        self.ship(action, d)
        return action, d

    def _forbidden_token(self, cmd: str):
        forbidden = self.contract.forbidden_paths
        for token in re.split(r"[\s;|&<>()'\"]+", cmd):
            if not token or token.startswith("-"):
                continue
            # Match forbidden against BOTH the literal repo-relative spelling AND the
            # symlink-resolved path. The literal (normalized lexically inside _match)
            # catches an in-repo path or symlink NAMED in forbidden_paths — including
            # one that resolves outside the repo, which rel() would otherwise turn
            # into an unmatched absolute path. The resolved form catches an absolute
            # in-repo path or a token that resolves INTO a forbidden dir. Forbidden
            # matching is case-insensitive, mirroring check_action.
            for t in (token, self.rel(token)):
                if _match(t, forbidden, case_insensitive=True):
                    # Return the matched form so check_action re-matches it as
                    # forbidden (FORBIDDEN_PATH_WRITE), not the resolved absolute
                    # path (which it would read as OUT_OF_SCOPE).
                    return t
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--repo-name", required=True)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--observe", action="store_true",
                    help="learn mode: allow everything, record every action for contractgen")
    args = ap.parse_args()
    daemon = Daemon(Path(args.repo_root).resolve(), args.repo_name, observe=args.observe)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            action, d = daemon.evaluate(body.get("tool_name", ""), body.get("tool_input") or {})
            if d is None:
                payload = {"decision": "allow", "reason": "not gated"}
            else:
                payload = {"decision": "deny" if d.decision in ("deny", "escalate") else "allow",
                           "reason": f"{d.reason_code}: {d.detail}"}
                print(f"gated: {d.decision.upper():6} [{d.reason_code}] {action['command'][:80]}", flush=True)
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass

    print(f"gated: listening on 127.0.0.1:{args.port}", flush=True)
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
