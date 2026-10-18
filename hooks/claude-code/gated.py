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
import hashlib
import hmac
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# Every ztipgate import sits under the fallback: run as a bare script beside a
# checkout with nothing installed, the FIRST ztipgate import is the one that
# fails, and an import above this block used to kill the daemon with
# ModuleNotFoundError before the fallback could run.
try:
    from ztipgate.gate import (DENY, Contract, Decision, Gate, _match,
                               is_irreversible)
    from ztipgate.transport import PlaneURLRefused, apply_transport
except ImportError:  # bare script beside a checkout, nothing installed
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from ztipgate.gate import (DENY, Contract, Decision, Gate, _match,
                               is_irreversible)
    from ztipgate.transport import PlaneURLRefused, apply_transport

PLANE = os.environ.get("ZTI_PLANE_URL", "http://127.0.0.1:8100")
PORT = 18790

# Which refusals are worth asking a human about. An
# ALLOWLIST, not "everything that is not a hard deny", so a future reason code
# never becomes approvable by accident.
#
#   UNSCOPED_ACTION  the gate library's own ESCALATE — it already says
#                    "requires explicit approval"
#   OUT_OF_SCOPE     a write to a path the lease is SILENT about: a question
#                    the operator has not been asked
#
# Deliberately absent, and never to be added:
#   FORBIDDEN_PATH_WRITE        the operator ALREADY answered — explicitly out
#                               of scope. Re-asking it through an inbox would
#                               let an agent relitigate a standing refusal.
#   IRREVERSIBLE_ACTION_BLOCKED the class this product exists to refuse.
_ESCALATABLE_REASON_CODES = frozenset({"UNSCOPED_ACTION", "OUT_OF_SCOPE"})


# Where the daemon drops the per-session secret for the hook to read. Same-user
# file, 0600: it raises the local bar against a port-squatting impostor that has
# NOT read this file, and does NOT pretend to stop an agent that reads its own
# session state -- that residual is the gate-key custody limit of anything that
# runs as the agent's own user, closable only by signing off the machine.
SESSION_FILE_ENV = "ZTI_GATE_SESSION_FILE"
_SESSION_FILE_DEFAULT = ".zti/gated.session"


def _mac(secret: str, raw: bytes, decision: str, reason: str) -> str:
    """Authenticate one hook answer. Signed over the EXACT request bytes the
    hook sent (which carry its fresh single-use nonce) plus the decision and its
    reason, so an impostor without the secret cannot forge an allow, and a
    captured allow cannot be replayed against a later request (a new nonce means
    new bytes). Raw bytes, not a re-serialisation, so there is no canonical-JSON
    drift between the two sides to smuggle a mismatch through."""
    msg = raw + b"\x00" + decision.encode() + b"\x00" + reason.encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()



def _escalation_action(action: dict) -> dict:
    """The action as the OPERATOR will judge it, which is what the plane
    fingerprints.

    `evaluate` labels a file write with a synthetic command, `f"{tool} {path}"`
    — Write, Edit and NotebookEdit on ONE file therefore produce three
    different strings. Fingerprinting those verbatim made the operator's
    decision protect a TOOL rather than a FILE: review reproduced an agent
    taking a denial on `Write build/x` and getting the same bytes
    written by re-asking as `Edit build/x`. The operator read "deny this write"
    and the plane stored "deny this spelling of this write".

    So a write is presented by its EFFECT: type + path, with a canonical
    `write <path>` command that reads the same in the inbox whichever tool
    asked. Non-write actions carry a real command the agent actually ran, and
    are passed through untouched — there the exact string IS the effect.
    """
    if action.get("type") != "write":
        return action
    return {**action, "command": f"write {action.get('path', '')}"}

# Proof-of-life cadence: how often the daemon tells the plane it is still
# enforcing. Must equal the plane's own heartbeat interval. Duplicated rather
# than imported because this daemon must run as a bare script beside a checkout
# (same rationale as _HEADER_SAFE below); the plane's own tests pin the two
# equal.
HEARTBEAT_INTERVAL_SECONDS = 30


# The characters the plane accepts in an HTTP header value; must equal the
# plane's own set. Duplicated rather than imported: this daemon must run as a
# bare script beside a checkout, and the plane's auth module pulls in FastAPI.
# The plane's own tests pin the two sets equal.
_HEADER_SAFE = frozenset(chr(c) for c in range(0x21, 0x7F)) | {" ", "\t"}


def _safe(text, cap=300) -> str:
    """Anything the PLANE chose, on its way to the operator's terminal.

    ZTI_PLANE_URL defaults to plain http, so this text is attacker-reachable. Raw
    ESC sequences can clear the screen and reprint a forged "contract loaded —
    enforcing" line, or a forged ALLOW decision, over the real output — and the
    line being overwritten is the one the operator reads to confirm enforcement is
    live. Printable characters only, and bounded.
    """
    return "".join(ch for ch in str(text) if ch.isprintable())[:cap]


def _decision_line(decision, reason_code, command) -> str:
    """The operator-facing DENY/ALLOW line.

    `command` arrives from the local hook port, so a governed agent could embed a
    cursor-up-and-erase sequence to remove the DENY line its own command just
    produced — inside this product's threat model. Its own function so the line can
    be tested without standing up the HTTP handler.
    """
    return (f"gated: {_safe(decision.upper(), 16):6} "
            f"[{_safe(reason_code, 48)}] {_safe(command, 80)}")


def _refusal(exc) -> str:
    """One readable line from whichever refusal envelope the plane used.

    The plane speaks three: FastAPI's `{"detail": ...}`, the licensing body
    (`{"decision","reason","module","contact"}`, emitted verbatim), and the global
    fail-closed body (`{"decision","reason"}`). Keying only on `detail` would drop
    the reason from the one refusal every customer eventually meets — trial expiry.
    """
    line = _safe(f"HTTP {exc.code} {exc.reason}".rstrip(), 200)
    try:
        body = json.loads(exc.read(65536))  # capped: a hostile plane is not a heap
    except Exception:
        return line
    if not isinstance(body, dict):
        return line
    reason = body.get("detail") or body.get("reason") or ""
    if not isinstance(reason, str):
        reason = json.dumps(reason)
    extra = " ".join(f"{k}={body[k]}" for k in ("module", "contact") if body.get(k))
    tail = " ".join(part for part in (reason, extra) if part)
    # Cap the WHOLE line, not just the body half: the status phrase is plane-chosen
    # too and http.client will carry about 64 KB of it.
    return _safe(f"{line} — {tail}", 300) if tail else line


class PlaneError(RuntimeError):
    """The plane answered and refused. Carries the plane's own coded reason.

    Without this, urlopen raises before the response body is read and the reason
    is discarded — a plane that refused for a nameable reason read to the operator
    as "plane down", which is the one thing it was not."""


def api(path, body=None, key=None, enroll=False):
    req = urllib.request.Request(PLANE + path, method="POST" if body is not None else "GET")
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    token = os.environ.get("ZTI_ENROLL_TOKEN")
    if enroll and token:
        if any(ch not in _HEADER_SAFE for ch in token) or token != token.strip():
            # The plane's own rule, applied before http.client raises ten frames
            # down. A trailing newline out of a secret store is the likeliest case,
            # and it is latin-1 encodable, so an encodability check misses it. The
            # value is never interpolated into the message — it is the secret.
            raise PlaneError("ZTI_ENROLL_TOKEN cannot be sent as an HTTP header "
                             "(empty, padded, or containing characters a header "
                             "cannot carry) — the plane will not accept it either") from None
        req.add_header("X-ZTI-Enroll", token)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise PlaneError(f"plane refused {path}: {_refusal(exc)}") from None
    except urllib.error.URLError as exc:
        # The plane being unreachable is the state the operator most needs told
        # apart from the plane refusing — one line each, never a stack trace.
        raise PlaneError(f"plane unreachable at {PLANE}: {exc.reason}") from None
    except OSError as exc:
        raise PlaneError(f"plane unreachable at {PLANE}: {exc}") from None
    except Exception as exc:
        # Catch-all, last: http.client raises HTTPException (BadStatusLine and
        # friends) outside urllib's OSError wrapper, and a malformed status line
        # carries attacker bytes straight into the traceback — bypassing both halves
        # of _safe. A bad body (JSONDecodeError) lands here too. A malformed 200 body
        # that omits a key does NOT: that raises in Daemon.__init__, outside this try.
        # The exception TYPE is named; its message is not, because that is where the
        # plane's bytes live.
        raise PlaneError(f"plane returned an unreadable response: "
                         f"{_safe(type(exc).__name__, 64)}") from None


def _announce(msg, stream=None):
    """Say something to the operator — and never let saying it change a verdict.

    The daemon's stdout is a pipe the hook client owns. A dead reader raises
    BrokenPipeError, and an ASCII-only stdout raises UnicodeEncodeError on a
    plane-chosen etag (`_safe` permits any printable, not just ASCII). Either
    one used to escape `_refresh_contract`, and from there `_consult_release`
    and `evaluate()` — so the action was correctly blocked but the daemon
    shipped NO decision event and the plane never heard about the denial
    (found in review, reproduced both ways).

    An announcement is not enforcement. It is never raised — but it is not
    silently thrown away either. Swallowing an unencodable line made ENFORCING
    mode look exactly like OBSERVE mode on a non-UTF-8 terminal (both banners
    carry an em dash), and let a governed agent suppress its own DENY line just
    by putting a non-ASCII character in a path. Losing the message is a defect
    in its own right: a surface that quietly stops saying what it knows. So an
    unencodable line is re-encoded lossily and printed anyway; only a stream
    that cannot be written to at all is given up on.
    """
    out = stream if stream is not None else sys.stdout
    try:
        print(msg, file=out, flush=True)
        return
    except UnicodeEncodeError:
        pass
    except Exception:
        return              # a dead pipe cannot be written to, lossily or not
    try:
        enc = getattr(out, "encoding", None) or "ascii"
        print(msg.encode(enc, "replace").decode(enc, "replace"), file=out, flush=True)
    except Exception:
        pass


class Daemon:
    def __init__(self, repo_root: Path, repo_name: str, observe: bool = False):
        self.repo_root = repo_root
        self.repo_name = repo_name
        self.observe = observe
        reg = api("/v1/gates/register", {"gate_id": f"gate-{repo_name}",
                                         "repo": repo_name, "agent": "claude-code"}, enroll=True)
        # The PLANE chooses gate_id, and it is interpolated into every later request
        # path and into operator-facing messages. Sanitised at the boundary.
        self.gate_id, self.key = _safe(reg["gate_id"], 128), reg["api_key"]
        # The plane-minted per-session secret the daemon proves to the hook on
        # every answer. An old plane that does not issue one leaves the
        # daemon unable to authenticate itself; that is a fail-CLOSED start, not a
        # silent downgrade -- the hook then refuses every allow it cannot verify.
        self.hook_secret = reg.get("hook_secret")
        if not self.hook_secret:
            raise PlaneError("plane did not issue a hook session secret -- refusing "
                             "to start a daemon the hook cannot authenticate "
                             "(upgrade the plane to a release that issues one)")
        self._write_session_file()
        if observe:
            # No contract needed — we're here to learn what the agent does so a
            # contract can be written. Allow everything; record every action.
            self.contract = Contract(work_id=f"observe-{repo_name}", allowed_paths=[])
            self.policy_etag = None      # observe mode never escalates
            self.gate = Gate(self.contract)
            _announce(f"gated: OBSERVING {repo_name} — allowing all, recording every "
                      f"action. Nothing is blocked. Ctrl-C when done; contractgen "
                      f"(ships with the ZTI Core plane) drafts a contract from what "
                      f"was observed.")
            return
        pol = api(f"/v1/gates/{self.gate_id}/policy", key=self.key)
        self.contract = Contract(**pol["contract"])
        # The basis this gate is judging on. Declared to the plane on every
        # escalation so a gate still holding a superseded
        # contract cannot have an action the CURRENT one forbids released: it
        # would report that path as OUT_OF_SCOPE, which is escalatable, where a
        # gate holding the live contract reports FORBIDDEN_PATH_WRITE, which is
        # not. Sanitised like every other plane-chosen string.
        self.policy_etag = _safe(pol["etag"], 64)
        self.gate = Gate(self.contract)
        # etag is plane-chosen: this is the line the operator reads to confirm
        # enforcement is live, so it is the most valuable one to forge over.
        _announce(f"gated: contract for {repo_name} loaded "
                  f"(etag {_safe(pol['etag'], 64)}) — enforcing")

    def _write_session_file(self):
        """Hand the hook this session's secret through a 0600 same-user file. The
        secret NEVER leaves the machine and never touches stdout (which the hook
        client owns). If the file cannot be written the daemon refuses to start:
        a running daemon whose answers the hook can never authenticate would deny
        every action while looking healthy on the plane -- fail closed, loudly, at
        startup instead."""
        env = os.environ.get(SESSION_FILE_ENV)
        path = Path(env) if env else (self.repo_root / _SESSION_FILE_DEFAULT)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Create 0600 from the start; do not widen an existing file's mode.
            # O_NOFOLLOW: never write the secret through a symlink planted at
            # the path (found in review). O_EXCL is deliberately
            # NOT used -- the daemon rewrites its own file on every restart, so
            # requiring create-exclusive would refuse a legitimate restart.
            fd = os.open(str(path),
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, self.hook_secret.encode())
            finally:
                os.close(fd)
            os.chmod(str(path), 0o600)
        except OSError as exc:
            raise PlaneError(f"cannot write the hook session file at {path}: {exc}") from None
        self.session_file = path

    def start_heartbeat(self):
        """Beat to the plane on a timer so a quiet session —
        the agent thinking, not calling tools — never reads as a disarm. A
        failed beat is swallowed on purpose: the plane is never in the
        evaluation path, enforcement continues on the cached
        contract, and the plane honestly records the silence as darkness —
        from its side an unreachable gate IS unobservable."""
        def loop():
            while True:
                time.sleep(HEARTBEAT_INTERVAL_SECONDS)
                try:
                    api(f"/v1/gates/{self.gate_id}/heartbeat", {}, self.key)
                except Exception:
                    pass
        threading.Thread(target=loop, daemon=True).start()

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
        if not self.observe and d.decision != "allow" \
                and d.reason_code in _ESCALATABLE_REASON_CODES:
            d = self._consult_release(action, d)
        self.ship(action, d)
        return action, d

    def _consult_release(self, action, denial):
        """Present the action to the plane and take back the operator's
        standing authority for it, if there is one.

        This is the ONLY thing that can turn this gate's own refusal into an
        allow, and it can only ever move in that direction. The evaluation
        above already happened, locally, against the cached contract — a plane
        that is down, slow, refusing, or answering nonsense leaves `denial`
        exactly as it was. That is why consulting the plane here does not put
        it in the evaluation path: it can release, never
        permit, and enforcement never weakens when the plane is unreachable.

        The gate does not name an escalation id — it re-presents the action,
        and the plane matches it by fingerprint. So a broadened re-run finds
        nothing, and an approval is spent exactly once, by the plane.
        """
        try:
            answer = api(f"/v1/gates/{self.gate_id}/escalations",
                         {"reason_code": denial.reason_code,
                          "action": _escalation_action(action),
                          "policy_etag": self.policy_etag}, self.key)
            # Coerced to a string INSIDE the guard. `state` is plane-chosen and
            # is used below as a dict key: an unhashable value ({} or []) from
            # a hostile or newer plane raised TypeError straight out of
            # evaluate(), which falsified this function's own claim that every
            # failure of the consult is a deny (found in review — the hook
            # still failed closed, but by accident, on a dropped HTTP response
            # rather than by this code's decision).
            state = answer.get("state")
            state = state if isinstance(state, str) else repr(state)
            esc_id = answer.get("escalation_id")
        except Exception:
            # Includes PlaneError and any malformed body — a POLICY_STALE
            # refusal lands here too, as a 409. Either way the answer is the
            # denial we already reached locally. Re-pulling the contract is
            # attempted NEXT, not here, and its failure changes nothing: the
            # gate keeps enforcing the contract it holds.
            self._refresh_contract()
            return Decision(denial.decision, denial.reason_code,
                            f"{denial.detail} (approval unavailable: plane did not answer)")
        if state == "approved":
            return self.gate.record_release(
                action, f"released once by operator approval "
                        f"(escalation {_safe(esc_id, 32)})")
        # pending, denied, and ANY state this client does not recognise — a
        # hostile or newer plane cannot invent a value that reads as a release.
        note = {"pending": f"awaiting operator approval (escalation {_safe(esc_id, 32)})",
                "denied": "operator denied this action"}.get(
                    state, f"not released (plane said {_safe(state, 32)})")
        return Decision(denial.decision, denial.reason_code, f"{denial.detail} — {note}")

    def _refresh_contract(self):
        """Re-pull the contract after the plane refused a consult.

        The daemon otherwise pulls once at startup and never again, which is
        exactly what let a stale gate keep classifying a now-forbidden path as
        merely unscoped. A failure here is swallowed: the gate goes on enforcing
        the contract it already holds — the plane is never required for
        enforcement, only for release.
        """
        try:
            pol = api(f"/v1/gates/{self.gate_id}/policy", key=self.key)
            contract = Contract(**pol["contract"])
            etag = _safe(pol["etag"], 64)
        except Exception:
            # The etag read belongs INSIDE this guard. It sat outside, so a 200
            # whose body simply omitted `etag` raised KeyError out of here, out
            # of _consult_release and out of evaluate() — and the daemon then
            # shipped NO decision event, leaving a denial that held locally but
            # was invisible to the plane, with a traceback where the DENY line
            # should be. Reachable from a version-skewed plane or a MITM on the
            # default plain-http transport. Same rule as the consult above:
            # every failure here is a swallowed refusal to refresh, never a
            # raised one.
            return
        if etag == self.policy_etag:
            return
        self.contract = contract
        self.policy_etag = etag
        # The Gate carries this session's audit chain and its blocked/completed
        # record, so it is REBOUND to the new contract rather than replaced —
        # replacing it would silently drop the session's tamper-evident history.
        self.gate.contract = contract
        _announce(f"gated: contract for {self.repo_name} refreshed "
                  f"(etag {self.policy_etag}) — enforcing")

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


def make_server(daemon, port):
    """The local decision endpoint the PreToolUse hook talks to.

    Module level, not a closure inside `main()`, because everything in here is
    operator-facing and enforcement-relevant and none of it was reachable from a
    test while it was nested.
    """

    class Handler(BaseHTTPRequestHandler):
        # This server is single-threaded on purpose — one agent, one hook at a
        # time — so a socket that opens and then says nothing used to wedge it
        # until the client gave up. A local process gets no bypass from that
        # (the hook fails closed) but it does get to stall the agent silently.
        #
        # Deliberately SHORTER than the hook client's own 3s budget: at 10s a
        # single silent socket, or one byte dripped every few seconds, still
        # held the daemon long enough that every real hook call landing in the
        # window blew its own timeout and failed closed. A stall the daemon
        # tolerates for longer than its caller does is not bounded, it is
        # deferred (measured in review).
        timeout = 2

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if length < 0:
                    # rfile.read(-1) reads until EOF, which for an open socket
                    # that sends nothing is forever. Only NEGATIVE is refused: an
                    # upper clamp looks prudent and is not. A Write's tool_input
                    # carries the file's whole CONTENT, so a 1 MiB cap denied a
                    # legitimate write to an ALLOWED path and then told the plane
                    # the gate could not read the request — a specific untrue
                    # statement about a specific action, at a size agents cross
                    # routinely (lockfiles, fixtures, bundles). The stall an
                    # upper bound was reaching for is the timeout's job, and the
                    # timeout does not have to guess what is legitimate.
                    raise ValueError(f"negative Content-Length {length}")
                raw = self.rfile.read(length)
                body = json.loads(raw)
                if not isinstance(body, dict):
                    raise ValueError("request body is not an object")
                action, d = daemon.evaluate(body.get("tool_name", ""),
                                            body.get("tool_input") or {})
            except Exception as exc:
                # A request this daemon cannot read is not a reason to stop
                # enforcing, and it is certainly not an allow. Before this guard
                # a one-byte body raised into the stdlib's own error handler,
                # which prints a traceback straight to stderr: 200 malformed
                # posts buried the operator's refusal lines under 4000 lines in
                # 0.08s, and with a dead stderr the FIRST one killed the daemon
                # after it had already registered — so the plane went on
                # reporting the gate online with nothing listening on its port
                # (found in review, reproduced both ways).
                _announce(f"gated: DENY   [MALFORMED_REQUEST] {_safe(exc, 200)}")
                # "A denial the plane never hears about is a defect even though
                # the action was blocked." Before this the request died before
                # `evaluate` could ship anything, so the refusal existed only on
                # the operator's terminal. The synthetic action carries no
                # attacker text beyond the sanitised exception.
                daemon.ship({"type": "exec", "path": "", "command": "unreadable request"},
                            Decision(DENY, "MALFORMED_REQUEST", _safe(exc, 200)))
                self._respond({"decision": "deny",
                               "reason": "MALFORMED_REQUEST: the gate could not "
                                         "read this request"},
                              raw=locals().get("raw", b""))
                return
            if d is None:
                payload = {"decision": "allow", "reason": "not gated"}
            else:
                payload = {"decision": "deny" if d.decision in ("deny", "escalate") else "allow",
                           "reason": f"{d.reason_code}: {d.detail}"}
                _announce(_decision_line(d.decision, d.reason_code, action["command"]))
            self._respond(payload, raw=raw)

        def _respond(self, payload, raw=b""):
            # Authenticate the answer so the hook can tell this daemon from an
            # impostor squatting the port. The mac binds to the exact
            # request bytes + the decision + its reason; the hook recomputes it and
            # refuses an allow that does not carry a valid one.
            payload["mac"] = _mac(daemon.hook_secret, raw,
                                  payload["decision"], payload["reason"])
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass

    class Server(HTTPServer):
        def handle_error(self, request, client_address):
            # The stdlib prints a full traceback to stderr here. That is an
            # unguarded operator-facing write on the one path that is reached
            # precisely when something has already gone wrong — the same
            # dead-stream premise that killed the daemon twice in review.
            _announce("gated: dropped a local request it could not serve",
                      stream=sys.stderr)

    return Server(("127.0.0.1", port), Handler)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--repo-name", required=True)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--observe", action="store_true",
                    help="learn mode: allow everything, record every action for contractgen")
    args = ap.parse_args()
    # Transport policy FIRST: a plaintext plane off this box is
    # refused before the daemon registers — registering would already have put
    # the api key and the hook session secret on the wire. A loopback plane or
    # https passes silently; the explicit override passes with a warning. This
    # also installs the opener: plaintext never rides an environment proxy.
    try:
        warning = apply_transport(PLANE)
    except PlaneURLRefused as exc:
        _announce(f"gated: cannot start — {_safe(exc, 500)}", stream=sys.stderr)
        raise SystemExit(1)
    if warning:
        _announce(f"gated: {_safe(warning, 500)}", stream=sys.stderr)
    try:
        daemon = Daemon(Path(args.repo_root).resolve(), args.repo_name, observe=args.observe)
    except PlaneError as exc:
        # A refusal the plane explained is an operator message, not a traceback.
        _announce(f"gated: cannot start — {_safe(exc, 500)}", stream=sys.stderr)
        raise SystemExit(1)

    daemon.start_heartbeat()
    try:
        server = make_server(daemon, args.port)
    except OSError as exc:
        # By here the gate has registered and is heartbeating, so a bind failure
        # left the plane reporting an online gate with nothing listening — and
        # said so with a raw traceback, on the one startup path that is reached
        # after the plane already believes the gate is up.
        _announce(f"gated: cannot start — {_safe(exc, 500)}", stream=sys.stderr)
        raise SystemExit(1)
    # Announced only once the socket is actually bound. Saying it first meant a
    # port collision printed "listening" and then an unguarded traceback, with
    # the plane already reporting the gate online.
    _announce(f"gated: listening on 127.0.0.1:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
