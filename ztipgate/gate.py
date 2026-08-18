"""ZTI gate library — the contract-enforcement layer for AI coding agents.

This is the piece the open protocol *describes* and the sandboxing tools do NOT
implement: it governs an agent's work as a leased, contract-bound unit, refuses
to accept "done" without independently re-verifying it, and stamps a
hash-chained ZTIP receipt. Fail-closed by construction.

MIT-licensed as part of the open ZTI client gate layer (ADR-0009), published
at github.com/bitscon/zti-cli; the commercial ZTI Core product is the closed
control plane this gate reports to. Depends only on the open `ztip` runtime
for canonicalization, hashing, and receipts — the money is the license, not
concealment.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import posixpath
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

# The open `ztip` runtime is a normal pip dependency. The sibling-checkout
# walker below is a dev convenience that runs ONLY when no `ztip` module exists
# on sys.path (ModuleNotFoundError). An installed ztip that exists but fails to
# import — a broken or half-installed dependency — raises here instead of being
# silently replaced by whatever checkout the walker finds: the module that
# seals receipts is never swapped behind a working install (ADR-0009 round,
# wave 2; narrowed per the zti:truth registered follow-up).
try:
    from ztip.hashing import CANONICALIZATION, HASH_ALGORITHM, envelope_hash
except ModuleNotFoundError:
    for _up in Path(__file__).resolve().parents:
        if (_up / "ztip" / "ztip" / "__init__.py").exists():
            sys.path.insert(0, str(_up / "ztip"))
            break
    from ztip.hashing import CANONICALIZATION, HASH_ALGORITHM, envelope_hash

ALLOW, DENY, ESCALATE = "allow", "deny", "escalate"

# Irreversible, high-blast-radius operations — the verbs behind the real 2025
# incidents. These route to a hard block regardless of path scope.
#
# This is a defense-in-depth denylist, NOT a complete command parser: the primary
# control is path scope (allowed/forbidden), and Bash scoping is screening (see
# the Tier-1 gate daemon, gated.py). `is_irreversible` is LINEAR by construction:
#   1. cap the input (bounds all work);
#   2. drop quoted-string DATA so a verb named inside a message/arg is not a false
#      positive (`git commit -m "fix rm -rf bug"`);
#   3. split on shell separators (;, &&, ||, |, newline) so tokens from DIFFERENT
#      sub-commands cannot combine (`git status && make clean -f`);
#   4. per segment, match the literal `rm -r…-f` cluster and the prefix+argument
#      verbs (dd…of=, find…-delete, git clean…-f, git push…force/+ref/delete) by
#      TOKEN membership on the BASENAME — never a distance-spanning `[^\n]*` regex,
#      which was both a DoS (O(n²)) and a padding bypass.
# The regex below holds only ADJACENT patterns, so it cannot ReDoS and has no gap to
# pad; bare-word verbs need a trailing space so a filename stem (`cat truncate.md`) is
# not the `truncate` command.
# Documented v0 limits (NOT caught — path scope is the backstop): shell obfuscation of
# the command NAME (`\rm`, `'rm'`, `${IFS}`, subshells), a verb executed FROM a quoted
# string (`sh -c "rm -rf /"`), redirection-only destruction (`> /dev/sda`), a verb past
# the input cap, and destructive classes not enumerated here (SQL `DELETE`, etc.).
_IRREVERSIBLE_VERBS = re.compile(
    r"""(
      drop\s+(?:database|table|schema)
    | \btruncate\s
    | \bmkfs(?:\.\w+)?\s
    | \bshred\s
    | \bwipe\s
    | format\s+disk
    | reset\s+--hard
    | \bforce[-\ ]?push\b
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# Quoted-string DATA (single or double quoted) — dropped before matching so a verb
# mentioned inside a message/argument is not a false positive.
_QUOTED_STRING = re.compile(r'"[^"]*"|\'[^\']*\'')
# Shell command separators — matched per segment so tokens don't combine across them.
_SHELL_SEP = re.compile(r"[;&|\n]+")

# DoS bound: caps the absolute worst case no matter how large the input grows. 64 KiB
# is far above any real command (they are well under 2 KiB), so a legitimate command is
# never truncated — only a pathological one is (a documented v0 limit).
_MAX_COMMAND_SCAN = 65536


def _rm_recursive_force(command: str) -> bool:
    """True iff `command` (one already-de-quoted shell segment) carries BOTH recursive
    and force on an `rm`, in any flag order or spelling (`-rf`, `-fr`, `-r -f`,
    `--recursive --force`, `-Rf`). Linear: reads only genuine rm flag clusters —
    `-draft` / `-- -weirdfile` are not flags. Matches the literal `rm` command name
    (basename, so `/bin/rm` counts); an obfuscated name (`\\rm`, `${IFS}rm`) is a
    documented v0 limit. The caller strips quoted DATA and splits on shell separators,
    so a verb named inside a message or in a different sub-command is not counted."""
    seen = recursive = force = False
    for tok in command.split():
        if tok.rsplit("/", 1)[-1] == "rm":
            seen, recursive, force = True, False, False
            continue
        if not seen:
            continue
        if tok == "--recursive":
            recursive = True
        elif tok == "--force":
            force = True
        elif tok.startswith("-") and len(tok) > 1 and all(c in "rRfiIvd" for c in tok[1:]):
            recursive = recursive or "r" in tok or "R" in tok
            force = force or "f" in tok
        if recursive and force:
            return True
    return False


def _token_combo(toks: list[str]) -> bool:
    """Prefix+argument destructive commands, matched by TOKEN membership (lowercased)
    rather than a distance-spanning regex — linear, and with no distance bound an agent
    can pad an argument past (`dd if=<long> of=/dev/sda`, `git clean -e <long> -f`).
    Command NAMES are matched on the basename (`/bin/dd` counts as `dd`), mirroring
    `_rm_recursive_force`; a path prefix must not evade the screen."""
    bases = {t.rsplit("/", 1)[-1] for t in toks}
    if "dd" in bases and any(t.startswith("of=") for t in toks):
        return True
    if "find" in bases and "-delete" in toks:
        return True
    if "git" in bases and "clean" in toks and any(
            t == "--force" or (len(t) > 1 and t[0] == "-" and t[1] != "-" and "f" in t)
            for t in toks):
        return True
    if "git" in bases and "push" in toks and any(
            # force-overwrite (--force*, incl --force-with-lease; -f; +<ref>) or remote
            # branch delete (--delete; -d; :<ref>; +:<ref>) — both rewrite/destroy remote
            # history. A short flag CLUSTER counts (`-fu`, `-fd`): `f`/`d` in a single-dash
            # token, mirroring the git-clean check.
            t.startswith("--force") or t == "--delete" or t.startswith(":")
            or (len(t) > 1 and t[0] == "-" and t[1] != "-" and ("f" in t or "d" in t))
            or (t.startswith("+") and len(t) > 1 and (t[1].isalpha() or t[1] == ":"))
            for t in toks):
        return True
    return False


def is_irreversible(command: str) -> bool:
    """Does `command` contain an irreversible, high-blast-radius operation? Applied
    to the COMMAND only — never a file path (a file named `truncate.md` is not a
    truncate command; running the verb screen over paths wrongly denied legit files)."""
    if not command:
        return False
    command = command[:_MAX_COMMAND_SCAN].replace("\\\n", " ")  # bound + join continuations
    command = _QUOTED_STRING.sub(" ", command)  # drop quoted DATA (not a false positive)
    if _IRREVERSIBLE_VERBS.search(command):
        return True
    for segment in _SHELL_SEP.split(command):
        if _rm_recursive_force(segment) or _token_combo(segment.lower().split()):
            return True
    return False


@dataclass
class Contract:
    """What a unit of work may touch and what must be true for it to be 'done'."""

    work_id: str
    allowed_paths: list[str]
    forbidden_paths: list[str] = field(default_factory=list)
    required_checks: list[str] = field(default_factory=list)


@dataclass
class Decision:
    decision: str
    reason_code: str
    detail: str


# ── ZTIP chain envelopes (ADR-0010) ─────────────────────────────────────────
# The open spec's request→receipt chain: a transaction_request declares the
# unit of work and its verification requirements BEFORE execution; an
# authorization_decision records the policy basis; the execution receipt binds
# to both by hash/ref. All three are built CLIENT-SIDE from artifacts that
# already exist (the governing contract, the operator-published policy).
#
# ZTIP role mapping (ADR-0010): the GATE is the ZTIP `control_plane` — it
# evaluates the request against the operator's published policy, authorizes,
# and independently verifies completion (exactly the local authority ADR-0001
# defines). The workspace/agent is BOTH `source_actor` (it requests the work)
# and `target_actor` (it executes it) — honest, since a coding agent plans and
# executes its own change, and agent-neutral (ADR-0004: the receipt names the
# workspace, never a specific agent). The zti-core plane is the ZTIP audit
# ledger (retain the trail), NOT the control_plane — it is never in the
# evaluation path (ADR-0001/0002).

ZTIP_VERSION = "1.0-draft"  # the spec's common-envelope const; `ztap_version` is its field name

# The capabilities a code-change unit exercises. The target actor (executor)
# must register a superset of what the action requires (SCHEMA.md: required ⊆
# target claims, else a conformant plane rejects CAPABILITY_MISSING).
_CODE_CHANGE_CAPABILITIES = ["file.write", "git.commit", "test.run"]

# ZTIP reason codes the spec enum already defines; everything else the gate
# emits is namespaced per the spec's namespaced-identifier rule.
_ZTIP_ENUM_REASON_CODES = frozenset({
    "SCHEMA_INVALID", "ROLE_INVALID", "ACTOR_UNREGISTERED", "AUTHORITY_MISSING",
    "POLICY_DENIED", "APPROVAL_REPLAYED", "RISK_LEVEL_ESCALATED",
    "CAPABILITY_MISSING", "TARGET_REJECTED", "ACTION_FAILED", "VERIFY_FAILED",
    "COMPLETION_UNVERIFIED", "VERIFY_UNAVAILABLE", "TIMEOUT", "EXPIRED",
    "CANCELLED", "INTEGRITY_FAILED", "EVIDENCE_MISSING",
    "PARTIAL_STATE_BLOCKED", "REGISTRY_INCONSISTENT",
})


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_ts(value: str) -> str:
    """Return `value` as an RFC 3339 **UTC** timestamp. A naive input (no
    offset) is interpreted as UTC; an offset input is converted to UTC — so
    every envelope timestamp is `…+00:00`, matching SCHEMA.md's "ISO 8601, UTC",
    not merely a valid `date-time`. Raises ValueError on a genuinely malformed
    timestamp — fail-closed, not silent."""
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _spec_reason_code(code: str) -> str:
    """A receipt-level reason code in the spec's value set: enum codes pass
    through; gate-specific codes carry the `zti.gate/` namespace."""
    return code if code in _ZTIP_ENUM_REASON_CODES else f"zti.gate/{code}"


def _contract_content_ref(contract: Contract) -> str:
    """The honest offline policy basis for a standalone mint: the contract's own
    content hash (sha256 over its canonical fields). A plane-published contract
    names its etag instead; this is what authorizes a mint with no plane."""
    body = json.dumps({"work_id": contract.work_id,
                       "allowed_paths": list(contract.allowed_paths),
                       "forbidden_paths": list(contract.forbidden_paths),
                       "required_checks": list(contract.required_checks)},
                      sort_keys=True)
    return "contract:sha256:" + hashlib.sha256(body.encode()).hexdigest()


def _actor(actor_id: str, role: list[str], organization_id: str,
           registration_ref: str, capability_claims: list[str] | None = None) -> dict:
    block = {"actor_id": actor_id, "role": role, "organization_id": organization_id,
             "registration_ref": registration_ref}
    if capability_claims:
        block["capability_claims"] = capability_claims
    return block


def _gate_actor(gate_id: str | None, organization_id: str) -> dict:
    """The ZTIP `control_plane` actor: the gate, the local authority that
    evaluates policy and verifies completion. Registered via the plane's gate
    registry when it has a gate_id (the spec's "API key with control plane
    registration" identity), honestly `unregistered` standalone."""
    return _actor(
        actor_id=gate_id or "gate:standalone",
        role=["control_plane"],
        organization_id=organization_id,
        registration_ref=f"zti-core:gates/{gate_id}" if gate_id else "unregistered",
    )


def _workspace_actor(repo: str, roles: list[str], gate_id: str | None,
                     organization_id: str) -> dict:
    """The workspace as a ZTIP actor — `source_actor` (requester) and
    `target_actor` (executor) are the same agent-neutral principal, carrying
    the capabilities a code-change unit exercises."""
    return _actor(
        actor_id=f"workspace:{repo}",
        role=roles,
        organization_id=organization_id,
        registration_ref=f"zti-core:gates/{gate_id}/workspace" if gate_id else "unregistered",
        capability_claims=list(_CODE_CHANGE_CAPABILITIES),
    )


def build_transaction_request(contract: Contract, *, repo: str = "unspecified",
                              gate_id: str | None = None,
                              organization_id: str = "self-hosted",
                              parameters: dict | None = None,
                              created_at: str | None = None) -> dict:
    """A hash-sealed ZTIP transaction_request for one unit of gate-governed work.

    Everything is derived from what genuinely exists: the verification
    requirements are the contract's required checks (declared BEFORE execution,
    as the spec demands, with `verification_actor` = the gate that will re-run
    them), the constraints are the lease's path scope, and the requester/executor
    is the workspace (agent-neutral). The requested capabilities are exactly the
    code-change set the target registers — required ⊆ target claims, so a
    conformant plane never trips CAPABILITY_MISSING. Without a gate_id the mint
    is standalone and says so (`registration_ref: "unregistered"`). A contract
    with no real checks yields an empty `verification_requirements`, which the
    request schema rejects (minItems 1) exactly as the gate rejects the mint
    (`NO_CHECKS_DEFINED`): undeclared verification is nonconformant by design,
    and the stored request shows why.
    """
    if not (isinstance(contract.work_id, str) and contract.work_id.strip()):
        raise ValueError("contract.work_id must be a non-empty string — it is the "
                         "ZTIP transaction_id and must satisfy non_empty_string")
    real_checks = [c for c in contract.required_checks if isinstance(c, str) and c.strip()]
    verifier = gate_id  # the gate is the expected verifier; omit when standalone
    envelope = {
        "ztap_version": ZTIP_VERSION,
        "envelope_type": "transaction_request",
        "transaction_id": contract.work_id,
        "created_at": _normalize_ts(created_at) if created_at else _utc_now_iso(),
        "source_actor": _workspace_actor(repo, ["planner", "source_actor"], gate_id,
                                         organization_id),
        "target_actor": _workspace_actor(repo, ["executor", "target_actor"], gate_id,
                                         organization_id),
        "requested_action": {
            "action_id": f"act-{contract.work_id}",
            "action_type": "code_change_certification",
            "profile": "ztip.core/gitops",
            "description": (f"Certify the unit of work '{contract.work_id}': "
                            f"independently re-run its required checks and mint "
                            f"an execution receipt for the result."),
            "parameters": parameters or {},
            "required_capabilities": list(_CODE_CHANGE_CAPABILITIES),
            "risk_level": "medium",
            "expected_outputs": [
                {"type": "execution_receipt",
                 "expected": "hash-sealed receipt for exactly this unit of work"},
            ],
        },
        "requested_capabilities": list(_CODE_CHANGE_CAPABILITIES),
        "atomicity_mode": "best_effort_allowed",
        "verification_requirements": [
            {"check_id": f"check-{i}", "check_type": "command", "description": check,
             "required": True, "expected_result": "exit 0",
             "failure_reason_code": "VERIFY_FAILED",
             **({"verification_actor": verifier} if verifier else {})}
            for i, check in enumerate(real_checks, start=1)
        ],
        "constraints": {"allowed_paths": list(contract.allowed_paths),
                        "forbidden_paths": list(contract.forbidden_paths)},
        "integrity": {"canonicalization": CANONICALIZATION, "hash_algorithm": HASH_ALGORITHM},
    }
    envelope["integrity"]["hash_value"] = envelope_hash(envelope)
    return envelope


def build_authorization_decision(request: dict, *, policy_ref: str,
                                 gate_id: str | None = None,
                                 organization_id: str = "self-hosted",
                                 evaluated_at: str | None = None) -> dict:
    """A hash-sealed ZTIP authorization_decision for `request`, produced by the
    gate acting as the local ZTIP control plane.

    Honesty is load-bearing: the gate (the `control_plane` actor) evaluates the
    request against the operator-published policy named in `policy_ref` — a
    plane policy etag, or the contract's own content hash offline. The zti-core
    plane (the audit ledger) is NOT the evaluator and is never in the evaluation
    path (ADR-0001/0002); the `notes` field states this. The short expiry scopes
    the authorization to this certification run."""
    when = _normalize_ts(evaluated_at) if evaluated_at else _utc_now_iso()
    expires = (datetime.fromisoformat(when) + timedelta(minutes=15)).isoformat()
    envelope = {
        "ztap_version": ZTIP_VERSION,
        "envelope_type": "authorization_decision",
        "transaction_id": request["transaction_id"],
        "decision_id": f"dec-{request['transaction_id']}",
        "request_hash": envelope_hash(request),
        "control_plane": _gate_actor(gate_id, organization_id),
        "evaluated_at": when,
        "authorization_status": "auto_authorized",
        "policy_refs": [policy_ref],
        "reason_codes": [],
        "authorized_at": when,
        "expires_at": expires,
        "notes": ("Issued by the gate acting as the local ZTIP control plane, "
                  "evaluating this request against the operator-published policy "
                  "in policy_refs. The zti-core plane is the audit ledger, not "
                  "the evaluation authority (ADR-0001/ADR-0002)."),
        "integrity": {"canonicalization": CANONICALIZATION, "hash_algorithm": HASH_ALGORITHM},
    }
    envelope["integrity"]["hash_value"] = envelope_hash(envelope)
    return envelope


# A path deeper than this is not a real repo file — treat it as out of scope
# (fail-closed) rather than feed an unbounded segment count to the matcher. Bounds
# the matcher's work against an agent that sets path depth via the number of '/'.
_MAX_SEGMENTS = 128


def _normalize(path: str) -> str | None:
    """Repo-relative POSIX path, or None if it is absolute, climbs above the repo
    root, or is absurdly deep. The gate governs paths INSIDE the leased repo; an
    absolute path or a `..` escape is out of scope by construction, so it must match
    nothing (→ denied as OUT_OF_SCOPE). Collapses `.`/`//`/`..` so trivially-equivalent
    spellings of the same file cannot dodge a pattern (`src/./secrets` == `src/secrets`)."""
    if not isinstance(path, str) or not path:
        return None
    p = path.replace("\\", "/")
    if p.startswith("/"):
        return None  # absolute — never inside the leased repo
    norm = posixpath.normpath(p)
    if norm == "." or norm == ".." or norm.startswith("../"):
        return None  # `.` is not a file; `..*` escapes the repo root
    if norm.count("/") + 1 > _MAX_SEGMENTS:
        return None  # degenerate depth → out of scope, fail-closed
    return norm


def _seg_norm(seg: str, case_insensitive: bool) -> str:
    """Per-segment normalization for the FORBIDDEN (case-insensitive) check: lowercase
    and strip trailing dots/spaces, which Win32 drops from every path component — so
    `secret.env`, `secret.env ` and `secret.env.` are one file and one forbidden rule
    catches all three."""
    return seg.rstrip(" .").lower() if case_insensitive else seg


def _seg_match(path_segs: list[str], pat_segs: list[str]) -> bool:
    """Segment-aware glob: `*`/`?`/`[...]` match WITHIN one path segment; `**` spans
    zero or more whole segments. (Plain `fnmatch` lets `*` cross `/`, which is why the
    old matcher let `src/*` swallow `src/../secrets`.) ITERATIVE two-pointer with `**`
    backtracking — O(n·m), no recursion: a recursive form RecursionError'd on a deep
    path and blew up exponentially on stacked `**`."""
    i = j = 0
    star_j = -1
    star_i = 0
    n, m = len(path_segs), len(pat_segs)
    while i < n:
        if j < m and pat_segs[j] == "**":
            star_j, star_i, j = j, i, j + 1      # `**` starts by matching zero segments
        elif j < m and pat_segs[j] != "**" and fnmatch.fnmatchcase(path_segs[i], pat_segs[j]):
            i += 1
            j += 1
        elif star_j != -1:
            star_i += 1                          # let the last `**` absorb one more segment
            i = star_i
            j = star_j + 1
        else:
            return False
    while j < m and pat_segs[j] == "**":
        j += 1
    return j == m


def _match(path: str, patterns: list[str], case_insensitive: bool = False) -> bool:
    """Does `path` fall under any of `patterns`?

    A pattern with no glob metacharacter matches the exact file OR the whole subtree
    beneath it at a SEGMENT boundary — so `src` (or `src/`) covers `src/app.py` but
    never the sibling `src_backup`. A pattern with `*`/`**` uses segment-aware glob.

    `case_insensitive` is passed True for the FORBIDDEN check only: on a
    case-insensitive filesystem (macOS/Windows) `PROD.env` and `prod.env` are the
    same file, so a forbidden rule must catch both (and Win32 trailing dot/space is
    folded — see `_seg_norm`). The ALLOWED check stays case-sensitive so a `src`
    lease never leaks to a distinct `SRC/` on Linux."""
    norm = _normalize(path)
    if not norm:
        return False
    path_segs = [_seg_norm(s, case_insensitive) for s in norm.split("/")]
    for raw in patterns:
        if not isinstance(raw, str) or not raw.strip():
            continue
        pat = raw.replace("\\", "/").strip()
        while pat.startswith("./"):
            pat = pat[2:]
        pat = pat.rstrip("/")
        if not pat:
            continue
        pat_norm = posixpath.normpath(pat)
        if pat_norm in (".", ".."):
            continue
        pat_segs = [_seg_norm(s, case_insensitive) for s in pat_norm.split("/")]
        if any(ch in seg for seg in pat_segs for ch in "*?["):
            if _seg_match(path_segs, pat_segs):
                return True
        elif path_segs[:len(pat_segs)] == pat_segs:  # exact file or dir-subtree prefix
            return True
    return False


class Gate:
    """A leased, contract-bound governor for one unit of agent work."""

    def __init__(self, contract: Contract):
        self.contract = contract
        self.attempted: list[dict] = []
        self.completed: list[dict] = []
        self.blocked: list[tuple[dict, Decision]] = []
        self._chain: list[dict] = []  # hash-chained decision audit
        # The receipt certifies the gate's own transaction — the verification
        # run — so its started_at is when this gate began governing the unit.
        self.started_at = _utc_now_iso()

    # ── enforcement (the "block the reckless action" beat) ──────────────────
    def check_action(self, action: dict) -> Decision:
        """action = {"type", "path", "command"}. Fail-closed on anything risky."""
        self.attempted.append(action)
        command = action.get("command", "") or ""
        path = action.get("path", "") or ""

        # Irreversibility is a property of an EXECUTED command, not a file write. The
        # daemon labels a write with a synthetic command (`Write <path>`), so screening
        # it here would run the verb denylist over the path and wrongly block a legit
        # file whose name contains a verb (`scripts/force-push.sh`). Writes are governed
        # by path scope below; only non-write actions carry a real command to screen.
        if action.get("type") != "write" and is_irreversible(command):
            decision = Decision(DENY, "IRREVERSIBLE_ACTION_BLOCKED",
                                 f"irreversible operation refused: {command}")
        elif path and _match(path, self.contract.forbidden_paths, case_insensitive=True):
            decision = Decision(DENY, "FORBIDDEN_PATH_WRITE",
                                 f"path is explicitly out of contract scope: {path}")
        elif path and not _match(path, self.contract.allowed_paths):
            decision = Decision(DENY, "OUT_OF_SCOPE",
                                 f"path not in the leased scope: {path}")
        elif not path:
            # A command-only action can't be scoped to the lease. Never silently
            # allow it — escalate for explicit approval (fail-closed).
            decision = Decision(ESCALATE, "UNSCOPED_ACTION",
                                 f"command-only action cannot be scoped to the lease; "
                                 f"requires explicit approval: {command}")
        else:
            decision = Decision(ALLOW, "IN_SCOPE", f"permitted: {path or command}")

        if decision.decision == ALLOW:
            self.completed.append(action)
        else:
            self.blocked.append((action, decision))
        self._record(action, decision)
        return decision

    # ── the differentiator: independent completion verification ─────────────
    def verify_completion(
        self, claimed_status: str, check_runner: Callable[[str], bool]
    ) -> tuple[bool, list[dict], str]:
        """Re-run every required check ourselves. Never trust the agent's word.

        Each result carries `check_id` (linking it back to the request's
        `verification_requirements[i]`) and `passed`. If a check cannot be run
        at all — the runner raises — completion resolves the spec's third
        fail-closed mode: `VERIFY_UNAVAILABLE` (SPEC.md, Fail-Closed Acceptance;
        "an unverifiable success is not a success"), never propagated as a
        crash."""
        results: list[dict] = []
        all_passed = True
        unavailable = False
        # A "real" check is a non-blank command. A list that is empty — OR contains
        # only blank/whitespace entries (a typo'd or malformed contract) — has nothing
        # to independently re-run, so there is NOTHING to certify. The product's
        # premise is that a success *claim* is not evidence; with no real check there
        # is no evidence to weigh. Fail closed and NEVER read as independently verified
        # (this is exactly the "attestation satisfies a check" trap). A blank entry is
        # skipped, mirroring the path matcher's handling of blank patterns.
        real_checks = [c for c in self.contract.required_checks
                       if isinstance(c, str) and c.strip()]
        for i, check in enumerate(real_checks, start=1):
            entry = {"check_id": f"check-{i}", "check": check, "verifier": "gate-independent"}
            try:
                passed = bool(check_runner(check))
            except Exception as exc:  # verifier could not run this check
                entry.update(passed=False, available=False, detail=str(exc))
                results.append(entry)
                all_passed = False
                unavailable = True
                continue
            entry["passed"] = passed
            results.append(entry)
            all_passed = all_passed and passed
        if not real_checks:
            return False, results, "NO_CHECKS_DEFINED"
        if unavailable:
            return False, results, "VERIFY_UNAVAILABLE"
        accepted = (claimed_status == "succeeded") and all_passed
        reason = "COMPLETION_VERIFIED" if accepted else "COMPLETION_UNVERIFIED"
        return accepted, results, reason

    # ── the tamper-evident ZTIP receipt ─────────────────────────────────────
    def _completion_reason_codes(self, claimed_status: str, completion_reason: str,
                                 verification_results: list[dict]) -> list[str]:
        """The spec's distinct completion-failure codes (SPEC.md, Fail-Closed
        Acceptance): a check that could not be run is VERIFY_UNAVAILABLE; a
        check that ran and did not pass is VERIFY_FAILED; an executor that did
        not itself claim success is ACTION_FAILED; a success claim with no
        independent verification is COMPLETION_UNVERIFIED. Every condition that
        is true is recorded."""
        if completion_reason == "NO_CHECKS_DEFINED":
            return [_spec_reason_code("NO_CHECKS_DEFINED")]
        codes = []
        if completion_reason == "VERIFY_UNAVAILABLE" or any(
                r.get("available") is False for r in verification_results):
            codes.append("VERIFY_UNAVAILABLE")
        if any(r.get("passed") is False and r.get("available") is not False
               for r in verification_results):
            codes.append("VERIFY_FAILED")
        if claimed_status != "succeeded":
            codes.append("ACTION_FAILED")
        return codes or ["COMPLETION_UNVERIFIED"]

    def _atomicity_result(self, accepted: bool) -> dict:
        result = {"mode_declared": "best_effort_allowed", "rollback_performed": False}
        if accepted:
            result["outcome"] = "full"
        elif self.completed:
            result["outcome"] = "partial"
            result["partial_state_description"] = {
                "actions_completed": len(self.completed),
                "actions_blocked": len(self.blocked)}
        else:
            result["outcome"] = "none"
        return result

    def issue_receipt(self, claimed_status: str, accepted: bool,
                      verification_results: list[dict], completion_reason: str,
                      *, request: dict | None = None,
                      authorization: dict | None = None) -> dict:
        """Mint the execution receipt — format 2, full ZTIP execution-receipt
        conformance (ADR-0010).

        Every execution receipt answers a request: the spec has no chain-less
        receipt (`request_hash` and `authorization_decision_ref` are required on
        every one). So `request`/`authorization` are optional only as an
        OVERRIDE — pass both to bind the exact envelopes the plane will store
        (the `zti receipt` path), or neither and the gate builds the honest
        standalone chain from the contract it holds (an unregistered workspace,
        the contract's own content hash as the policy basis). Either way the
        receipt is schema-conformant and chain-linked. The gate is the
        `control_plane` (the verifying authority); results name it per check."""
        if (request is None) != (authorization is None):
            raise ValueError("request and authorization travel together: pass both "
                             "(bind the exact plane-stored envelopes) or neither "
                             "(the gate builds the standalone chain)")
        if request is None:
            request = build_transaction_request(self.contract)
            authorization = build_authorization_decision(
                request, policy_ref=_contract_content_ref(self.contract))

        # Deny codes belong to a FAILED receipt's reason (why it did not
        # succeed); on a SUCCEEDED receipt reason_codes stay empty — the blocks
        # are fully recorded in actions_blocked, and the spec reserves a
        # succeeded receipt's reason_codes for confirming the policy basis, not
        # carrying denials.
        if accepted:
            reason_codes: list[str] = []
        else:
            reason_codes = self._completion_reason_codes(
                claimed_status, completion_reason, verification_results)
            reason_codes += [_spec_reason_code(d.reason_code) for _, d in self.blocked]

        gate = dict(authorization["control_plane"])
        source = {k: request["source_actor"][k]
                  for k in ("actor_id", "role", "organization_id", "registration_ref")}
        target = {k: request["target_actor"][k]
                  for k in ("actor_id", "role", "organization_id", "registration_ref")}
        now = _utc_now_iso()
        envelope = {
            "ztap_version": ZTIP_VERSION,
            "zti_receipt_format": 2,
            "envelope_type": "execution_receipt",
            "transaction_id": self.contract.work_id,
            "receipt_id": f"rcpt-{self.contract.work_id}",
            "request_hash": envelope_hash(request),
            "authorization_decision_ref": authorization["decision_id"],
            "source_actor": source,
            "target_actor": target,
            "control_plane": gate,
            "started_at": self.started_at,
            "completed_at": now,
            "issued_at": now,
            # The spec's fail-closed completion semantics: a refused claim is a
            # FAILED transaction (a pre-execution policy refusal would be
            # `rejected`; this gate refuses at verification time).
            "status": "succeeded" if accepted else "failed",
            "agent_claimed_status": claimed_status,
            "reason_codes": reason_codes,
            "actions_attempted": [self._summary(a) for a in self.attempted],
            "actions_completed": [self._summary(a) for a in self.completed],
            "actions_blocked": [
                {"action": self._summary(a), "reason_code": d.reason_code, "detail": d.detail}
                for a, d in self.blocked
            ],
            # Each result names the verifying authority — the gate (control_plane)
            # — via `verification_actor`, the field SPEC.md's Recorded Results
            # section requires; `verifier` is kept for format-1 readers.
            "verification_results": [
                {**r, "verification_actor": gate["actor_id"]}
                for r in verification_results
            ],
            "verification_authority": "independent-gate",
            "atomicity_result": self._atomicity_result(accepted),
            "audit_chain_head": self._chain[-1]["hash"] if self._chain else None,
            "integrity": {"canonicalization": CANONICALIZATION, "hash_algorithm": HASH_ALGORITHM},
        }
        envelope["integrity"]["hash_value"] = envelope_hash(envelope)
        return envelope

    # ── hash-chained audit (tamper-evident record of every decision) ────────
    def _record(self, action: dict, decision: Decision) -> None:
        entry = {
            "seq": len(self._chain),
            "action": self._summary(action),
            "decision": decision.decision,
            "reason_code": decision.reason_code,
            "prev_hash": self._chain[-1]["hash"] if self._chain else None,
        }
        entry["hash"] = envelope_hash(entry)
        self._chain.append(entry)

    @property
    def audit_chain(self) -> list[dict]:
        return self._chain

    @staticmethod
    def _summary(action: dict) -> dict:
        return {k: action.get(k) for k in ("type", "path", "command") if action.get(k)}
