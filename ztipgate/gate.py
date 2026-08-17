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
import posixpath
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

# The open `ztip` runtime is a normal pip dependency. The fallback walker runs
# ONLY when it is not installed (a sibling checkout, dev convenience) — an
# installed ztip always wins, so nothing on the filesystem can shadow the
# hashing module that seals receipts (ADR-0009 round, wave 2).
try:
    from ztip.hashing import CANONICALIZATION, HASH_ALGORITHM, envelope_hash
except ImportError:
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
        """Re-run every required check ourselves. Never trust the agent's word."""
        results: list[dict] = []
        all_passed = True
        # A "real" check is a non-blank command. A list that is empty — OR contains
        # only blank/whitespace entries (a typo'd or malformed contract) — has nothing
        # to independently re-run, so there is NOTHING to certify. The product's
        # premise is that a success *claim* is not evidence; with no real check there
        # is no evidence to weigh. Fail closed and NEVER read as independently verified
        # (this is exactly the "attestation satisfies a check" trap). A blank entry is
        # skipped, mirroring the path matcher's handling of blank patterns.
        real_checks = [c for c in self.contract.required_checks
                       if isinstance(c, str) and c.strip()]
        for check in real_checks:
            passed = bool(check_runner(check))
            results.append({"check": check, "passed": passed, "verifier": "gate-independent"})
            all_passed = all_passed and passed
        if not real_checks:
            return False, results, "NO_CHECKS_DEFINED"
        accepted = (claimed_status == "succeeded") and all_passed
        reason = "COMPLETION_VERIFIED" if accepted else "COMPLETION_UNVERIFIED"
        return accepted, results, reason

    # ── the tamper-evident ZTIP receipt ─────────────────────────────────────
    def issue_receipt(self, claimed_status: str, accepted: bool,
                      verification_results: list[dict], completion_reason: str) -> dict:
        reason_codes = [] if accepted else [completion_reason]
        reason_codes += [d.reason_code for _, d in self.blocked]
        envelope = {
            "ztap_version": "1.0-draft",
            "envelope_type": "execution_receipt",
            "transaction_id": self.contract.work_id,
            "receipt_id": f"rcpt-{self.contract.work_id}",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "status": "succeeded" if accepted else "blocked",
            "agent_claimed_status": claimed_status,
            "reason_codes": reason_codes,
            "actions_attempted": [self._summary(a) for a in self.attempted],
            "actions_completed": [self._summary(a) for a in self.completed],
            "actions_blocked": [
                {"action": self._summary(a), "reason_code": d.reason_code, "detail": d.detail}
                for a, d in self.blocked
            ],
            "verification_results": verification_results,
            "verification_authority": "independent-gate",
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
