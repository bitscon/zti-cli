"""zti — the ZTI client CLI (ADR-0004, opened under ADR-0009).

Three verbs, one binding model (receipt ↔ git tree hash):

  zti receipt        re-run the contract's required checks (independent — never
                     the agent's word), mint a hash-sealed ZTIP receipt for the
                     exact staged content, ship it to the plane bound to
                     `git write-tree`
  zti verify         does a passing, hash-verified receipt exist for this
                     content? --staged checks the index (Tier 2, pre-commit);
                     a SHA checks <sha>^{tree} (Tier 3, CI). Exit 0 = yes.
  zti install-hooks  drop the Tier-2 pre-commit receipt-gate into .git/hooks

Fail-closed on every path: no receipt, failed receipt, unreachable plane, and
a license-locked plane (402) all block. Agent-neutral: nothing here knows or
cares which agent (or human) produced the change — only git content and the
plane's stored receipts speak.

Config: `.zti/config.json` in the repo ({"plane_url", "gate_id"}) and
`.zti/gate.key` (bearer key — keep it out of version control), overridable by
ZTI_PLANE_URL / ZTI_GATE_ID / ZTI_GATE_KEY.

Exit codes:
  0  passing receipt found / receipt minted passing
  1  RECEIPT_NOT_PASSED   — receipt exists for this content but is not passing
  2  DONE_WITHOUT_RECEIPT — no receipt for this content
  3  PLANE_UNAVAILABLE    — plane unreachable, erroring, or license-locked
  4  usage / environment error (not a git repo, no gate key, bad contract…)
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from ztipgate.gate import Contract, Gate

PASS, RECEIPT_NOT_PASSED, DONE_WITHOUT_RECEIPT, PLANE_UNAVAILABLE, USAGE = 0, 1, 2, 3, 4
DEFAULT_PLANE = "http://127.0.0.1:8100"


class PlaneUnavailable(Exception):
    pass


# ── git ──────────────────────────────────────────────────────────────────────

def _git(*args: str, cwd: Path | None = None) -> str:
    proc = subprocess.run(["git", *args], capture_output=True, text=True, cwd=cwd)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def repo_root() -> Path:
    return Path(_git("rev-parse", "--show-toplevel"))


def staged_tree(cwd: Path) -> str:
    """The content address of exactly what would be committed (Tier-2 key)."""
    return _git("write-tree", cwd=cwd)


def commit_tree(sha: str, cwd: Path) -> str:
    """The same content address, derived from an existing commit (Tier-3 key)."""
    return _git("rev-parse", f"{sha}^{{tree}}", cwd=cwd)


# ── config ───────────────────────────────────────────────────────────────────

def load_config(root: Path) -> tuple[str, str | None, str | None]:
    """(plane_url, gate_id, gate_key) from env > .zti/ files > default."""
    cfg = {}
    cfg_file = root / ".zti" / "config.json"
    if cfg_file.exists():
        try:
            cfg = json.loads(cfg_file.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            raise RuntimeError(f"unreadable {cfg_file}: {exc}")
    plane = os.environ.get("ZTI_PLANE_URL") or cfg.get("plane_url") or DEFAULT_PLANE
    gate_id = os.environ.get("ZTI_GATE_ID") or cfg.get("gate_id")
    key = os.environ.get("ZTI_GATE_KEY")
    if not key:
        key_file = root / ".zti" / "gate.key"
        if key_file.exists():
            key = key_file.read_text().strip()
    return plane, gate_id, key


# ── plane client ─────────────────────────────────────────────────────────────

class Plane:
    """Thin urllib client. Network trouble raises PlaneUnavailable; HTTP status
    is returned to the caller to interpret (fail-closed there)."""

    def __init__(self, base_url: str, key: str):
        self.base_url = base_url.rstrip("/")
        self.key = key

    def _request(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        req = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.key}"},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read() or b"{}")
            except json.JSONDecodeError:
                return exc.code, {}
        except Exception as exc:  # URLError, timeout, refused, DNS …
            raise PlaneUnavailable(str(exc))

    def get_policy(self, gate_id: str) -> tuple[int, dict]:
        return self._request("GET", f"/v1/gates/{gate_id}/policy")

    def ship_receipt(self, gate_id: str, receipt: dict, binding: dict) -> tuple[int, dict]:
        return self._request("POST", f"/v1/gates/{gate_id}/receipts",
                             {"receipt": receipt, "binding": binding})

    def verify_by_tree(self, tree: str) -> tuple[int, dict]:
        return self._request("GET", f"/v1/verify/by-tree/{tree}")


# ── zti verify ───────────────────────────────────────────────────────────────

def cmd_verify(args: argparse.Namespace) -> int:
    try:
        root = repo_root()
        tree = staged_tree(root) if args.staged else commit_tree(args.sha, root)
    except RuntimeError as exc:
        print(f"zti verify: {exc}", file=sys.stderr)
        return USAGE
    try:
        plane_url, _, key = load_config(root)
    except RuntimeError as exc:
        print(f"zti verify: {exc}", file=sys.stderr)
        return USAGE
    if not key:
        print("zti verify: no gate key (set ZTI_GATE_KEY or .zti/gate.key)", file=sys.stderr)
        return USAGE

    target = "staged content" if args.staged else f"commit {args.sha}"
    try:
        status, body = Plane(plane_url, key).verify_by_tree(tree)
    except PlaneUnavailable as exc:
        print(f"zti verify: BLOCKED — PLANE_UNAVAILABLE (plane unreachable: {exc}); "
              f"failing closed", file=sys.stderr)
        return PLANE_UNAVAILABLE
    if status == 402:
        print("zti verify: BLOCKED — PLANE_UNAVAILABLE (plane is license-locked; "
              "enforcement fails closed, never open)", file=sys.stderr)
        return PLANE_UNAVAILABLE
    if status != 200:
        print(f"zti verify: BLOCKED — PLANE_UNAVAILABLE (plane answered {status}); "
              f"failing closed", file=sys.stderr)
        return PLANE_UNAVAILABLE

    if body.get("passing"):
        print(f"zti verify: PASS — receipt {body['receipt_id']} covers {target} "
              f"(tree {tree[:12]})")
        return PASS
    if body.get("receipt_id"):
        print(f"zti verify: BLOCKED — RECEIPT_NOT_PASSED: receipt {body['receipt_id']} "
              f"for {target} has status '{body.get('status')}'. Fix the work, then "
              f"re-run `zti receipt`.", file=sys.stderr)
        return RECEIPT_NOT_PASSED
    print(f"zti verify: BLOCKED — DONE_WITHOUT_RECEIPT: no receipt for {target} "
          f"(tree {tree[:12]}). Run `zti receipt` to verify the work and mint one.",
          file=sys.stderr)
    return DONE_WITHOUT_RECEIPT


# ── zti receipt ──────────────────────────────────────────────────────────────

def _load_contract(args, plane_url: str, gate_id: str | None, key: str | None,
                   root: Path) -> dict:
    """Contract source order: --contract file > plane policy > .zti/contract.json.
    No contract → error (fail-closed: nothing to verify against means no receipt)."""
    if args.contract:
        return json.loads(Path(args.contract).read_text())
    if gate_id and key:
        try:
            status, body = Plane(plane_url, key).get_policy(gate_id)
            if status == 200 and "contract" in body:
                return body["contract"]
        except PlaneUnavailable:
            pass  # fall through to the local file — mint offline, verify later
    local = root / ".zti" / "contract.json"
    if local.exists():
        return json.loads(local.read_text())
    raise RuntimeError("no contract: give --contract, configure the plane policy, "
                       "or create .zti/contract.json")


def _run_check(check: str, cwd: Path) -> bool:
    proc = subprocess.run(check, shell=True, cwd=cwd, capture_output=True, text=True)
    verdict = "PASS" if proc.returncode == 0 else "FAIL"
    print(f"  [{verdict}] {check}")
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-10:]
        for line in tail:
            print(f"         {line}")
    return proc.returncode == 0


def cmd_receipt(args: argparse.Namespace) -> int:
    try:
        root = repo_root()
        tree = staged_tree(root)
        plane_url, gate_id, key = load_config(root)
    except RuntimeError as exc:
        print(f"zti receipt: {exc}", file=sys.stderr)
        return USAGE
    if not (gate_id and key):
        print("zti receipt: gate_id + gate key required (ZTI_GATE_ID/ZTI_GATE_KEY "
              "or .zti/config.json + .zti/gate.key)", file=sys.stderr)
        return USAGE
    try:
        spec = _load_contract(args, plane_url, gate_id, key, root)
    except (RuntimeError, OSError, json.JSONDecodeError) as exc:
        print(f"zti receipt: {exc}", file=sys.stderr)
        return USAGE

    # Unique work unit per content: suffix the lease id with the tree prefix so
    # every mint gets its own transaction_id/receipt_id (ADR-0004 §2) without
    # touching the gate library.
    contract = Contract(
        work_id=f"{spec.get('work_id', 'work')}:{tree[:12]}",
        allowed_paths=list(spec.get("allowed_paths", [])),
        forbidden_paths=list(spec.get("forbidden_paths", [])),
        required_checks=list(spec.get("required_checks", [])),
    )
    gate = Gate(contract)
    print(f"zti receipt: verifying {len(contract.required_checks)} required check(s) "
          f"for tree {tree[:12]} (independent re-run — the agent's word is not input)")
    accepted, results, reason = gate.verify_completion(
        "succeeded", lambda check: _run_check(check, root))
    receipt = gate.issue_receipt("succeeded", accepted, results, reason)

    try:
        status, body = Plane(plane_url, key).ship_receipt(
            gate_id, receipt, {"tree_hash": tree})
    except PlaneUnavailable as exc:
        print(f"zti receipt: plane unreachable ({exc}) — receipt NOT shipped; "
              f"commits will stay blocked until it is", file=sys.stderr)
        return PLANE_UNAVAILABLE
    if status != 200 or not body.get("accepted"):
        print(f"zti receipt: plane refused the receipt ({status} "
              f"{body.get('reason', '')}) — failing closed", file=sys.stderr)
        return PLANE_UNAVAILABLE

    verdict = receipt["status"]
    print(f"zti receipt: {verdict.upper()} — receipt {body['receipt_id']} bound to "
          f"tree {tree[:12]} ({'commit will pass' if verdict == 'succeeded' else 'commit stays blocked'})")
    return PASS if verdict == "succeeded" else RECEIPT_NOT_PASSED


# ── zti install-hooks ────────────────────────────────────────────────────────

def _hook_source() -> str:
    return (Path(__file__).resolve().parent / "hooks" / "pre-commit").read_text()


def cmd_install_hooks(args: argparse.Namespace) -> int:
    try:
        git_dir = Path(_git("rev-parse", "--absolute-git-dir"))
    except RuntimeError as exc:
        print(f"zti install-hooks: {exc}", file=sys.stderr)
        return USAGE
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    dest = hooks_dir / "pre-commit"
    source = _hook_source()
    if dest.exists() and dest.read_text() != source and not args.force:
        print(f"zti install-hooks: {dest} already exists and is not ours — "
              f"re-run with --force to replace it", file=sys.stderr)
        return USAGE
    dest.write_text(source)
    dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"zti install-hooks: Tier-2 receipt-gate installed at {dest}")
    return PASS


# ── entry point ──────────────────────────────────────────────────────────────

class _Parser(argparse.ArgumentParser):
    """Usage errors exit USAGE (4). argparse's default is exit 2, which is
    DONE_WITHOUT_RECEIPT in this CLI's contract — a flag typo must never read
    as "no receipt" to a hook or CI wrapper (ADR-0009 adversarial round)."""

    def error(self, message: str):
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(USAGE)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(
        prog="zti", description="ZTI client CLI — receipt-gated commits and merges")
    sub = parser.add_subparsers(dest="command", required=True)

    p_receipt = sub.add_parser(
        "receipt", help="run required checks and mint a receipt for the staged content")
    p_receipt.add_argument("--contract", help="path to a contract JSON (overrides "
                           "plane policy and .zti/contract.json)")
    p_receipt.set_defaults(func=cmd_receipt)

    p_verify = sub.add_parser(
        "verify", help="exit 0 iff a passing receipt exists for the target content")
    p_verify.add_argument("sha", nargs="?", default="HEAD",
                          help="commit to verify (default HEAD)")
    p_verify.add_argument("--staged", action="store_true",
                          help="verify the staged content instead of a commit")
    p_verify.set_defaults(func=cmd_verify)

    p_install = sub.add_parser(
        "install-hooks", help="install the pre-commit receipt-gate into .git/hooks")
    p_install.add_argument("--force", action="store_true",
                           help="replace an existing foreign pre-commit hook")
    p_install.set_defaults(func=cmd_install_hooks)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
