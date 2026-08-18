# zti: the Verified Done gate for AI coding agents

[![CI](https://img.shields.io/github/actions/workflow/status/bitscon/zti-cli/ci.yml?branch=main&label=ci)](https://github.com/bitscon/zti-cli/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-f97316)](LICENSE)

Your agent says the work is done. `zti` proves it. It re-runs the required
checks itself, seals the result in a hash-chained [ZTIP](https://github.com/bitscon/ztip)
receipt bound to the exact git tree, and blocks the commit or merge when no
passing receipt exists. The agent's claim is never the input.

This repo is the open client layer of [ZTI](https://zerotrustintelligence.io):
the CLI, the gate library, and the enforcement hooks. MIT licensed. It reports
to a ZTI Core control plane, which stores receipts, verifies them at commit and
merge time, and gives you the fleet dashboard and audit trail.

**See it work in public:** [bitscon/zti-verified-done-demo](https://github.com/bitscon/zti-verified-done-demo).
PR #2 is a `--no-verify` bypass caught red in CI and left open on purpose.

## Three enforcement tiers, one binding model

A receipt binds to `git write-tree`: the content address of exactly what would
be committed. Identical at pre-commit and in CI, so nothing can drift between
what was verified and what ships.

| Tier | Where | What it does |
|---|---|---|
| 1. Runtime hook | Claude Code `PreToolUse` | Blocks out-of-contract writes and irreversible commands live during the session. Bash is screened for irreversible patterns and forbidden-path tokens; full Bash scoping is on the roadmap |
| 2. Pre-commit gate | `.git/hooks/pre-commit` | Blocks the commit unless a passing receipt covers the staged tree |
| 3. CI required check | GitHub Actions | Catches `--no-verify` at the merge, on the PR head SHA |

Fail-closed on every path: no receipt, a failed receipt, an unreachable plane,
and a license-locked plane all block. Agent-neutral: it governs any committer,
human or agent, by git content alone.

## Install

```bash
pip install "zti @ git+https://github.com/bitscon/zti-cli"
```

Point it at your plane with `.zti/config.json` in the repo
(`{"plane_url": "...", "gate_id": "..."}`) plus the gate key in
`.zti/gate.key`, or use the `ZTI_PLANE_URL` / `ZTI_GATE_ID` / `ZTI_GATE_KEY`
environment variables. Keep `.zti/gate.key` out of version control.

## Use

```bash
zti receipt         # re-run the contract's required checks, mint a receipt,
                    # ship it to the plane bound to the staged tree
zti verify --staged # exit 0 only if a passing receipt covers the staged content
zti verify <sha>    # same check for a commit (what CI runs)
zti install-hooks   # drop the Tier-2 pre-commit gate into .git/hooks
```

Exit codes: `0` pass · `1` receipt exists but not passing · `2` no receipt ·
`3` plane unavailable (fail-closed) · `4` usage error.

A contract is a small JSON document. `zti receipt` re-runs its
`required_checks` itself and refuses a passing receipt when they fail:

```json
{"work_id": "billing-fix", "allowed_paths": ["src/**"],
 "forbidden_paths": ["db/**"], "required_checks": ["pytest -q"]}
```

For Tier 3, copy `zticli/templates/zti-verify.yml` into the governed repo's
`.github/workflows/` and mark `zti-verify` as a required status check in
branch protection.

## The Claude Code hook (Tier 1)

`hooks/claude-code/` holds the pair:

- `gated.py` runs beside the repo, loads its contract from the plane, and
  enforces it with the same gate library that mints receipts. If the plane
  goes down it keeps enforcing on the cached contract. The plane is never in
  the evaluation path.
- `pretooluse.py` is the Claude Code `PreToolUse` hook. It asks the local
  daemon and blocks on anything but an explicit allow. A dead gate can never
  silently allow.

Start the daemon beside the repo first. At startup it registers with your
plane (set `ZTI_ENROLL_TOKEN` first if the plane requires an enrollment
token) and loads the contract it will enforce:

```bash
python3 hooks/claude-code/gated.py --repo-root . --repo-name myrepo
```

Then wire the hook in the governed repo's `.claude/settings.json`:

```json
{"hooks": {"PreToolUse": [{"matcher": "Write|Edit|NotebookEdit|Bash",
  "hooks": [{"type": "command", "command": "python3 /path/to/pretooluse.py"}]}]}}
```

## What you need to run it

A ZTI Core plane. ZTI Core is complete and in early access. Every install
includes a free 30-day trial with full functionality, and individual use is
free on the honor system. Organizations license it per year; pricing is
announced at launch. Start at
[licensing@zerotrustintelligence.io](mailto:licensing@zerotrustintelligence.io)
or [zerotrustintelligence.io](https://zerotrustintelligence.io).

The protocol underneath is open: [ZTIP](https://github.com/bitscon/ztip),
MIT, with its own spec, schemas, and reference runtime.

## Development

```bash
pip install -e . pytest
pytest -q
```

Two suites ship here: the gate library and the runtime hook. The full product
battery runs in the ZTI Core tree.

## License

MIT. Copyright (c) 2026 Chad McCormack.
