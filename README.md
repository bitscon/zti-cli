# zti: the Verified Done gate for AI coding agents

[![CI](https://img.shields.io/github/actions/workflow/status/bitscon/zti-cli/ci.yml?branch=main&label=ci)](https://github.com/bitscon/zti-cli/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/zti-cli?label=pypi)](https://pypi.org/project/zti-cli/)
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
pip install zti-cli
```

The package is `zti-cli`; the command it installs is `zti`.

Point it at your plane with `.zti/config.json` in the repo
(`{"plane_url": "...", "gate_id": "..."}`) plus the gate key in
`.zti/gate.key`, or use the `ZTI_PLANE_URL` / `ZTI_GATE_ID` / `ZTI_GATE_KEY`
environment variables. Keep `.zti/gate.key` out of version control.

The plane URL must be `https://`, or plain `http://` to a loopback host
(`localhost`, `127.0.0.0/8`, `::1`; the default is `http://127.0.0.1:8100`).
Plain `http://` to any other host is refused before the first request, because
that channel carries the gate key, contracts, decisions and the hook session
secret. If you must run a plaintext plane on a LAN, set
`ZTI_ALLOW_INSECURE_HTTP=1` to accept that risk explicitly; the client then
proceeds with a warning on every start. Plaintext plane traffic never goes
through an environment proxy.

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

Where the contract comes from, in order: the policy your plane publishes for
the repo, then `--contract <file>`, then `.zti/contract.json`. The published
policy is the authority. A `--contract` file that differs from it is refused
and nothing mints, so the governed party cannot swap the operator's checks
for weaker ones; a file that restates the policy exactly is accepted. With no
published policy, the local contract is used. `zti receipt` also warns when a
required check is a constant-true no-op (`true`, `echo ok`, `pytest || true`):
it still mints, but says the check verifies nothing.

For Tier 3, copy `zticli/templates/zti-verify.yml` into the governed repo's
`.github/workflows/` and mark `zti-verify` as a required status check in
branch protection.

## The Claude Code hook (Tier 1)

`hooks/claude-code/` holds the pair:

- `gated.py` runs beside the repo, loads its contract from the plane, and
  enforces it with the same gate library that mints receipts. If the plane
  goes down it keeps enforcing on the cached contract. The plane is never in
  the evaluation path.
  While it runs it sends the plane a heartbeat, so a gate that is switched
  off reads as dark on the plane instead of silently looking healthy.
- `pretooluse.py` is the Claude Code `PreToolUse` hook. It asks the local
  daemon and blocks on anything but an explicit allow. A dead gate can never
  silently allow. An allow counts only when the daemon signs it with this
  session's secret, so a process squatting the daemon's port cannot answer
  "allow"; an unsigned or wrongly signed allow, or a secret the hook cannot
  read, blocks.

Start the daemon beside the repo first, with the Python that has `zti-cli`
installed (the daemon imports its gate library). At startup it registers with
your plane (set `ZTI_ENROLL_TOKEN` first if the plane requires an enrollment
token), writes the session secret to `.zti/gated.session` (mode 0600; set
`ZTI_GATE_SESSION_FILE` to put it elsewhere, and keep it out of version
control), and loads the contract it will enforce:

```bash
python3 hooks/claude-code/gated.py --repo-root . --repo-name myrepo
```

Run the hook from the governed repo's root so it finds the session file, or
export the same `ZTI_GATE_SESSION_FILE` to both.

The honest limit: the hook runs as the agent's own user, so an agent that
reads its own session file can still forge a signed allow. Daemon signing
raises the bar against an impostor that has not read it; it does not stop one
that has. Only signing off the machine closes that, and the plane's liveness
record is what makes a disarm visible.

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

The suites here cover the gate library, the runtime hook and gate daemon
client, the `zti` CLI (against a stand-in plane), the plane transport policy,
and ZTIP conformance. The plane halves of those behaviours, and the full
product battery, run in the ZTI Core tree.

## License

MIT. Copyright (c) 2026 Chad McCormack.
