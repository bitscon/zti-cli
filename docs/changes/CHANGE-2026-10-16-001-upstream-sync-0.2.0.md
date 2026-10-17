# Change Record

- **Date:** 2026-10-16
- **Type:** sync / security — bring the open client gate layer up to the ZTI
  Core product tree. The previous full sync added the ZTIP receipt
  conformance; everything the product tree fixed since then arrives here.
  Version 0.1.0 → 0.2.0 for the user-visible changes below. Not published;
  publishing is a separate, manual operator step (docs/RELEASING.md).
- **What changed (synced byte-for-byte from the product tree):**
  - `ztipgate/transport.py` (new) — the plane transport policy: `https://`
    always; plain `http://` only to a loopback host; any other plaintext plane
    refused unless `ZTI_ALLOW_INSECURE_HTTP=1`, then a loud warning. Plaintext
    plane traffic never rides an environment proxy.
  - `zticli/main.py` — applies the transport policy before the first request
    (refusal exits 4); the plane's published policy now outranks `--contract`,
    and a divergent `--contract` is refused before any check runs; a warning
    at mint for constant-true no-op checks; the plane's "stored but not
    verified" answer (enforcement was not live across the work) is a failure,
    never SUCCEEDED, and a blocked `verify` line names the plane's reason.
  - `ztipgate/gate.py` — `is_noop_check` classifier; `Gate.record_release`,
    so an operator-approved action is recorded as performed, not blocked;
    every check result carries `check_type`.
  - `hooks/claude-code/gated.py` (from the product tree's hook daemon) —
    liveness heartbeat to the plane; requires a per-session secret from the
    plane, writes it 0600 to `.zti/gated.session` (never through a symlink),
    and authenticates every answer with an HMAC under that secret; asks the
    plane for operator approval of out-of-scope writes and releases an
    approved one exactly once; refuses an empty or unsendable enrollment
    token; sanitises every plane-chosen string before it reaches the terminal;
    applies the transport policy before registering.
  - `hooks/claude-code/pretooluse.py` — an allow is trusted only when it is
    authenticated with an HMAC under the per-session secret, over this
    request's exact bytes and fresh nonce; a missing or wrong HMAC, or an
    unreadable secret, blocks.
- **Upgrade effects (why 0.2.0):**
  1. A `--contract` file that differs from the policy the plane publishes for
     the repo is refused (`zti receipt` exits 4, nothing mints). Previously the
     local file silently won. This client-side refusal needs the plane to be
     reachable and serving the policy; offline, the local contract mints and
     the plane's own check at ingest refuses it.
  2. Plain `http://` to a non-loopback plane is refused unless
     `ZTI_ALLOW_INSECURE_HTTP=1`. This hits `zti receipt`, `zti verify` and so
     the pre-commit gate, and the hook daemon: on a plaintext LAN plane every
     commit is blocked until the override is set in the environment git runs
     under, or the plane moves to https. Previously any URL was used as given.
  3. The hook pair must be upgraded together and needs a plane that issues the
     per-session secret; an older plane makes the daemon refuse to start
     rather than run unauthenticated. The hook command should name the session
     file with an absolute `ZTI_GATE_SESSION_FILE` (README example updated).
  4. The daemon no longer starts as a bare script from a checkout with nothing
     installed: it needs `zti-cli` installed in the Python that runs it (see
     known issue below).
- **Packaging:** the sdist is now an allowlist — the two packages, the hook
  pair, the tests, README, LICENSE and pyproject. Repository housekeeping
  (agent and estate notes, CI workflows, change records) no longer ships.
  Verified with a throwaway build in a temp directory, then deleted.
- **Docs:** README — transport policy and override (including its effect on
  `zti verify` and the pre-commit gate), contract source order and supremacy
  with its offline limit, no-op warning, hook session file with an absolute
  path in the hook example, heartbeat, the honest same-user limit, an
  "Upgrading from 0.1.0" section, suite list. `docs/RELEASING.md` fallback
  command names the 0.2.0 files.
- **Tests:** ported the plane-free halves of the upstream suites —
  `test_hook_runtime.py` (now upstream's, adapted only for the hooks path),
  `test_plane_url_policy.py`, `test_noop_check.py` (the classifier half of
  upstream's contract-generator suite), `test_gate_client.py` (daemon client
  halves of upstream's enrollment and approval suites). New for this repo:
  `test_cli_client.py` (CLI against a stand-in plane), `test_approval_client.py`
  (the daemon's approval consult and contract re-pull against a stand-in
  plane), `test_gate_release.py`, `test_check_results.py`, plus heartbeat and
  session-file symlink tests. Each new guard was shown to bite by mutating it
  and watching a test fail, then reverting. Plane halves stay upstream.
- **Not changed:** `zticli/templates/zti-verify.yml` (diverges by design). Its
  verifier pin still names `zti-cli==0.1.0`; once 0.2.0 is published, the pin
  and hash need regenerating in a follow-up.
- **Known upstream issue, carried as-is (byte-identity):** `gated.py` imports
  `ztipgate.transport` before its bare-script path fallback, so the daemon
  needs `zti-cli` installed in the Python that runs it; README says so. Fix
  belongs upstream first.
- **Risk:** MEDIUM — deliberate fail-closed tightenings an existing user can
  hit (divergent contract, plaintext LAN plane blocking commits, hook pair
  needing a current plane); each has a clear message and a documented way
  through.
- **Verified:** suite 322 passed / 6 skipped (the skips need `jsonschema`),
  three consecutive runs; `cmp` byte-identity of every shipped file against
  the product tree, the template excepted.
- **Files:** `ztipgate/transport.py` (new), `ztipgate/gate.py`,
  `zticli/main.py`, `hooks/claude-code/gated.py`,
  `hooks/claude-code/pretooluse.py`, `pyproject.toml`, `README.md`,
  `docs/RELEASING.md`, `PROJECT_STATUS.md` (mod); `tests/test_hook_runtime.py`
  (mod); `tests/test_plane_url_policy.py`, `tests/test_noop_check.py`,
  `tests/test_gate_client.py`, `tests/test_cli_client.py`,
  `tests/test_approval_client.py`, `tests/test_gate_release.py`,
  `tests/test_check_results.py`, this record (new).
