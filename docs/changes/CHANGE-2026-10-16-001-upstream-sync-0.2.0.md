# Change Record

- **Date:** 2026-10-16
- **Type:** sync / security — bring the open client gate layer up to the ZTI
  Core product tree (last full sync: ADR-0010, 2026-08-18). Version 0.1.0 →
  0.2.0: two user-visible behaviour changes, below. Not published; publishing
  is a separate, manual operator step (docs/RELEASING.md).
- **ADR reference:** ADR-0009 (the open layer and its byte-identity rule);
  upstream ADR-0013 (enforcement liveness), ADR-0014 (approval release),
  ADR-0015 (daemon-to-hook authentication), ADR-0016 (plane transport policy);
  upstream cards `zti:vac-plane`, `zti:vac-gate`, `zti:vac-config`,
  `zti:fix-selfdisarm`, `zti:fix-approvals`, `zti:fix-hookimp`,
  `zti:fix-planeapi`.
- **What changed (all synced byte-for-byte from the product tree):**
  - `ztipgate/transport.py` (new) — the plane transport policy: `https://`
    always; plain `http://` only to a loopback host; any other plaintext plane
    refused unless `ZTI_ALLOW_INSECURE_HTTP=1`, then a loud warning. Plaintext
    plane traffic never rides an environment proxy. (ADR-0016)
  - `zticli/main.py` — applies the transport policy before the first request
    (refusal exits 4); the plane's published policy now outranks `--contract`,
    and a divergent `--contract` is refused before any check runs (vac-gate);
    mint-time warning on constant-true no-op checks (vac-gate); handles the
    plane's "stored but not verified" answer as a failure, never SUCCEEDED,
    and the blocked `verify` line names the plane's reason (ADR-0013).
  - `ztipgate/gate.py` — `is_noop_check` classifier (vac-gate);
    `Gate.record_release` so an operator-released action is recorded as
    performed, not blocked (ADR-0014); check results carry `check_type`
    (vac-plane).
  - `hooks/claude-code/gated.py` (from `core/hook/gated.py`) — liveness
    heartbeat to the plane (ADR-0013); requires a plane-issued per-session
    secret, writes it 0600 to `.zti/gated.session` and signs every allow
    (ADR-0015); escalation consult and one-time release (ADR-0014); empty or
    unsendable enrollment token refused client-side (vac-config); every
    plane-chosen string sanitised before it reaches the terminal; transport
    policy applied before registering (ADR-0016).
  - `hooks/claude-code/pretooluse.py` (from `core/hook/pretooluse.py`) — an
    allow is trusted only with a valid signature over this request's fresh
    nonce; a missing or wrong signature, or an unreadable secret, blocks
    (ADR-0015).
- **User-visible behaviour changes (why 0.2.0):**
  1. A `--contract` file that differs from the policy the plane publishes for
     the repo is refused (`zti receipt` exits 4, nothing mints). Previously the
     local file silently won.
  2. Plain `http://` to a non-loopback plane is refused unless
     `ZTI_ALLOW_INSECURE_HTTP=1`. Previously any URL was used as given.
  3. The hook pair must be upgraded together and needs a plane that issues
     the hook session secret (ADR-0015); an older plane makes the daemon
     refuse to start rather than run unauthenticated.
- **Docs:** README — transport policy and override, contract source order and
  supremacy, no-op warning, hook session file, heartbeat, the honest
  same-user limit, suite list. `docs/RELEASING.md` fallback command names the
  0.2.0 files.
- **Tests:** ported the plane-free halves of the upstream suites —
  `test_hook_runtime.py` (now upstream's, adapted only for the hooks path),
  `test_plane_url_policy.py`, `test_noop_check.py` (classifier half of
  upstream `test_contractgen_noop.py`), `test_gate_client.py` (daemon client
  halves of upstream enrollment and approval suites, plus a heartbeat test).
  New for this repo: `test_cli_client.py` (CLI against a stand-in plane:
  supremacy, no-op lint, unverified outcome, transport refusal) and
  `test_gate_release.py`. Plane halves stay upstream.
- **Not changed:** `zticli/templates/zti-verify.yml` (diverges by design). Its
  verifier pin still names `zti-cli==0.1.0`; once 0.2.0 is published, the pin
  and hash need regenerating in a follow-up.
- **Known upstream issue, carried as-is (byte-identity):** `gated.py` imports
  `ztipgate.transport` before its bare-script path fallback, so the daemon
  needs `zti-cli` installed in the Python that runs it; README says so. Fix
  belongs upstream first.
- **Risk:** MEDIUM — two deliberate fail-closed tightenings an existing user
  can hit (divergent contract, plaintext LAN plane); both have a clear message
  and a documented way through.
- **Verified:** suite 290 passed / 6 skipped (jsonschema-gated conformance),
  three consecutive runs; `cmp` byte-identity of every shipped file against
  the product tree, the template excepted.
- **Files:** `ztipgate/transport.py` (new), `ztipgate/gate.py`,
  `zticli/main.py`, `hooks/claude-code/gated.py`,
  `hooks/claude-code/pretooluse.py`, `pyproject.toml`, `README.md`,
  `docs/RELEASING.md`, `PROJECT_STATUS.md` (mod); `tests/test_hook_runtime.py`
  (mod); `tests/test_plane_url_policy.py`, `tests/test_noop_check.py`,
  `tests/test_gate_client.py`, `tests/test_cli_client.py`,
  `tests/test_gate_release.py`, this record (new).
