# Change Record

- **Date:** 2026-10-17
- **Type:** sync / fix — re-sync the open client gate layer with the ZTI Core
  product tree after it fixed the daemon's bare-script start and rewrote the
  shipped files' comments in plain language. Version 0.2.0 → 0.2.1. Not
  published; publishing is a separate, manual operator step
  (docs/RELEASING.md).
- **What changed (synced byte-for-byte from the product tree):**
  - `hooks/claude-code/gated.py` — every `ztipgate` import now sits inside the
    bare-script fallback, so `python3 hooks/claude-code/gated.py ...` starts
    from a checkout again with only the `ztip` runtime importable. In 0.2.0 the
    transport-policy import sat above the fallback and the daemon died with
    ModuleNotFoundError unless `zti-cli` was installed. Comments and
    docstrings rewritten in plain language.
  - `hooks/claude-code/pretooluse.py`, `zticli/__init__.py`, `zticli/main.py`,
    `zticli/hooks/pre-commit`, `ztipgate/__init__.py`, `ztipgate/gate.py`,
    `ztipgate/transport.py` — comments and docstrings only: plain language,
    no internal decision numbers, work-item handles or closed-tree file
    names. No behaviour change.
  - `zticli/templates/zti-verify.yml` — line 1 comment only, matching the
    product tree. This file still diverges by design; its 0.2.0 verifier pin
    and hash are unchanged.
- **Tests:**
  - `tests/test_gated_bare_script.py` (new, verbatim from the product tree; it
    finds the daemon in either repository layout) — starts the daemon in a
    subprocess with site-packages off and only `ztip` importable: it reaches
    argument parsing, applies the transport policy, and gets as far as
    contacting the plane. Passes here; with the 0.2.0 `gated.py` swapped in,
    3 of its 4 tests fail (the fourth pins the test's own premise).
  - The mirror's own tests (`test_hook_runtime.py`, `test_plane_url_policy.py`,
    `test_proto_conformance.py`, `test_gate_library.py`, `test_gate_client.py`,
    `test_noop_check.py`) — comments and docstrings reworded the same way:
    review labels, decision numbers and work-item handles removed, meaning
    kept. No assertion changed.
- **Docs:** README — the daemon runs from a checkout again (needs only the
  `ztip` runtime), the 0.2.0 upgrade note now lists three stricter behaviours
  and says the bare-script break is fixed in 0.2.1, suite list.
  `docs/RELEASING.md` fallback command names the 0.2.1 files.
  `PROJECT_STATUS.md` updated.
- **Upgrade effects:** none beyond 0.2.0's. Anyone who installed `zti-cli`
  only to work around the bare-script break may keep it or drop it.
- **Packaging:** the `pyproject.toml` header comment reworded the same way
  (it ships in the sdist).
- **Not changed, upstream residue:** `ztipgate/gate.py` still carries two
  internal decision numbers inside the text of the authorization envelope's
  `notes` field. That is emitted data, not a comment, and the file stays
  byte-identical to the product tree, so the change belongs there first.
- **Follow-up:** once 0.2.1 is published, move the Tier-3 template's verifier
  pin and hash to it.
- **Risk:** LOW — one import moved inside an existing fallback; everything
  else is comments, docs and the version.
- **Verified:** suite 328 passed / 4 skipped in a standalone clone, three
  consecutive runs (332 tests; the skips are schema-validation tests that need
  the ztip schema files from a sibling ztip checkout); `cmp` byte-identity of every shipped file against
  the product tree, the template excepted; a throwaway sdist build grepped
  clean of private names and internal vocabulary, then deleted.
- **Files:** `hooks/claude-code/gated.py`, `hooks/claude-code/pretooluse.py`,
  `zticli/__init__.py`, `zticli/main.py`, `zticli/hooks/pre-commit`,
  `zticli/templates/zti-verify.yml`, `ztipgate/__init__.py`,
  `ztipgate/gate.py`, `ztipgate/transport.py`, `pyproject.toml`, `README.md`,
  `docs/RELEASING.md`, `PROJECT_STATUS.md`, `tests/test_hook_runtime.py`,
  `tests/test_plane_url_policy.py`, `tests/test_proto_conformance.py`,
  `tests/test_gate_library.py`, `tests/test_gate_client.py`,
  `tests/test_noop_check.py` (mod); `tests/test_gated_bare_script.py`, this
  record (new).
