# Change Record

- **Date:** 2026-09-03
- **Type:** security / supply-chain — the open-source Tier-3 template (board
  card `zti:vac-demo`; closes the registered unpinned-git-install note).
- **ADR reference:** ADR-0004 §6, ADR-0009; the scout note in
  `zticore/docs/proof/2026-09-02-vacuity-scout-report.md`.
- **What changed:**
  - `zticli/templates/zti-verify.yml` — the install step no longer runs
    `pip install "zti-cli @ git+https://github.com/bitscon/zti-cli"` (an
    **unpinned** git ref: whatever `HEAD` happens to be at CI time). It now
    installs `zti-cli` from PyPI pinned to an exact version **and** artifact
    hash (`pip install --require-hashes --no-deps`), from outside the tree under
    test. Header comments rewritten.
- **Why:** An unpinned git install lets the verifier change under the adopter
  between runs (and offers no artifact integrity). `zti-cli` is now published on
  PyPI, so a version+hash pin is the clean supply-chain form and matches the
  delivery template — both now install the same pinned way.
- **Design decision:** pinned PyPI + `--require-hashes` over a mutable git tag;
  a hash is immutable and index-independent. Pins: `zti-cli==0.1.0`
  (sha256 3316ba91…3a17) + `ztip==1.0.0.dev2` (sha256 4767a573…1ac9).
- **Risk:** LOW — template only; stricter and fail-closed. No CLI code touched.
- **Residual (operator GitHub-side):** a PR that also edits the workflow runs
  its own copy — close with a repository ruleset / required workflow pinned
  outside the PR. (Same residual as the demo and delivery records.)
- **Verified:** YAML parses; the `run:` install command is byte-identical to
  the delivery template. End-to-end attack/fail-closed/green reproduction (a
  stub wheel defeated the old in-tree install and is now ignored; dead plane →
  blocked; genuine receipt → green; wrong hash → install refused) is recorded
  in the demo repo's `CHANGE-2026-09-03-001` against a real loopback plane.
- **Adversarial round (class M):** covered jointly with the demo/delivery
  fixes — wave 1 (two lenses) found the shared install prose stale, fixed;
  wave 2 clean. Converged at 2 waves.
- **Files:** `zticli/templates/zti-verify.yml` (mod), this record (new).
