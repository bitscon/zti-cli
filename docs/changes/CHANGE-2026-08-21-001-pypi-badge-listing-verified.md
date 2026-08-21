# Change Record

- **Date:** 2026-08-21
- **Type:** docs (README badge — board card `zti:pypi-fallback`, subtask 3)
- **ADR reference:** none
- **What changed:**
  - `README.md`: PyPI version badge added to the badge row
    (`img.shields.io/pypi/v/zti-cli` → pypi.org/project/zti-cli). It was
    deliberately absent until the listing existed; the operator fired the
    first upload via Trusted Publishing on 2026-08-21 and it does now.
- **Why:** The queued follow-up on the fallback card: verify the listing
  after the operator's fire, then add the badge. Publication itself was the
  operator's action (Trusted Publishing, workflow `publish.yml`); nothing
  was ever uploaded from the barn.
- **Risk:** LOW — one README line; no code, no packaging metadata.
- **Verified (the listing, before the badge):**
  - PyPI JSON API: project `zti-cli`, version 0.1.0, both artifacts present,
    uploaded 2026-08-21T23:45Z; description renders and contains
    `pip install zti-cli`; the name-similarity check did NOT block (the
    card's known risk did not materialize; subtask 4 moot).
  - Customer-path reproduction: fresh venv `pip install zti-cli` resolved
    zti-cli 0.1.0 + ztip 1.0.0.dev2 (pre-release dependency specifier
    worked without `--pre`); `zti --help` exit 0.
  - Artifact integrity: the published wheel is **byte-identical** to the
    barn-staged wheel (outer sha256 `3316ba91…` equal; all 12 inner files
    hash-equal). The published sdist differs from the staged one by exactly
    one file — this repo's CHANGE-2026-08-20-001 record, present because CI
    built from `789444d` (which includes it) while the staged sdist was
    built pre-commit; all 27 other files common. Expected, benign.
- **Verified (this change):** badge URL and project URL both HTTP 200;
  battery green after the edit (universal closeout gate; docs-only change,
  adversarial round exempt per ADR-0005 / AGENT_OS §21.4); failure-set grep
  clean on the touched README.
