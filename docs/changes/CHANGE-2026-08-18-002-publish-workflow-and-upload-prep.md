# Change Record

- **Date:** 2026-08-18
- **Type:** chore (packaging/CI — ZTI UX wave 3, board card `zti:ux-w3`)
- **ADR reference:** none
- **What changed:**
  - New `.github/workflows/publish.yml`: manual-dispatch-only PyPI publish via
    Trusted Publishing (OIDC, `pypa/gh-action-pypi-publish`, environment
    `pypi`, `id-token: write`). Inert until the operator registers this repo +
    workflow as a trusted publisher on PyPI; never fires on push or tag. The
    same workflow serves either project name (`zti` on the name grant, or the
    `zti-cli` fallback) because the repo-to-project binding lives on PyPI.
  - New `docs/RELEASING.md`: the release runbook — Trusted Publishing setup,
    twine fallback, the name-request/fallback story, and the alias-package
    ("claim `zti-cli`") rationale with a self-contained regeneration script.
  - No tracked source changed. `zticli/` and `ztipgate/` byte-untouched.
  - Untracked build output (gitignored `dist/`): `zti-0.1.0` sdist + wheel
    rebuilt from today's tree so the PyPI long description is the current
    README (5c28eba: badge row + the aligned availability story), replacing
    the 2026-08-17 artifacts that predated it; plus a metadata-only
    `zti_cli-0.1.0` alias package (no code, depends on `zti`, README says the
    real package is `zti`) staged for the typosquat-guard upload in the
    granted-name scenario.
- **Why:** Registry wave (`zti:ux-w3`): uploads are irreversible and stay the
  operator's, so this session preps artifacts + the trusted-publishing path
  and lands ready-to-fire commands on the `zti:ux-pypi` board card. Nothing
  was uploaded from the barn.
- **Risk:** LOW — one inert manual-dispatch workflow file; no source, no
  mirrored trees, no behavior change.
- **Verified:** suite green after the change — `pytest -q` 167/167 passed
  (AGENTS.md rule; W2 baseline was 161 passed + 6 env skips, all 167 pass in
  this environment); `twine check` PASSED on all four artifacts (client sdist
  + wheel, alias sdist + wheel; twine 7.0.0); client sdist PKG-INFO inspected
  — long description is the current README (CI + MIT badges, "complete and in
  early access" availability paragraph); `git status` clean apart from the new
  workflow + this record (dist/ is gitignored); failure-set grep clean (no
  dollar figures, no "ZTI Foundation", no ZTAP outside `ztap_version`, no bare
  `pip install ztip`). Adversarial round exempt (docs+packaging wave, no
  .py/pyproject behavior change, ADR-0005 / AGENT_OS §21.4); this battery is
  the universal closeout gate.
