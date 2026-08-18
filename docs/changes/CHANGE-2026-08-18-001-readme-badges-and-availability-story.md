# Change Record

- **Date:** 2026-08-18
- **Type:** docs (README only — ZTI UX wave 2, board card `zti:ux-w2`)
- **ADR reference:** none
- **What changed:**
  - Badge row added under the title: CI (shields.io workflow-status for
    `ci.yml`, branch `main`, linking the Actions page) and License: MIT in
    brand orange `f97316` (linking `LICENSE`). No PyPI badge on purpose: the
    `zti` name is not granted yet (PyPI name request open); a PyPI badge
    would render broken.
  - "What you need to run it" availability paragraph aligned to the one
    story the site now tells (staged by ux-w1): ZTI Core complete and in
    early access; free 30-day trial with full functionality; individual use
    free on the honor system; organizations license per year; pricing
    announced at launch; contact licensing@zerotrustintelligence.io. The
    plain-terms licensing statement this README already carried (BRAND.md
    §1/§7 exception for the open client repo) is aligned, not stripped; no
    dollar figures.
- **Why:** The 2026-08-18 UX audit's repo wave: the public client README must
  match the site story — same availability sentences, CI surfaced.
- **Risk:** LOW — README-only; the mirrored `zticli/` + `ztipgate/` source
  trees are byte-untouched (verified by git diff scope: README.md + this
  record only).
- **Verified:** full suite after the edit: 167 collected — 161 passed,
  6 skipped (environment-dependent skips), 0 failed. Failure-set grep clean
  (no dollar figures, no "ZTI Foundation", no ZTAP, no bare
  `pip install ztip`, no stale "in build"/"coming"). Both badge URLs HTTP
  200 (CI badge renders "passing"); raw README render-check after push.
  Adversarial round exempt (docs-only wave, ADR-0005 / AGENT_OS §21.4); this
  battery is the universal closeout gate.
