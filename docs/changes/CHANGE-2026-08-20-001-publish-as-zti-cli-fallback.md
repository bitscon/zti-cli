# Change Record

- **Date:** 2026-08-20
- **Type:** chore (packaging/docs — board card `zti:pypi-fallback`)
- **ADR reference:** none
- **What changed:**
  - `pyproject.toml`: package name `zti` → `zti-cli` (operator decision
    2026-08-20). The console script (`zti`), the import packages
    (`zticli`, `ztipgate`), the version (0.1.0), and the dependency set are
    unchanged — only the `pip install` name moves.
  - `README.md`: install line is now `pip install zti-cli`, plus a one-line
    package-vs-command note. The PyPI badge stays deliberately absent until
    the listing exists (queued follow-up on the board card).
  - `docs/RELEASING.md`: rewritten to the fallback-now reality per its own
    rename-fallback section — Trusted Publishing targets project `zti-cli`
    (pending-publisher path first, since the first upload creates the
    project); the twine fallback carries a from-the-tree regenerate recipe
    and names the two artifacts; the "why `zti-cli`" section records the
    decision, keeps pypi/support#11900 open with the grant-day decision
    reserved, and retires the alias-package machinery (the real package now
    holds `zti-cli`, and `zti` stays blocked for everyone by the similarity
    check, so neither name has typosquat exposure; the grant-scenario alias
    script lives in git history).
  - `zticli/templates/zti-verify.yml`: one token — the Tier-3 template's
    install line `"zti @ git+…"` → `"zti-cli @ git+…"`. **Registered
    deviation** from the kickoff's "mirrored trees byte-untouched" gotcha:
    after the rename, pip hard-fails the old line on requested-name vs
    metadata-name mismatch, so every governed repo copying the template
    fresh would get a broken CI install step. AGENTS.md marks this exact
    file as the one by-design divergent file in the mirror (never
    upstream-synced), so mirror fidelity is not violated. All `zticli/` and
    `ztipgate/` Python files remain byte-untouched.
  - Untracked, gitignored `dist/`: wiped and rebuilt from this tree
    (build 1.5.0). The wipe is the card's own requirement — the stale
    metadata-only alias artifacts staged by the 2026-08-18 registry wave
    carried the **same filenames** the real renamed package produces
    (`zti_cli-0.1.0-*`), so a stale grab would have uploaded a 2.2 KB empty
    shell as the product. `dist/` now holds exactly two files, both real:
    `zti_cli-0.1.0-py3-none-any.whl` + `zti_cli-0.1.0.tar.gz`. Every fire
    path — the publish workflow (rebuilds from the tree itself), named-file
    twine, even a careless `dist/*` — now reaches only the real client.
- **Why:** Operator decision 2026-08-20 (board card `zti:pypi-fallback`):
  ticket pypi/support#11900 sits behind ~304 open PEP 541 requests, and
  launch wants `pip install zti-cli` to exist now. Fallback by choice, not
  refusal. This session is prep only — NOTHING was uploaded from the barn;
  the upload is the operator's (Trusted Publishing steps on the card).
- **Risk:** LOW — packaging metadata plus docs plus one template token; no
  `.py` behavior change; artifacts regenerate from the tree; everything
  reverts with the commit. The template token alters governed-repo copies
  of the Tier-3 workflow, but the line it replaces would hard-fail
  post-rename, so the change removes breakage rather than adding risk.
- **Verified:**
  - Battery green at the 167 baseline: `pytest -q` **167/167 passed** on
    this tree in a CI-recipe venv (pytest 9.1.1, jsonschema 4.26.0, and the
    real ztip 1.0.0.dev2 wheel pip-installed, mirroring CI where `pip
    install -e .` resolves ztip from PyPI). Control run on a pristine copy
    of HEAD in the same venv: 163 passed + 4 skipped, 0 failures (the 4 are
    the schema-validation layer's designed skips where the sibling spec
    checkout is not visible).
  - **Registered, pre-existing, not this change:** under the barn's system
    python the same 6 conformance tests FAIL (not skip) on any tree,
    including pristine HEAD's class: system jsonschema predates the
    `referencing` split, so `pytest.importorskip("jsonschema")` passes and
    the unguarded `from referencing import …` raises ModuleNotFoundError
    mid-test. Unreachable by this diff (metadata + docs only). Candidate
    one-line follow-up for the upstream conformance suite: guard
    `referencing` with `importorskip` too. Related environment note: the
    suite only collects at all under system python because the gate
    library's sibling-checkout walker fires during full-suite collection
    order; solo runs of the conformance module error on import there.
  - `twine check` **PASSED** on both artifacts (twine 7.0.0). Wheel inner
    contents inspected: the real client — `zticli/` + `ztipgate/` code, the
    updated template, entry point, 24.7 KB — not the 2.2 KB alias shell.
    `dist/` listing confirmed: exactly the two named files.
  - Failure-set grep clean on all four touched surfaces and repo-wide
    outside historical change records: no `zti @ git`, no `dist/zti-0.1.0`,
    no bare `pip install zti`, no bare `pip install ztip`.
  - `git status`: only the four intended files plus this record.
  - Adversarial round exempt (docs + packaging, no `.py` behavior change —
    ADR-0005 / AGENT_OS §21.4); the battery above is the universal
    closeout gate.
