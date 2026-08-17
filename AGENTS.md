# AGENTS

Rules for any coding agent working in this repository.

## Scope

- This repo is the open MIT client gate layer of ZTI: the `zti` CLI
  (`zticli/`), the gate library (`ztipgate/`), the Tier-2 pre-commit receipt
  gate, the Tier-3 CI check template, and the Claude Code Tier-1 hook pair
  (`hooks/claude-code/`). Nothing else belongs here.
- The ZTI Core control plane is a separate, closed product. Never add plane
  code, license tooling, keys, or credentials to this repo.

## Rules

- Every `zticli/` and `ztipgate/` source file shipped here is byte-identical to
  its ZTI Core product-tree counterpart (upstream-only extras, such as the gate
  library's internal docs and demo, do not ship), with ONE exception:
  `zticli/templates/zti-verify.yml` diverges by design
  (this repo's copy installs the CLI from this public repo; the product tree's
  copy installs a vendored wheel). Never sync over it. Behavior changes land
  upstream first, then sync here.
- Run the suite before any commit: `pip install -e . pytest` then `pytest -q`.
- No secrets, tokens, private hostnames, or internal paths in any file.
- End every session with a list of all files created or modified.
