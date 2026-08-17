# PROJECT STATUS: zti-cli

- **2026-08-17**: Initial public release. The ZTI client gate layer,
  open-sourced from the ZTI Core product tree under ADR-0009 (MIT). Ships the
  `zti` CLI (`receipt` / `verify` / `install-hooks`), the `ztipgate` gate
  library, the Tier-2 pre-commit receipt gate, the Tier-3 GitHub Actions
  template, and the Claude Code Tier-1 hook pair. Test suites: gate library
  and hook runtime. CI runs both on push and PR.
