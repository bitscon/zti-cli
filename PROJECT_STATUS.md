# PROJECT STATUS: zti-cli

- **2026-08-17**: Initial public release. The ZTI client gate layer,
  open-sourced from the ZTI Core product tree under ADR-0009 (MIT). Ships the
  `zti` CLI (`receipt` / `verify` / `install-hooks`), the `ztipgate` gate
  library, the Tier-2 pre-commit receipt gate, the Tier-3 GitHub Actions
  template, and the Claude Code Tier-1 hook pair. Test suites: gate library
  and hook runtime. CI runs both on push and PR.
- **2026-10-16**: 0.2.0 prepared (not yet published). Synced the client layer
  to the ZTI Core product tree: plane transport policy (plaintext only to
  loopback, `ZTI_ALLOW_INSECURE_HTTP` override), published-policy supremacy
  over `--contract`, no-op check warning, enforcement-liveness heartbeat and
  the "stored but not verified" outcome, daemon answers to the hook
  authenticated with an HMAC under a per-session secret. Suites
  now also cover the CLI, the daemon client and the transport policy. Open:
  publish 0.2.0, then regenerate the Tier-3 template's verifier pin.
  See `docs/changes/CHANGE-2026-10-16-001-upstream-sync-0.2.0.md`.
- **2026-10-17**: 0.2.1 prepared (not yet published; 0.2.0 is on PyPI). The
  hook daemon starts as a bare script from a checkout again, and the shipped
  files' comments are rewritten in plain language. Re-synced byte-for-byte
  with the ZTI Core product tree; the mirror's own tests now carry plain
  wording too. Open: publish 0.2.1, then move the Tier-3 template's verifier
  pin to it. See `docs/changes/CHANGE-2026-10-17-001-upstream-sync-0.2.1.md`.
