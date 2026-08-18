# CHANGE-2026-08-17-001 — PyPI release metadata: ship the README as the long description

- **Date:** 2026-08-17
- **Type:** chore (packaging metadata only)
- **ADR reference:** ADR-0009 (registered follow-up: PyPI publication of `zti`)

## What changed
`pyproject.toml` gains `readme = "README.md"` so the PyPI project page renders
the real README instead of a blank description. No code change.

## Why
The `zti` name is being claimed on PyPI (verified available 2026-08-17; the
Actions template references PyPI availability, so squatting is a live risk).
The project page is a distribution surface and should carry the README.

## Risk
LOW — metadata only; no runtime behavior involved.

## Verified
Reproduction pass: sdist + wheel built clean; `twine check` passes both
artifacts (long description renders); wheel METADATA carries the README body
and `License: MIT`; fresh-venv install from the built wheel runs `zti --help`
and reports version 0.1.0; wheel file list unchanged apart from metadata.
