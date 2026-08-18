# CHANGE-2026-08-17-002 — SPDX license expression for PyPI acceptance

- **Date:** 2026-08-17
- **Type:** chore (packaging metadata only)
- **ADR reference:** ADR-0009 (registered follow-up: PyPI publication of `zti`)

## What changed
`pyproject.toml` license moves from the classic `{ text = "MIT" }` table to the
PEP 639 SPDX string `license = "MIT"`.

## Why
The first upload attempt returned HTTP 400 from PyPI. The built wheel carried
the legacy `License: MIT` field combined with `License-File:` under
`Metadata-Version: 2.5` — a combination current PyPI rejects. The SPDX string
makes hatchling emit a clean `License-Expression: MIT`, the accepted modern
form (and the form the ecosystem-listings prep already recommended).

## Risk
LOW — metadata only; no runtime behavior involved.

## Verified
Rebuilt sdist + wheel; `twine check` passes; wheel METADATA now carries
`License-Expression: MIT` with no legacy `License:` field; fresh-venv install
from the rebuilt wheel runs `zti --help`.
