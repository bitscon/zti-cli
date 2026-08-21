# Releasing to PyPI

How this package reaches PyPI. Publishing is a manual, human action every
time. Nothing in this repo uploads on push, tag, or merge.

The package publishes as `zti-cli`. The installed command stays `zti`.

## Preferred path: Trusted Publishing (no tokens)

One-time setup on PyPI, then every release is one button.

1. On pypi.org, add this repo as a trusted publisher for project `zti-cli`:
   - First upload (project does not exist on PyPI yet): account settings,
     Publishing, add a "pending publisher" for project name `zti-cli`.
   - Every later release (project exists): project page, Manage, Publishing,
     add GitHub publisher — already done if the pending publisher converted.
   - Fields either way: owner `bitscon`, repository `zti-cli`, workflow
     `publish.yml`, environment `pypi`.
2. On GitHub: Actions, workflow "publish", Run workflow on `main`.
   The workflow builds sdist + wheel from the tree and uploads via OIDC.
   No API token exists anywhere in this setup.

## Fallback path: twine from a trusted machine

Regenerate the artifacts from the tree, then upload the two files by name:

```bash
cd zti-cli
rm -rf dist/
python3 -m build
python3 -m twine check dist/*
python3 -m twine upload dist/zti_cli-0.1.0-py3-none-any.whl dist/zti_cli-0.1.0.tar.gz
```

If `build` or `twine` is missing:
`python3 -m pip install --user --upgrade build twine`.
Authenticate with username `__token__` and a PyPI API token. Naming the two
files keeps a stale or foreign file in `dist/` from ever riding along.

## Project name: why `zti-cli`

The name `zti` is blocked by PyPI's automatic similarity check (too close to
`ztip`, same owner) and sits under an open name request:
github.com/pypi/support issue 11900. On 2026-08-20, with that queue hundreds
of requests deep, the call was made to stop waiting and publish as `zti-cli`.
The installed command is `zti` either way; only the `pip install` name
differs.

- Issue 11900 stays open on purpose. If the grant ever lands, whether `zti`
  becomes the canonical package name (with `zti-cli` republished as an alias)
  is a decision for that day. Nothing here forecloses it.
- No alias package is needed under this name. The real package holds
  `zti-cli`, and `zti` itself stays blocked for everyone by the same
  similarity check, so neither name is exposed to typosquatting. (The
  earlier plan to ship a metadata-only `zti-cli` alias applied only to the
  grant scenario; see git history for that machinery.)

Known risk: the first `zti-cli` upload may trip the same similarity check
that blocked `zti`. If it does, nothing is lost — comment on issue 11900
asking to allow `zti-cli` for the same account, and the queue position
already exists.
