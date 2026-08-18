# Releasing to PyPI

How this package reaches PyPI. Publishing is a manual, human action every
time. Nothing in this repo uploads on push, tag, or merge.

## Preferred path: Trusted Publishing (no tokens)

One-time setup on PyPI, then every release is one button.

1. On pypi.org, add this repo as a trusted publisher:
   - Existing project: project page, Manage, Publishing, add GitHub publisher.
   - New project (first upload): account settings, Publishing, add a
     "pending publisher" for the project name.
   - Fields either way: owner `bitscon`, repository `zti-cli`, workflow
     `publish.yml`, environment `pypi`.
2. On GitHub: Actions, workflow "publish", Run workflow on `main`.
   The workflow builds sdist + wheel from the tree and uploads via OIDC.
   No API token exists anywhere in this setup.

## Fallback path: twine from a trusted machine

```bash
python3 -m pip install --user --upgrade twine
cd zti-cli
python3 -m twine upload dist/zti-0.1.0-py3-none-any.whl dist/zti-0.1.0.tar.gz
```

Authenticate with username `__token__` and a PyPI API token. Upload the two
files by name, never `dist/*`: the alias package below stages its artifacts
in the same directory.

## Project name

The package is `zti`. That name is under a PyPI name request
(github.com/pypi/support issue 11900; the automatic similarity check blocks
it as too close to `ztip`, which has the same owner). If the request is
refused, the package publishes under the name `zti-cli` instead; the
installed command stays `zti`. The rename is a one-line `name` change in
`pyproject.toml` plus a rebuild, done as a reviewed commit, not ad hoc.

## Alias package: claiming `zti-cli` on PyPI

When the package publishes as `zti`, the name `zti-cli` (this repo's name)
stays claimable by anyone. To keep it out of typosquatters' hands we publish
a metadata-only alias package under that name: no code, one dependency on
`zti`, a README that says the real package is `zti`. Anyone who
`pip install zti-cli` gets the real client through the dependency. This is
the standard alias-package pattern, not squatting: the name resolves to the
real project.

If the package publishes as `zti-cli` (the fallback), the real package holds
the name and no alias is needed.

Regenerate the alias artifacts any time:

```bash
mkdir -p /tmp/zti-cli-alias && cd /tmp/zti-cli-alias
cp /path/to/zti-cli/LICENSE .

cat > README.md <<'EOF'
# zti-cli (alias package)

This package name exists to protect users of the ZTI client from
typosquatting. The client installs as `zti`:

```bash
pip install zti
```

Installing `zti-cli` is safe. It contains no code and depends on `zti`,
so you get the real client either way.

- Client repository: https://github.com/bitscon/zti-cli
- Protocol (ZTIP): https://github.com/bitscon/ztip
- Site: https://zerotrustintelligence.io
EOF

cat > pyproject.toml <<'EOF'
[build-system]
requires = ["setuptools>=77", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "zti-cli"
version = "0.1.0"
description = "Alias package for zti, the open ZTI client gate layer. Installing zti-cli installs zti."
readme = "README.md"
requires-python = ">=3.10"
license = "MIT"
license-files = ["LICENSE"]
authors = [{ name = "Chad McCormack", email = "info@bitscon.net" }]
dependencies = ["zti"]

[project.urls]
Homepage = "https://zerotrustintelligence.io"
Repository = "https://github.com/bitscon/zti-cli"

[tool.setuptools]
py-modules = []
EOF

python3 -m pip install --user --upgrade build twine
python3 -m build
python3 -m twine check dist/*
python3 -m twine upload dist/zti_cli-0.1.0-py3-none-any.whl dist/zti_cli-0.1.0.tar.gz
```

The bare `zti` dependency (no version pin) means the alias never needs a
re-release when the client version moves.

Known risk: the first `zti-cli` upload may trip the same PyPI similarity
check that blocked `zti`. If it does, ask on the existing name-request
ticket to allow `zti-cli` for the same account.
