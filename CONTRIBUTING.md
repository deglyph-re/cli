# Contributing to deglyph

Thanks for your interest in improving deglyph. This guide covers the development
setup and the checks a change must pass.

## Development setup

Python 3.10 or newer is required.

```bash
python3 -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"       # runtime deps + pytest, ruff, mypy, black
```

## The gate

Every change must pass the same checks CI runs. Run them locally before opening
a pull request:

```bash
ruff check deglyph scripts tests     # lint
black --check deglyph scripts tests  # formatting
mypy deglyph                         # type checking (library)
python scripts/verify.py           # tone and comment-style contract
pytest                             # tests
```

`black` is the formatter and its output is the contract; run `black .` to fix
formatting. `scripts/verify.py` enforces the comment and prose style described in
`CLAUDE.md` (no marketing copy, no first-person, ASCII in user-facing docs); keep
it at zero findings.

## Conventions

- Read `CLAUDE.md` first. It documents the architecture invariants (the virtual-
  address model, function identity, thunk resolution, the disassembler arch map)
  and the behavioral rules for changes.
- Type hints on public functions; `from __future__ import annotations` at the top
  of every module.
- The detectors are heuristics. State their limits where results are reported;
  do not present a detector hit as a verified fact.
- Add a test for new analysis logic. Detector tests assert against hand-assembled
  code in `tests/test_detectors.py`; loader and disassembler tests may use a host
  binary and skip when none is present.

## Pull requests

- Keep the diff scoped to one change. Note adjacent fixes separately rather than
  bundling them.
- Update `CHANGELOG.md` under `[Unreleased]`.
- Update `CLAUDE.md` for any architectural change a future contributor would
  otherwise miss.

## Releasing

The package is `deglyph` on PyPI. Releases publish automatically from
`.github/workflows/release.yml` when a `v*` tag is pushed, using PyPI Trusted
Publishing (OIDC), so no API token is stored.

One-time setup (PyPI account owner): on PyPI, add a Trusted Publisher for the
project `deglyph` pointing at this repository, workflow `release.yml`, and
environment `pypi`. For the first ever release, register it as a pending
publisher before pushing the tag.

To cut a release:

1. Bump `__version__` in `deglyph/__init__.py` and move the `[Unreleased]` notes
   in `CHANGELOG.md` under the new version.
2. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`. The tag must match
   `deglyph.__version__` or the workflow fails the version check.
