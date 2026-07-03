---
name: release
description: Cut a deglyph release (version bump, changelog, tag; PyPI publishes via Trusted Publishing on tag push). Use when the user asks to release, publish, or tag a version.
---

The release procedure is CONTRIBUTING.md, "Releasing"; this is its
step-by-step form. Everything here changes public state, so confirm the
version number with the user before touching anything, and do not push
without an explicit go-ahead.

1. Preflight: working tree clean on `main`, gate green (run the `/gate`
   skill), and `CHANGELOG.md` has content under `[Unreleased]`.
2. Pick the version by semver against the `[Unreleased]` notes: breaking
   shape or CLI change is major, features minor, fixes patch.
3. Bump `__version__` in `deglyph/__init__.py`.
4. In `CHANGELOG.md`: move the `[Unreleased]` notes under
   `## [X.Y.Z] - <date>`, leave an empty `[Unreleased]`, and update the
   compare links at the bottom.
5. Update every pinned `deglyph-re/cli@vX.Y.Z` action reference: README.md,
   AGENTS.md, `examples/deglyph-scan.yml`, `doc/help/GitHub-Action.md`, and
   `doc/help/Badges.md` (grep for `deglyph-re/cli@` to catch new sites).
6. Commit (`release: X.Y.Z <one-line theme>`), then tag and push:
   `git tag vX.Y.Z && git push origin main vX.Y.Z`.
7. The tag triggers `.github/workflows/release.yml`: it verifies the tag
   matches `deglyph.__version__` (a mismatch fails the run), builds, and
   publishes to PyPI via Trusted Publishing (OIDC, no stored token).
   Watch the run; on a version-check failure, fix the mismatch and re-tag.
