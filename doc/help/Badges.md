# Badges

deglyph supports two kinds of README badge: a static one that links back to the project, and a live one that tracks the result of your latest scan.

## A static badge

Paste this anywhere to show your project is scanned with deglyph:

```markdown
[![scanned with deglyph](https://img.shields.io/badge/scanned%20with-deglyph-orange)](https://github.com/deglyph-re/cli)
```

## A live badge from a scan

`deglyph scan --format badge` emits a [shields.io endpoint](https://shields.io/badges/endpoint-badge) object: `schemaVersion`, `label`, `message`, and `color`.

```bash
deglyph scan ./app.exe --fail-on never --format badge
# { "schemaVersion": 1, "label": "deglyph", "message": "1 error, 2 warnings", "color": "red" }
```

The message and color summarize the run. A clean scan reads `clean` in green; otherwise the message counts findings worst-first and the color follows the worst level: note is blue, warning is yellow, error is red.

Publish that JSON anywhere with a stable raw URL and shields.io renders it as a badge. The flow is three steps.

### 1. Write the badge file during the scan

With [the GitHub Action](GitHub-Action.md), set the `badge` input to a path inside your repository:

```yaml
      - name: Scan with deglyph
        uses: deglyph-re/cli@v1
        with:
          path: build/app
          fail-on: never                    # record the result, do not fail the job
          badge: .github/badges/deglyph.json
```

`fail-on: never` keeps a failing gate from stopping the job before the badge is written. The Action writes the file on every run, even when the gate fails. In a pipeline that does not use the Action, the CLI writes the same file:

```bash
deglyph scan build/app --fail-on never --format badge --output .github/badges/deglyph.json
```

### 2. Publish the file

The badge needs a stable raw URL. The simplest source is the repository itself: commit the file back after the scan. A `[skip ci]` marker in the commit message stops that commit from re-triggering the workflow.

```yaml
      - name: Commit the badge
        if: github.ref == 'refs/heads/main'
        uses: stefanzweifel/git-auto-commit-action@v5
        with:
          commit_message: "chore: update deglyph badge [skip ci]"
          file_pattern: .github/badges/deglyph.json
```

This needs `permissions: contents: write` on the job. Any host that serves the JSON raw works equally well: a gist or a `gh-pages` branch are common alternatives.

### 3. Embed it in your README

Point a shields.io endpoint badge at the raw URL of the file you published, replacing `OWNER/REPO` (and the branch or path if you published elsewhere):

```markdown
[![deglyph](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/main/.github/badges/deglyph.json)](https://github.com/OWNER/REPO)
```

shields.io fetches the JSON and redraws the badge whenever your scan updates it.

## See also

- [Output Formats](Output-Formats.md): the `badge` format alongside json, sarif, and the rest.
- [The GitHub Action](GitHub-Action.md): the `badge` input and the other result surfaces.
- [Scanning Binaries](Scanning.md): producing the findings the badge summarizes.
