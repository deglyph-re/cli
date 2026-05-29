# Baseline Diff

The baseline diff reports what changed between the binary you are scanning and a
prior build. It is how you catch drift: an import or a function that appeared, or
one that disappeared, since a known-good reference. It runs when you pass a
`--baseline` build.

```bash
deglyph scan ./build/app.exe --baseline ./reference/app.exe
```

## What it reports

| Rule | Meaning | Level |
| --- | --- | --- |
| `diff/added-import` | An imported API present here but not in the baseline | warning |
| `diff/added-function` | A function present here but not in the baseline | note |
| `diff/removed-function` | A function in the baseline but not here | note |

A newly added import is `warning` because a new external capability is the most
review-worthy kind of drift: a build that suddenly imports a network or
process-execution API deserves attention. Added and removed functions are `note`.

## How it compares

The diff compares the two binaries by symbol and import **name**. It is a set
difference: names present on one side and not the other. It does not diff
instruction bytes or detect a function whose body changed but whose name stayed
the same, so it surfaces structural drift rather than behavioral drift.

## Using it in CI

Point `--baseline` at the last released build, or the previous commit's artifact,
and a pull request that adds an unexpected import or a surprising set of functions
shows up in the scan. Pair it with a committed
[`.deglyphignore`](Suppressing-Findings.md) so expected, reviewed additions do
not keep failing the gate.

## See also

- [Scanning Binaries](Scanning.md): the scanner and the `--fail-on` gate.
- [Import Capabilities](Import-Capabilities.md): what an added import can mean.
- [Suppressing Findings](Suppressing-Findings.md): accepting expected drift.
