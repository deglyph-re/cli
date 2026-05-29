# Scan Rules Catalog

Every `deglyph scan` finding carries a rule id and a default severity level. This
page lists the full catalog. The level determines whether a finding trips the
`--fail-on` gate, which defaults to `warning`. Any rule can be silenced; see
[Suppressing Findings](Suppressing-Findings.md).

## Levels

- **error**: a high-confidence, high-impact finding (an embedded secret, a known
  CVE).
- **warning**: review-worthy by default; trips the default gate.
- **note**: informational; reported but does not fail the default gate.

## Secrets

See [Secret Detection](Secret-Detection.md).

| Rule | Level |
| --- | --- |
| `secret/private-key` | error |
| `secret/aws-access-key` | error |
| `secret/github-token` | error |
| `secret/github-pat` | error |
| `secret/gitlab-pat` | error |
| `secret/slack-token` | error |
| `secret/slack-webhook` | warning |
| `secret/google-api-key` | error |
| `secret/stripe-key` | error |
| `secret/npm-token` | error |
| `secret/sendgrid-key` | error |
| `secret/openai-key` | error |
| `secret/telegram-token` | warning |
| `secret/jwt` | warning |
| `secret/credential-keyword` | warning |
| `secret/high-entropy` | note |

## Imports

See [Import Capabilities](Import-Capabilities.md).

| Rule | Level |
| --- | --- |
| `import/process-exec` | warning |
| `import/code-injection` | warning |
| `import/memory-protect` | note |
| `import/dynamic-load` | note |
| `import/network` | note |
| `import/anti-debug` | note |

## Hardening

See [Hardening Posture](Hardening.md).

| Rule | Level |
| --- | --- |
| `harden/no-aslr` | warning |
| `harden/no-dep` | warning |
| `harden/no-stack-canary` | warning |
| `harden/no-pie` | warning |
| `harden/no-relro` | warning |
| `harden/partial-relro` | note |
| `harden/no-cfg` | note |
| `harden/no-high-entropy-va` | note |
| `harden/no-safeseh` | note |
| `harden/no-fortify` | note |
| `harden/no-bti-pac` | note |
| `harden/unsigned` | note |

## Libraries and CVEs

See [Library Fingerprinting](Library-Fingerprinting.md) and
[CVE Scanning](CVE-Scanning.md).

| Rule | Level |
| --- | --- |
| `lib/detected` | note |
| `cve/known` | error |

## Baseline drift

See [Baseline Diff](Baseline-Diff.md).

| Rule | Level |
| --- | --- |
| `diff/added-import` | warning |
| `diff/added-function` | note |
| `diff/removed-function` | note |

## See also

- [Scanning Binaries](Scanning.md): how rules are produced and gated.
- [Suppressing Findings](Suppressing-Findings.md): silencing a rule or category.
- [Output Formats](Output-Formats.md): rule ids in SARIF and JSON.
