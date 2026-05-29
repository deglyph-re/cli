# Secret Detection

The secret detector scans the binary's string table for embedded credentials. It
runs by default in `deglyph scan` and combines two always-on layers with one
opt-in layer.

## Provider token formats

A catalog of high-precision regexes matches well-known token shapes. Each pattern
is specific enough to fire on a real credential rather than incidental text:

| Rule | Matches |
| --- | --- |
| `secret/private-key` | PEM private key blocks |
| `secret/aws-access-key` | AWS access key ids (`AKIA` / `ASIA`) |
| `secret/github-token` | GitHub tokens (`ghp_`, `gho_`, ...) |
| `secret/github-pat` | GitHub fine-grained PATs (`github_pat_`) |
| `secret/gitlab-pat` | GitLab PATs (`glpat-`) |
| `secret/slack-token` | Slack tokens (`xox...`) |
| `secret/slack-webhook` | Slack incoming webhook URLs |
| `secret/google-api-key` | Google API keys (`AIza...`) |
| `secret/stripe-key` | Stripe live secret keys (`sk_live_`, `rk_live_`) |
| `secret/npm-token` | npm access tokens (`npm_`) |
| `secret/sendgrid-key` | SendGrid API keys (`SG.`) |
| `secret/openai-key` | OpenAI keys (`sk-`, `sk-proj-`) |
| `secret/telegram-token` | Telegram bot tokens |
| `secret/jwt` | JSON Web Tokens |

## The credential rule

Beyond the provider formats, `secret/credential-keyword` is a generic rule for
labeled secrets. It fires only when there is evidence of an actual **value**, not
merely a keyword:

- an **assignment** of a non-trivial value, such as `password=hunter2hunter2` or
  `client_secret: aB3xK9zQ2mLp7Rt5Vw`, or
- a keyword embedded in a single **value-shaped token**, such as
  `S3cr3t-demo-API-key-do-not-ship`.

A bare keyword on its own is not a finding. A struct field name, an environment
variable name like `AWS_ACCESS_KEY_ID`, a format placeholder like
`client_secret=%s`, a path, a `SCREAMING_CASE` constant, and a mangled C++ symbol
all carry credential words but no value, so none of them register. This keeps the
rule quiet on real binaries, where bare keyword matching produces overwhelming
noise.

## The entropy catch-all

An opt-in entropy rule (`secret/high-entropy`, enabled with `--entropy`) flags
long, opaque, high-entropy tokens that no specific pattern caught. It is off by
default because on native binaries it fires on build paths and mangled symbol
names. Reach for it when you suspect a non-standard secret format.

## Reporting a hit

A secret finding is a candidate, not a confirmed leak. The detector matched a
pattern; it did not verify the value is live or sensitive. Say "candidate
secret", and confirm before acting. If a hit is a known false positive, suppress
it; see [Suppressing Findings](Suppressing-Findings.md).

## See also

- [Scanning Binaries](Scanning.md): the scanner overview.
- [Suppressing Findings](Suppressing-Findings.md): silencing a rule or a finding.
- [Heuristics, Not Proofs](Heuristics.md): how much a hit is worth.
