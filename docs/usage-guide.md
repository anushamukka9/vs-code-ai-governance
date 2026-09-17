# Usage Guide — AI Governance Guard

## What gets flagged

### PII (`pii.*`)
| Rule | Severity | Detects |
|---|---|---|
| `pii.email` | warning | Email addresses |
| `pii.ssn` | error | US Social-Security-like numbers (with area-number sanity checks) |
| `pii.phone` | warning | Phone-number-like digit sequences |
| `pii.credit-card` | error | Card-length digit sequences |
| `pii.ipv4` | information | IPv4 addresses (capped at 20/file to avoid config-file noise) |

### Secrets (`secret.*`)
| Rule | Severity | Detects |
|---|---|---|
| `secret.aws-key` | error | `AKIA…` access key IDs |
| `secret.openai-key` | error | `sk-…` API keys |
| `secret.bearer-token` | error | `Bearer …` token literals |
| `secret.generic-key-assignment` | error | `api_key = "…"`-style inline assignments |
| `secret.private-key` | error | `-----BEGIN … PRIVATE KEY-----` blocks |

### Prompt risk (`prompt-risk.*`)
| Rule | Severity | Detects |
|---|---|---|
| `prompt.ignore-instructions` | warning | "ignore all previous instructions" phrasing |
| `prompt.system-prompt-leak` | warning | "reveal your system prompt" requests |
| `prompt.jailbreak-roleplay` | warning | DAN / developer-mode framing |
| `prompt.hidden-instruction` | information | Mentions of hidden/zero-width instructions |

## Tuning for your team

- **Test fixtures keep firing?** Scope scanning with `aiGovernance.filePatterns`
  (e.g. `["src/**"]`) or disable the noisy rule for the workspace:
  `"aiGovernance.disabledRules": ["pii.ipv4"]`.
- **Only care about secrets in CI-adjacent code?** Set
  `"aiGovernance.enabledCategories": ["secret"]`.
- **Performance:** `scanOnChange` re-runs a regex scan per keystroke. For very
  large files, turn it off and rely on `scanOnSave`.

## Generating evidence

`AI Governance: Generate Report for Active File` opens a Markdown report with a
verdict (BLOCKED / REVIEW / INFORMATIONAL / CLEAN), summary tables, and a
per-finding detail section with line numbers, rule IDs, and remediation
guidance. Save the report next to your PR or audit packet — see
`examples/expected-report.md` for a sample.

## Verifying the extension itself

1. `npm test` — 15 unit tests over the rules engine and report generator.
2. Open `examples/sample-risky.py` — you should see 10 diagnostics; compare
   against `examples/expected-report.md`.
