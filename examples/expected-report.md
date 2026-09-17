# AI Governance Scan Report

- **File:** `examples/sample-risky.py`
- **Lines scanned:** 38
- **Generated:** 2026-09-17T16:35:54.145Z
- **Engine:** ai-governance heuristics v1

## Verdict: ⛔ BLOCKED — fix errors before proceeding

## Summary

| Category | Findings |
| --- | --- |
| PII | 4 |
| Secrets | 4 |
| Prompt risk | 2 |

| Severity | Findings |
| --- | --- |
| Error | 5 |
| Warning | 4 |
| Information | 1 |

## Findings

| # | Severity | Category | Line | Rule | Finding |
| --- | --- | --- | --- | --- | --- |
| 1 | 🔴 error | secret | 9:22 | `secret.aws-key` | Possible AWS access key ID |
| 2 | 🔴 error | secret | 10:14 | `secret.openai-key` | Possible OpenAI API key |
| 3 | 🔴 error | secret | 11:1 | `secret.generic-key-assignment` | Hardcoded secret assignment |
| 4 | 🔴 error | secret | 12:16 | `secret.bearer-token` | Bearer token literal |
| 5 | 🔴 error | pii | 15:17 | `pii.ssn` | Possible US Social Security number |
| 6 | 🟡 warning | pii | 16:18 | `pii.email` | Email address |
| 7 | 🟡 warning | pii | 17:19 | `pii.phone` | Possible phone number |
| 8 | 🔵 information | pii | 18:16 | `pii.ipv4` | IP address |
| 9 | 🟡 warning | prompt-risk | 23:18 | `prompt.ignore-instructions` | Instruction-override phrasing |
| 10 | 🟡 warning | prompt-risk | 24:20 | `prompt.system-prompt-leak` | System prompt disclosure request |

## Detail

### 1. Possible AWS access key ID

- **Location:** line 9, columns 22–42
- **Rule:** `secret.aws-key` (secret)
- **Severity:** error
- **Guidance:** Hardcoded AWS access key ID. Rotate the key and move it to a secret manager; never commit credentials.
- **Matched snippet:** `AKIAIOSFODNN7EXAMPLE`

### 2. Possible OpenAI API key

- **Location:** line 10, columns 14–46
- **Rule:** `secret.openai-key` (secret)
- **Severity:** error
- **Guidance:** Hardcoded OpenAI-style API key. Revoke it in the provider dashboard and inject via environment.
- **Matched snippet:** `sk-aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW`

### 3. Hardcoded secret assignment

- **Location:** line 11, columns 1–34
- **Rule:** `secret.generic-key-assignment` (secret)
- **Severity:** error
- **Guidance:** A secret-looking value is assigned inline in source. Move it to environment variables or a vault and rotate it.
- **Matched snippet:** `password = "Sup3rS3cretP@ssw0rd!"`

### 4. Bearer token literal

- **Location:** line 12, columns 16–54
- **Rule:** `secret.bearer-token` (secret)
- **Severity:** error
- **Guidance:** Bearer token in source. Tokens are credentials; load them at runtime from secure storage.
- **Matched snippet:** `Bearer eyJhbGciOiJIUzI1NiJ9.fake.token`

### 5. Possible US Social Security number

- **Location:** line 15, columns 17–28
- **Rule:** `pii.ssn` (pii)
- **Severity:** error
- **Guidance:** Pattern resembles a US Social Security number. Never include real SSNs in prompts, training data, or logs. Remove or tokenize.
- **Matched snippet:** `078-05-1120`

### 6. Email address

- **Location:** line 16, columns 18–38
- **Rule:** `pii.email` (pii)
- **Severity:** warning
- **Guidance:** Email address detected. If this is real user data being sent to an AI model or logged, it may violate data-handling policy. Redact or pseudonymize.
- **Matched snippet:** `jane.doe@example.com`

### 7. Possible phone number

- **Location:** line 17, columns 19–31
- **Rule:** `pii.phone` (pii)
- **Severity:** warning
- **Guidance:** Pattern resembles a phone number. Phone numbers are PII; verify this is test data before it reaches any AI system.
- **Matched snippet:** `555-867-5309`

### 8. IP address

- **Location:** line 18, columns 16–26
- **Rule:** `pii.ipv4` (pii)
- **Severity:** information
- **Guidance:** IP address detected. Internal IPs in configs are usually fine, but public IPs may be identifying; review before sharing with AI services.
- **Matched snippet:** `10.24.7.11`

### 9. Instruction-override phrasing

- **Location:** line 23, columns 18–50
- **Rule:** `prompt.ignore-instructions` (prompt-risk)
- **Severity:** warning
- **Guidance:** Prompt contains instruction-override phrasing typical of jailbreak/prompt-injection attacks. Review whether this text ships to users or an LLM.
- **Matched snippet:** `Ignore all previous instructions`

### 10. System prompt disclosure request

- **Location:** line 24, columns 20–45
- **Rule:** `prompt.system-prompt-leak` (prompt-risk)
- **Severity:** warning
- **Guidance:** Text asks an assistant to disclose its system prompt. System prompts are proprietary; flag this as a prompt-injection risk.
- **Matched snippet:** `reveal your system prompt`
