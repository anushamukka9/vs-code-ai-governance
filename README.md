# AI Governance Guard (VS Code extension)

A VS Code extension that surfaces **AI-governance policy violations inline** as you code —
a companion to the [ai-policy-guard](https://github.com/anushamukka9/ai-policy-guard)
policy engine. It scans the active file with an embedded heuristics engine and shows:

- 🔴 **Diagnostics squiggles** under PII, hardcoded secrets, and risky prompt strings
- 📋 **Problems panel** entries with rule IDs and remediation guidance
- 📝 **One-click governance reports** in Markdown (`AI Governance: Generate Report for Active File`)

![screenshot placeholder](docs/screenshot-placeholder.png)

## Why

Prompts, training fixtures, and API glue code are where governance failures hide:
a customer email pasted into a debug prompt, an API key committed next to the
prompt template, a jailbreak string copied from a red-team notebook. This extension
puts the policy check where the code is written, so violations are caught before
they reach an LLM, a log, or a commit.

## Quickstart

1. Package the extension (see [Packaging](#packaging)) or install from the `.vsix`.
2. Open any file and start typing — findings appear as squiggles in the editor and
   entries in the **Problems** panel.
3. Open the Command Palette (`Ctrl/Cmd+Shift+P`) → **AI Governance: Generate Report
   for Active File** to open a Markdown governance report beside the editor.
4. Try the fixture: open `examples/sample-risky.py` — it should produce exactly the
   10 findings documented in `examples/expected-report.md`.

## Configuration

All settings live under `aiGovernance`:

| Setting | Default | Purpose |
|---|---|---|
| `aiGovernance.enable` | `true` | Master switch for diagnostics |
| `aiGovernance.enabledCategories` | `["pii","secret","prompt-risk"]` | Rule families to run |
| `aiGovernance.disabledRules` | `[]` | Rule IDs to skip, e.g. `["pii.ipv4"]` |
| `aiGovernance.filePatterns` | `["*"]` | Glob patterns of files to scan |
| `aiGovernance.scanOnChange` | `true` | Re-scan while typing |
| `aiGovernance.scanOnSave` | `true` | Re-scan on save |

Example `.vscode/settings.json`:

```json
{
  "aiGovernance.enabledCategories": ["pii", "secret"],
  "aiGovernance.disabledRules": ["pii.ipv4"],
  "aiGovernance.scanOnChange": false
}
```

## Architecture

```
src/
  extension.ts   VS Code glue: activation, DiagnosticCollection, commands
  rules.ts       Heuristics engine (pure TS, no vscode dependency)
  report.ts      Markdown report generator
  types.ts       Finding / ScanResult / Severity types
```

The engine is deliberately dependency-free so the same rule set can be unit-tested
in plain Node (`npm test`) and — in principle — reused outside VS Code. Diagnostics
map 1:1 to engine findings (line/column positions, severities, rule IDs).

Rule families: **pii** (email, SSN, phone, credit-card, IPv4), **secret**
(AWS keys, OpenAI keys, bearer tokens, inline secret assignments, private keys),
**prompt-risk** (instruction-override, system-prompt disclosure, jailbreak
roleplay, hidden instructions).

## Development

```bash
npm install
npm test        # compiles src -> out, runs 15 unit tests
npm run compile # tsc build
```

### Packaging

```bash
npm install -g @vscode/vsce
vsce package        # produces vs-code-ai-governance-1.0.0.vsix
code --install-extension vs-code-ai-governance-1.0.0.vsix
```

## Limitations

Heuristics are pattern-based: they can miss obfuscated secrets and can flag
test fixtures (see `docs/usage-guide.md` on tuning). This extension is a
guardrail, not a substitute for a secrets manager, DLP review, or legal advice.

## License

MIT — Copyright 2026 Anusha Mukka. See [LICENSE](LICENSE).
