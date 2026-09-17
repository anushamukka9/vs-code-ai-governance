// Heuristics engine for AI-governance policy violations.
// Pure TypeScript, zero dependencies: runs inside the extension host
// and is fully unit-testable without VS Code.
//
// Three rule families:
//   pii          - personally identifiable information patterns
//   secret       - hardcoded credentials / API keys / tokens
//   prompt-risk  - risky prompt-engineering strings (jailbreaks, system
//                  prompt exfiltration, prompt injection primers)

import type { Category, Finding, ScanResult, Severity } from "./types";

interface RawRule {
  id: string;
  category: Category;
  severity: Severity;
  title: string;
  pattern: RegExp;
  message: string;
  /** Optional cap: only report if this rule fires at most N times per file (noise control). */
  maxPerFile?: number;
}

const EMAIL =
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
const US_SSN = /\b(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b/;
const US_PHONE =
  /(?:(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4})\b/;
const CREDIT_CARD =
  /\b(?:\d[ -]*?){13,19}\b/;
const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/;

const RULES: RawRule[] = [
  // ---------------- PII ----------------
  {
    id: "pii.email",
    category: "pii",
    severity: "warning",
    title: "Email address",
    pattern: new RegExp(EMAIL.source, "g"),
    message:
      "Email address detected. If this is real user data being sent to an AI model or logged, it may violate data-handling policy. Redact or pseudonymize.",
  },
  {
    id: "pii.ssn",
    category: "pii",
    severity: "error",
    title: "Possible US Social Security number",
    pattern: new RegExp(US_SSN.source, "g"),
    message:
      "Pattern resembles a US Social Security number. Never include real SSNs in prompts, training data, or logs. Remove or tokenize.",
  },
  {
    id: "pii.phone",
    category: "pii",
    severity: "warning",
    title: "Possible phone number",
    pattern: new RegExp(US_PHONE.source, "g"),
    message:
      "Pattern resembles a phone number. Phone numbers are PII; verify this is test data before it reaches any AI system.",
  },
  {
    id: "pii.credit-card",
    category: "pii",
    severity: "error",
    title: "Possible credit card number",
    pattern: new RegExp(CREDIT_CARD.source, "g"),
    message:
      "Digit sequence matches a credit-card length profile. Real card numbers must never appear in code, prompts, or fixtures.",
  },
  {
    id: "pii.ipv4",
    category: "pii",
    severity: "information",
    title: "IP address",
    pattern: new RegExp(IPV4.source, "g"),
    message:
      "IP address detected. Internal IPs in configs are usually fine, but public IPs may be identifying; review before sharing with AI services.",
    maxPerFile: 20,
  },

  // ---------------- Secrets ----------------
  {
    id: "secret.aws-key",
    category: "secret",
    severity: "error",
    title: "Possible AWS access key ID",
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    message:
      "Hardcoded AWS access key ID. Rotate the key and move it to a secret manager; never commit credentials.",
  },
  {
    id: "secret.generic-key-assignment",
    category: "secret",
    severity: "error",
    title: "Hardcoded secret assignment",
    pattern:
      /\b(?:api[_-]?key|apikey|secret|passwd|password|token|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*["'][^"'`]{8,}["']/gi,
    message:
      "A secret-looking value is assigned inline in source. Move it to environment variables or a vault and rotate it.",
  },
  {
    id: "secret.private-key",
    category: "secret",
    severity: "error",
    title: "Private key material",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    message:
      "Private key block embedded in a file. Keys must live in a secret manager, never in source.",
  },
  {
    id: "secret.openai-key",
    category: "secret",
    severity: "error",
    title: "Possible OpenAI API key",
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/g,
    message:
      "Hardcoded OpenAI-style API key. Revoke it in the provider dashboard and inject via environment.",
  },
  {
    id: "secret.bearer-token",
    category: "secret",
    severity: "error",
    title: "Bearer token literal",
    pattern: /\bBearer\s+[A-Za-z0-9\-._~+/=]{16,}\b/g,
    message:
      "Bearer token in source. Tokens are credentials; load them at runtime from secure storage.",
  },

  // ---------------- Prompt risk ----------------
  {
    id: "prompt.ignore-instructions",
    category: "prompt-risk",
    severity: "warning",
    title: "Instruction-override phrasing",
    pattern:
      /\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|earlier|your|the)\s+(instructions|prompts?|rules?|guidelines?)\b/gi,
    message:
      "Prompt contains instruction-override phrasing typical of jailbreak/prompt-injection attacks. Review whether this text ships to users or an LLM.",
  },
  {
    id: "prompt.system-prompt-leak",
    category: "prompt-risk",
    severity: "warning",
    title: "System prompt disclosure request",
    pattern:
      /\b(reveal|show|print|output|repeat|disclose|exfiltrate)\s+(your|the)\s+system\s+(prompt|instructions)\b/gi,
    message:
      "Text asks an assistant to disclose its system prompt. System prompts are proprietary; flag this as a prompt-injection risk.",
  },
  {
    id: "prompt.jailbreak-roleplay",
    category: "prompt-risk",
    severity: "warning",
    title: "Jailbreak roleplay framing",
    pattern:
      /\b(you are (now |no longer )?DAN|do anything now|developer mode|jailbreak mode)\b/gi,
    message:
      "Jailbreak-style roleplay framing detected. This pattern is used to bypass model safety guardrails.",
  },
  {
    id: "prompt.hidden-instruction",
    category: "prompt-risk",
    severity: "information",
    title: "Suspicious hidden instruction",
    pattern:
      /\b(hidden|invisible|white[ -]?text|zero[ -]?width)\s+(instruction|prompt|text)\b/gi,
    message:
      "Mentions hidden instructions, a technique for smuggling instructions past human reviewers. Verify intent.",
  },
];

export interface EngineOptions {
  /** Rule families to enable. Defaults to all. */
  enabledCategories?: Category[];
  /** Rule ids to skip entirely. */
  disabledRules?: string[];
}

/** Scan a document's lines and return structured findings. */
export function scanLines(
  file: string,
  lines: string[],
  options: EngineOptions = {},
): ScanResult {
  const enabled = new Set(options.enabledCategories ?? ["pii", "secret", "prompt-risk"]);
  const disabled = new Set(options.disabledRules ?? []);
  const counts = new Map<string, number>();
  const findings: Finding[] = [];

  for (const rule of RULES) {
    if (!enabled.has(rule.category)) continue;
    if (disabled.has(rule.id)) continue;

    const re = new RegExp(rule.pattern.source, rule.pattern.flags);
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      let m: RegExpExecArray | null;
      re.lastIndex = 0;
      while ((m = re.exec(lineText)) !== null) {
        const n = (counts.get(rule.id) ?? 0) + 1;
        counts.set(rule.id, n);
        if (rule.maxPerFile !== undefined && n > rule.maxPerFile) {
          continue;
        }
        // Guard against zero-length matches looping forever.
        if (m[0].length === 0) {
          re.lastIndex += 1;
          continue;
        }
        findings.push({
          title: rule.title,
          ruleId: rule.id,
          category: rule.category,
          severity: rule.severity,
          line: i + 1,
          column: (m.index ?? 0) + 1,
          endColumn: (m.index ?? 0) + m[0].length + 1,
          message: rule.message,
          snippet: m[0].slice(0, 40),
        });
      }
    }
  }

  findings.sort((a, b) => a.line - b.line || a.column - b.column);
  return { file, lines: lines.length, findings };
}

/** Convenience wrapper for scanning whole text. */
export function scanText(
  file: string,
  text: string,
  options?: EngineOptions,
): ScanResult {
  return scanLines(file, text.split(/\r?\n/), options);
}

/** The compiled rule set, exposed for docs/reporting. */
export function listRules(): Pick<RawRule, "id" | "category" | "severity" | "title">[] {
  return RULES.map((r) => ({
    id: r.id,
    category: r.category,
    severity: r.severity,
    title: r.title,
  }));
}
