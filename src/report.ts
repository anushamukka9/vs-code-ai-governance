// Governance report generator: turns a ScanResult into a Markdown report
// suitable for saving, pasting into a PR, or attaching to audit evidence.

import type { Category, ScanResult, Severity } from "./types";

const SEVERITY_EMOJI: Record<Severity, string> = {
  error: "🔴",
  warning: "🟡",
  information: "🔵",
};

export function generateMarkdownReport(result: ScanResult): string {
  const { file, lines, findings } = result;
  const byCategory: Record<Category, number> = { pii: 0, secret: 0, "prompt-risk": 0 };
  const bySeverity: Record<Severity, number> = {
    error: 0,
    warning: 0,
    information: 0,
  };
  for (const f of findings) {
    byCategory[f.category] += 1;
    bySeverity[f.severity] += 1;
  }

  const verdict =
    bySeverity.error > 0
      ? "⛔ BLOCKED — fix errors before proceeding"
      : bySeverity.warning > 0
        ? "⚠️ REVIEW — warnings require human review"
        : findings.length > 0
          ? "ℹ️ INFORMATIONAL — low-risk findings only"
          : "✅ CLEAN — no findings";

  const out: string[] = [];
  out.push("# AI Governance Scan Report");
  out.push("");
  out.push(`- **File:** \`${file}\``);
  out.push(`- **Lines scanned:** ${lines}`);
  out.push(`- **Generated:** ${new Date().toISOString()}`);
  out.push(`- **Engine:** ai-governance heuristics v1`);
  out.push("");
  out.push(`## Verdict: ${verdict}`);
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push("| Category | Findings |");
  out.push("| --- | --- |");
  out.push(`| PII | ${byCategory.pii} |`);
  out.push(`| Secrets | ${byCategory.secret} |`);
  out.push(`| Prompt risk | ${byCategory["prompt-risk"]} |`);
  out.push("");
  out.push("| Severity | Findings |");
  out.push("| --- | --- |");
  out.push(`| Error | ${bySeverity.error} |`);
  out.push(`| Warning | ${bySeverity.warning} |`);
  out.push(`| Information | ${bySeverity.information} |`);
  out.push("");

  if (findings.length === 0) {
    out.push("_No policy violations detected._");
    out.push("");
    return out.join("\n");
  }

  out.push("## Findings");
  out.push("");
  out.push("| # | Severity | Category | Line | Rule | Finding |");
  out.push("| --- | --- | --- | --- | --- | --- |");
  findings.forEach((f, i) => {
    out.push(
      `| ${i + 1} | ${SEVERITY_EMOJI[f.severity]} ${f.severity} | ${f.category} | ${f.line}:${f.column} | \`${f.ruleId}\` | ${f.title} |`,
    );
  });
  out.push("");
  out.push("## Detail");
  out.push("");
  findings.forEach((f, i) => {
    out.push(`### ${i + 1}. ${f.title}`);
    out.push("");
    out.push(`- **Location:** line ${f.line}, columns ${f.column}–${f.endColumn}`);
    out.push(`- **Rule:** \`${f.ruleId}\` (${f.category})`);
    out.push(`- **Severity:** ${f.severity}`);
    out.push(`- **Guidance:** ${f.message}`);
    out.push(`- **Matched snippet:** \`${f.snippet.replace(/`/g, "'")}\``);
    out.push("");
  });

  return out.join("\n");
}
