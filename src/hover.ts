// Hover content for AI-governance findings.
//
// Pure functions only: no vscode dependency, so hover text is fully
// unit-testable in plain Node. extension.ts wires this into
// vscode.languages.registerHoverProvider.

import type { Finding, Severity } from "./types";

const SEVERITY_ICON: Record<Severity, string> = {
  error: "$(error)",
  warning: "$(warning)",
  information: "$(info)",
};

/** Markdown shown when the user hovers a finding's squiggle. */
export function buildHoverMarkdown(f: Finding): string {
  const out: string[] = [];
  out.push(`### ${SEVERITY_ICON[f.severity]} ${f.title}`);
  out.push("");
  out.push(`**Rule:** \`${f.ruleId}\` (${f.category}, severity ${f.severity})`);
  out.push("");
  out.push(f.message);
  out.push("");
  out.push(`**Matched snippet:** \`${f.snippet.replace(/`/g, "'")}\``);
  out.push("");
  out.push(
    "_AI Governance Guard: heuristic match, may be a false positive. " +
      "Run `AI Governance: Generate Report for Active File` for the full picture._",
  );
  return out.join("\n");
}

/**
 * Find the finding under a 0-based (line, character) position, or undefined.
 * Findings store 1-based positions, so callers pass editor coordinates.
 */
export function findingAt(
  findings: Finding[],
  line0: number,
  character0: number,
): Finding | undefined {
  return findings.find(
    (f) =>
      f.line - 1 === line0 &&
      character0 >= f.column - 1 &&
      character0 < f.endColumn - 1,
  );
}
