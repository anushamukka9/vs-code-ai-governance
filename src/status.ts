// Status-bar summary for the active file's scan result.
//
// Pure functions only: no vscode dependency, so the text is fully
// unit-testable in plain Node. extension.ts owns the actual
// vscode.StatusBarItem and calls buildStatusBarText after each scan.

import type { ScanResult, Severity } from "./types";

export interface SeverityCounts {
  error: number;
  warning: number;
  information: number;
}

export function countBySeverity(result: ScanResult): SeverityCounts {
  const counts: SeverityCounts = { error: 0, warning: 0, information: 0 };
  for (const f of result.findings) {
    counts[f.severity as Severity] += 1;
  }
  return counts;
}

/** Status-bar text, e.g. "$(check) AI Gov: clean" or "AI Gov: $(error) 2 $(warning) 1". */
export function buildStatusBarText(counts: SeverityCounts): string {
  const total = counts.error + counts.warning + counts.information;
  if (total === 0) {
    return "$(check) AI Gov: clean";
  }
  const parts: string[] = [];
  if (counts.error > 0) parts.push(`$(error) ${counts.error}`);
  if (counts.warning > 0) parts.push(`$(warning) ${counts.warning}`);
  if (counts.information > 0) parts.push(`$(info) ${counts.information}`);
  return `AI Gov: ${parts.join(" ")}`;
}

/** Short tooltip shown on hover of the status-bar item. */
export function buildStatusBarTooltip(counts: SeverityCounts): string {
  const total = counts.error + counts.warning + counts.information;
  if (total === 0) {
    return "AI Governance Guard: no findings in the active file. Click for a full report.";
  }
  return (
    `AI Governance Guard: ${total} finding(s) in the active file ` +
    `(${counts.error} error, ${counts.warning} warning, ${counts.information} info). ` +
    "Click for a full report."
  );
}
