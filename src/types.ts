// Shared types for the AI Governance scanner engine.

export type Severity = "error" | "warning" | "information";

export type Category = "pii" | "secret" | "prompt-risk";

export interface Finding {
  /** Human-readable title, e.g. "Possible AWS secret key". */
  title: string;
  /** Rule identifier, e.g. "secret.aws-key". */
  ruleId: string;
  category: Category;
  severity: Severity;
  /** 1-based line number. */
  line: number;
  /** 1-based column where the match starts. */
  column: number;
  /** 1-based end column (exclusive). */
  endColumn: number;
  /** Short explanation + remediation hint. */
  message: string;
  /** The matched snippet, redacted to the first 40 chars. */
  snippet: string;
}

export interface ScanResult {
  /** Relative path or URI of the scanned document. */
  file: string;
  /** Total lines scanned. */
  lines: number;
  findings: Finding[];
}
