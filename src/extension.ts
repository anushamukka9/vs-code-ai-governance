// VS Code extension entry point: ai-governance diagnostics + report command.

import * as vscode from "vscode";
import { scanText } from "./rules";
import { generateMarkdownReport } from "./report";
import type { Category, Finding, ScanResult } from "./types";

let diagnostics: vscode.DiagnosticCollection;

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("ai-governance");
  context.subscriptions.push(diagnostics);

  const config = () => vscode.workspace.getConfiguration("aiGovernance");
  const scanOnChange = config().get<boolean>("scanOnChange", true);
  const scanOnSave = config().get<boolean>("scanOnSave", true);

  if (vscode.window.activeTextEditor) {
    lintDocument(vscode.window.activeTextEditor.document);
  }

  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) lintDocument(editor.document);
    }),
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (scanOnChange) lintDocument(e.document);
    }),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (scanOnSave) lintDocument(doc);
    }),
    vscode.commands.registerCommand("aiGovernance.generateReport", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        void vscode.window.showWarningMessage(
          "AI Governance: no active editor to report on.",
        );
        return;
      }
      const result = scanDocument(editor.document);
      const markdown = generateMarkdownReport(result);
      const doc = await vscode.workspace.openTextDocument({
        content: markdown,
        language: "markdown",
      });
      await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
      void vscode.window.showInformationMessage(
        `AI Governance: ${result.findings.length} finding(s) in report.`,
      );
    }),
    vscode.commands.registerCommand("aiGovernance.clearDiagnostics", () => {
      diagnostics.clear();
      void vscode.window.showInformationMessage(
        "AI Governance: diagnostics cleared.",
      );
    }),
  );
}

function scanDocument(doc: vscode.TextDocument): ScanResult {
  const cfg = vscode.workspace.getConfiguration("aiGovernance");
  const enabled = cfg.get<Category[]>("enabledCategories", [
    "pii",
    "secret",
    "prompt-risk",
  ]);
  const disabledRules = cfg.get<string[]>("disabledRules", []);
  return scanText(doc.fileName, doc.getText(), {
    enabledCategories: enabled,
    disabledRules,
  });
}

function toVsCodeSeverity(s: Finding["severity"]): vscode.DiagnosticSeverity {
  switch (s) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "warning":
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

function lintDocument(doc: vscode.TextDocument): void {
  const cfg = vscode.workspace.getConfiguration("aiGovernance");
  const filePatterns = cfg.get<string[]>("filePatterns", ["*"]);
  const enabled = cfg.get<boolean>("enable", true);
  if (!enabled) {
    diagnostics.delete(doc.uri);
    return;
  }
  if (
    !filePatterns.some((p) => matchGlob(p, doc.fileName)) &&
    filePatterns.length > 0
  ) {
    diagnostics.delete(doc.uri);
    return;
  }

  const result = scanDocument(doc);
  const vsDiags = result.findings.map((f) => {
    const range = new vscode.Range(
      new vscode.Position(f.line - 1, f.column - 1),
      new vscode.Position(f.line - 1, Math.max(f.column - 1, f.endColumn - 1)),
    );
    const d = new vscode.Diagnostic(
      range,
      `[${f.ruleId}] ${f.title}: ${f.message}`,
      toVsCodeSeverity(f.severity),
    );
    d.source = "ai-governance";
    d.code = f.ruleId;
    return d;
  });
  diagnostics.set(doc.uri, vsDiags);
}

/** Minimal glob matcher supporting `*` and `**` for file-pattern config. */
function matchGlob(pattern: string, fileName: string): boolean {
  if (pattern === "*") return true;
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "§§")
    .replace(/\*/g, "[^/\\\\]*")
    .replace(/§§/g, ".*");
  return new RegExp(`^${escaped}$`).test(fileName);
}

export function deactivate(): void {
  diagnostics?.clear();
}
