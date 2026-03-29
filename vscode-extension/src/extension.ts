import * as vscode from "vscode";
import { scanFile, scanWorkspace, VibecheckFinding } from "./scanner";

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel("VibeCheck");
  diagnosticCollection = vscode.languages.createDiagnosticCollection("vibecheck");
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.command = "vibecheck.scanFile";
  statusBarItem.show();
  updateStatusBar(0);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("vibecheck.scanFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        runScanOnFile(editor.document);
      }
    }),

    vscode.commands.registerCommand("vibecheck.scanWorkspace", () => {
      runScanOnWorkspace();
    }),

    vscode.commands.registerCommand("vibecheck.clearDiagnostics", () => {
      diagnosticCollection.clear();
      updateStatusBar(0);
    })
  );

  // Scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration("vibecheck");
      if (config.get<boolean>("enable") && config.get<boolean>("scanOnSave")) {
        runScanOnFile(doc);
      }
    })
  );

  // Scan on open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration("vibecheck");
      if (config.get<boolean>("enable") && config.get<boolean>("scanOnOpen")) {
        runScanOnFile(doc);
      }
    })
  );

  // Clean up diagnostics when file is closed
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
    })
  );

  // Hover provider — shows fix hints
  context.subscriptions.push(
    vscode.languages.registerHoverProvider(
      [
        "python",
        "javascript",
        "typescript",
        "javascriptreact",
        "typescriptreact",
        "json",
      ],
      new VibecheckHoverProvider()
    )
  );

  // Code action provider — quick fix
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      [
        "python",
        "javascript",
        "typescript",
        "javascriptreact",
        "typescriptreact",
        "json",
      ],
      new VibecheckCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );

  context.subscriptions.push(diagnosticCollection, statusBarItem, outputChannel);

  outputChannel.appendLine("VibeCheck activated");

  // Scan currently open file on activation
  const editor = vscode.window.activeTextEditor;
  if (editor) {
    const config = vscode.workspace.getConfiguration("vibecheck");
    if (config.get<boolean>("enable")) {
      runScanOnFile(editor.document);
    }
  }
}

async function runScanOnFile(document: vscode.TextDocument) {
  if (document.uri.scheme !== "file") return;

  const config = vscode.workspace.getConfiguration("vibecheck");
  const severity = config.get<string>("severity", "medium");
  const pythonPath = config.get<string>("pythonPath", "");

  try {
    const findings = await scanFile(
      document.uri.fsPath,
      severity,
      pythonPath,
      outputChannel
    );
    applyDiagnostics(document.uri, findings);
  } catch (err: any) {
    outputChannel.appendLine(`Error scanning ${document.fileName}: ${err.message}`);
  }
}

async function runScanOnWorkspace() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) {
    vscode.window.showWarningMessage("No workspace folder open");
    return;
  }

  const config = vscode.workspace.getConfiguration("vibecheck");
  const severity = config.get<string>("severity", "medium");
  const pythonPath = config.get<string>("pythonPath", "");

  statusBarItem.text = "$(loading~spin) VibeCheck scanning...";

  try {
    const findings = await scanWorkspace(
      folders[0].uri.fsPath,
      severity,
      pythonPath,
      outputChannel
    );

    // Group findings by file
    const byFile = new Map<string, VibecheckFinding[]>();
    for (const f of findings) {
      const list = byFile.get(f.file) || [];
      list.push(f);
      byFile.set(f.file, list);
    }

    diagnosticCollection.clear();
    let total = 0;
    for (const [filePath, fileFindings] of byFile) {
      const uri = vscode.Uri.file(filePath);
      applyDiagnostics(uri, fileFindings);
      total += fileFindings.length;
    }

    updateStatusBar(total);
    vscode.window.showInformationMessage(
      `VibeCheck: ${total} findings across ${byFile.size} files`
    );
  } catch (err: any) {
    outputChannel.appendLine(`Workspace scan error: ${err.message}`);
    vscode.window.showErrorMessage(`VibeCheck: ${err.message}`);
  }
}

function applyDiagnostics(uri: vscode.Uri, findings: VibecheckFinding[]) {
  const diagnostics: vscode.Diagnostic[] = findings.map((f) => {
    const line = Math.max(0, f.line - 1);
    const range = new vscode.Range(line, f.column, line, 1000);

    const severity = mapSeverity(f.severity);
    const diag = new vscode.Diagnostic(range, f.message, severity);
    diag.source = "vibecheck";
    diag.code = f.check;

    // Store fix hint in relatedInformation for hover/codeaction access
    if (f.fix) {
      diag.relatedInformation = [
        new vscode.DiagnosticRelatedInformation(
          new vscode.Location(uri, range),
          `Fix: ${f.fix}`
        ),
      ];
    }

    return diag;
  });

  diagnosticCollection.set(uri, diagnostics);

  // Count total across all files
  let total = 0;
  diagnosticCollection.forEach(() => total++);
  updateStatusBar(findings.length);
}

function mapSeverity(sev: string): vscode.DiagnosticSeverity {
  switch (sev) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
    case "info":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}

function updateStatusBar(count: number) {
  if (count === 0) {
    statusBarItem.text = "$(shield) VibeCheck";
    statusBarItem.tooltip = "No security issues found";
    statusBarItem.backgroundColor = undefined;
  } else {
    statusBarItem.text = `$(warning) VibeCheck: ${count}`;
    statusBarItem.tooltip = `${count} security issue${count === 1 ? "" : "s"} found`;
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.warningBackground"
    );
  }
}

// Hover provider — shows fix hints on vulnerable lines
class VibecheckHoverProvider implements vscode.HoverProvider {
  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position
  ): vscode.Hover | undefined {
    const diagnostics = diagnosticCollection.get(document.uri) || [];

    for (const diag of diagnostics) {
      if (diag.range.contains(position) && diag.source === "vibecheck") {
        const parts: vscode.MarkdownString[] = [];

        const md = new vscode.MarkdownString();
        md.isTrusted = true;
        md.appendMarkdown(`**VibeCheck** \`${diag.code}\`\n\n`);
        md.appendMarkdown(`${diag.message}\n\n`);

        if (diag.relatedInformation?.length) {
          md.appendMarkdown(`---\n\n`);
          md.appendMarkdown(
            `${diag.relatedInformation[0].message}\n`
          );
        }

        parts.push(md);
        return new vscode.Hover(parts, diag.range);
      }
    }
    return undefined;
  }
}

// Code action provider — quick fix suggestions
class VibecheckCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diag of context.diagnostics) {
      if (diag.source !== "vibecheck") continue;

      // "Explain this check" action
      const explainAction = new vscode.CodeAction(
        `VibeCheck: Explain "${diag.code}"`,
        vscode.CodeActionKind.QuickFix
      );
      explainAction.command = {
        command: "workbench.action.terminal.sendSequence",
        title: "Explain check",
        arguments: [{ text: `vibecheck explain ${diag.code}\n` }],
      };
      explainAction.diagnostics = [diag];
      explainAction.isPreferred = false;
      actions.push(explainAction);

      // If there's a fix hint, add "Copy fix" action
      if (diag.relatedInformation?.length) {
        const fixText = diag.relatedInformation[0].message.replace(
          /^Fix: /,
          ""
        );
        const copyAction = new vscode.CodeAction(
          `VibeCheck: Copy fix to clipboard`,
          vscode.CodeActionKind.QuickFix
        );
        copyAction.command = {
          command: "editor.action.clipboardCopyAction",
          title: "Copy fix",
        };
        // Actually, let's use a proper command to copy
        copyAction.command = {
          command: "vibecheck.copyFix",
          title: "Copy fix hint",
          arguments: [fixText],
        };
        copyAction.diagnostics = [diag];
        actions.push(copyAction);
      }
    }

    return actions;
  }
}

export function deactivate() {
  diagnosticCollection?.dispose();
  statusBarItem?.dispose();
  outputChannel?.dispose();
}
