import { execFile } from "child_process";
import { OutputChannel } from "vscode";

export interface VibecheckFinding {
  check: string;
  severity: string;
  file: string;
  line: number;
  column: number;
  message: string;
  snippet: string;
  fix: string;
  ai?: {
    verdict: string;
    confidence: number;
    explanation: string;
    fix: string;
    severity: string | null;
  };
}

interface VibecheckResult {
  findings: VibecheckFinding[];
  summary: {
    files_scanned: number;
    duration_ms: number;
    total: number;
  };
}

/**
 * Find the critik executable.
 * Priority: user config > PATH lookup
 */
function getExecutable(pythonPath: string): string {
  if (pythonPath) return pythonPath;
  return "critik";
}

/**
 * Run critik on a single file and return findings.
 */
export async function scanFile(
  filePath: string,
  severity: string,
  pythonPath: string,
  output: OutputChannel
): Promise<VibecheckFinding[]> {
  const exe = getExecutable(pythonPath);
  const args = ["scan", filePath, "--format", "json", "--severity", severity];

  return runVibecheck(exe, args, output);
}

/**
 * Run critik on a workspace directory.
 */
export async function scanWorkspace(
  dirPath: string,
  severity: string,
  pythonPath: string,
  output: OutputChannel
): Promise<VibecheckFinding[]> {
  const exe = getExecutable(pythonPath);
  const args = ["scan", dirPath, "--format", "json", "--severity", severity];

  return runVibecheck(exe, args, output);
}

function runVibecheck(
  exe: string,
  args: string[],
  output: OutputChannel
): Promise<VibecheckFinding[]> {
  return new Promise((resolve, reject) => {
    output.appendLine(`> ${exe} ${args.join(" ")}`);

    execFile(
      exe,
      args,
      { timeout: 30000, maxBuffer: 10 * 1024 * 1024 },
      (error, stdout, stderr) => {
        // critik exits 1 when findings exist — that's expected
        if (error && error.code !== 1) {
          // Real error (not installed, crashed, etc.)
          if (
            stderr?.includes("command not found") ||
            stderr?.includes("No such file") ||
            error.code === 127
          ) {
            reject(
              new Error(
                "critik not found. Install with: pip install critik"
              )
            );
            return;
          }
          output.appendLine(`stderr: ${stderr}`);
        }

        if (!stdout.trim()) {
          resolve([]);
          return;
        }

        try {
          const result: VibecheckResult = JSON.parse(stdout);
          output.appendLine(
            `Scanned ${result.summary.files_scanned} files in ${result.summary.duration_ms}ms — ${result.summary.total} findings`
          );
          resolve(result.findings);
        } catch (e) {
          output.appendLine(`Failed to parse output: ${stdout.substring(0, 200)}`);
          resolve([]);
        }
      }
    );
  });
}
