# VibeCheck for VS Code / Cursor

AI-powered security scanner for vibe-coded apps. Catches what Copilot ships and Snyk overcharges for.

## Features

- **Real-time scanning** on file save — red squiggles on vulnerable lines
- **Hover cards** with explanations and fix hints
- **Quick fix actions** — explain check, copy fix to clipboard
- **Status bar** showing finding count
- **Workspace scan** for full project analysis

## Requirements

Install the VibeCheck CLI:

```bash
pip install vibecheck-ai
```

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `vibecheck.enable` | `true` | Enable VibeCheck scanning |
| `vibecheck.severity` | `medium` | Minimum severity to report |
| `vibecheck.scanOnSave` | `true` | Scan files on save |
| `vibecheck.scanOnOpen` | `false` | Scan files when opened |
| `vibecheck.pythonPath` | `""` | Path to vibecheck executable |

## Commands

- **VibeCheck: Scan Current File** — scan the active file
- **VibeCheck: Scan Workspace** — scan the entire workspace
- **VibeCheck: Clear Diagnostics** — clear all findings

## How It Works

The extension runs `vibecheck scan <file> --format json` and converts findings to VS Code diagnostics. It requires the `vibecheck` CLI to be installed and on your PATH.

For AI-powered analysis, set `GROQ_API_KEY` or `VIBECHECK_API_KEY` in your environment and run `vibecheck scan . --ai` from the terminal.
