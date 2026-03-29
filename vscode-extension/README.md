# Critik for VS Code / Cursor

AI-powered security scanner for vibe-coded apps. Catches what Copilot ships and Snyk overcharges for.

## Features

- **Real-time scanning** on file save — red squiggles on vulnerable lines
- **Hover cards** with explanations and fix hints
- **Quick fix actions** — explain check, copy fix to clipboard
- **Status bar** showing finding count
- **Workspace scan** for full project analysis

## Requirements

Install the Critik CLI:

```bash
pip install critik
```

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `critik.enable` | `true` | Enable Critik scanning |
| `critik.severity` | `medium` | Minimum severity to report |
| `critik.scanOnSave` | `true` | Scan files on save |
| `critik.scanOnOpen` | `false` | Scan files when opened |
| `critik.pythonPath` | `""` | Path to critik executable |

## Commands

- **Critik: Scan Current File** — scan the active file
- **Critik: Scan Workspace** — scan the entire workspace
- **Critik: Clear Diagnostics** — clear all findings

## How It Works

The extension runs `critik scan <file> --format json` and converts findings to VS Code diagnostics. It requires the `critik` CLI to be installed and on your PATH.

For AI-powered analysis, set `GROQ_API_KEY` or `CRITIK_API_KEY` in your environment and run `critik scan . --ai` from the terminal.
