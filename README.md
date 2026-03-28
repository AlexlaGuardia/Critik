# VibeCheck

Security scanner for vibe-coded apps. Catch what Copilot ships and Snyk overcharges for.

```bash
pip install vibecheck-ai
vibecheck scan .
```

## What it catches

- **Hardcoded secrets** — AWS keys, API tokens, database URLs, private keys (16 patterns)
- **SQL injection** — f-strings and string concatenation in execute() calls
- **Command injection** — eval(), exec(), os.system(), subprocess with shell=True
- **XSS vectors** — dangerouslySetInnerHTML, document.write(), eval() in JS
- **Missing auth** — FastAPI/Express routes without authentication middleware
- **Insecure config** — DEBUG=True, CORS wildcard, insecure cookies
- **Exposed .env** — real secrets in .env files, missing .gitignore entries

## Usage

```bash
# Scan current directory
vibecheck scan .

# Scan specific path
vibecheck scan ./src

# JSON output (for CI/CD)
vibecheck scan . --format json

# Only show critical and high
vibecheck scan . --severity high

# Quiet mode (summary only)
vibecheck scan . --quiet
```

## Exit codes

- `0` — No critical or high findings
- `1` — Critical or high findings detected
- `2` — Scanner error

## Supported languages

- Python (.py)
- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
- Environment files (.env)
- Config files (.json, .yaml, .toml)

## Ignore patterns

Create a `.vibeignore` file in your project root:

```
# Skip test fixtures
tests/fixtures/*
# Skip generated code
generated/*
```

## GitHub Action

Add to `.github/workflows/vibecheck.yml`:

```yaml
name: VibeCheck
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install vibecheck-ai
      - run: vibecheck scan .
```

For GitHub Code Scanning integration (findings appear inline on PRs):

```yaml
      - run: vibecheck scan . --format sarif > vibecheck.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vibecheck.sarif
```

## Why VibeCheck?

53% of teams that shipped AI-generated code discovered security issues that passed review. The vibe coding era needs a security scanner that's:

- **Fast** — scans in milliseconds, not minutes
- **Offline** — no API calls, no code leaving your machine
- **Free** — open source, zero dependencies
- **Focused** — catches real issues, not style nits

## License

MIT
