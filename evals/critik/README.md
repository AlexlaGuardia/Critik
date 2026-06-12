# Critik Detection Benchmark

The labeled corpus that measures Critik's **detection rate** and **false-positive rate** —
the credibility numbers a scanner lives or dies on. Before this, `tests/` had only
"bad" fixtures, so precision was untestable and the 78% FP-cut overhaul flew blind.

## Run

```bash
python3 -m evals.critik.run_evals
```

Deterministic — no AI pass, no API key. Writes `results.json` as the regression baseline.

## What it measures

- **Detection rate (recall)** — of the vulnerable corpus, the fraction caught at the
  expected severity. "Critik catches N/N known issues."
- **False-positive rate** — of the clean corpus, the fraction that raised a finding at or
  above the noise floor (MEDIUM). This is the half that had no test corpus before.
- **File-level precision** + **F1**, and **per-category recall**.

## Current baseline

`recall 100% (7/7) · FP-rate 0% (8 clean) · precision 100% · F1 1.00`

## Corpus

- `corpus/vulnerable/` — files that SHOULD trip a finding (the 7 original fixtures, copied
  here so the benchmark is self-contained and stable).
- `corpus/clean/` — FP-traps: code that looks scary but is safe (env-var secrets, a real
  `.env.example` template, parameterized SQL, hardened cookies, auth-gated firebase rules,
  server-side Next.js env). This is the precision guard.
- `labels.py` — ground truth: expected category + min severity per file; the MEDIUM noise floor.

## What it already caught

First run flagged a real FP: a canonical `.env.example` line
`DATABASE_URL=postgres://USER:PASSWORD@localhost/dbname` tripped `env-example-real-secret`
because the dotenv placeholder detector didn't recognize loopback hosts or generic
`USER:PASSWORD` credentials. Fixed in `checks/dotenv.py` (`_PLACEHOLDER_URL`) — real leaks
(non-loopback host, non-generic creds) still flag; 138 unit tests still pass. Precision 88% → 100%.

## Adding cases

Drop a file in `corpus/{vulnerable,clean}/`, add one line to `labels.py`. Keep clean cases
realistic (real filenames, real placeholder conventions) — an unrealistic fixture tests an
unrealistic code path.
