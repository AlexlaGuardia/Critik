"""Critik detection benchmark — the precision/recall scorecard.

    python -m evals.critik.run_evals

Scans every labeled file with the real Scanner and computes:
  - Detection rate (recall): of vulnerable files, the fraction caught at expected severity.
    This is the credibility number — "Critik catches X% of N known issues."
  - False-positive rate: of clean files, the fraction that raised a finding at/above the
    noise floor. The half that had no test corpus before, so the FP-cut overhaul flew blind.
  - File-level precision: TP / (TP + FP).
  - Per-category recall.

Deterministic — no AI pass, no API key needed. Writes evals/critik/results.json.
"""

import json
import os
from pathlib import Path

from critik.scanner import Scanner
from critik.models import Severity
from evals.critik import labels

CORPUS = Path(__file__).parent / "corpus"
RESULTS_PATH = Path(__file__).parent / "results.json"


def _rank(sev_value: str) -> int:
    return Severity(sev_value).rank


def scan_file(path: Path):
    """Return the list of (check_name, severity_value, line) for one file."""
    res = Scanner(str(path)).scan()
    return [(f.check_name, f.severity.value, f.line) for f in res.findings]


def main():
    floor = _rank(labels.NOISE_FLOOR)

    # ── vulnerable half: recall ──
    vuln_rows, cat_recall = [], {}
    detected = 0
    for fname, lbl in labels.VULNERABLE.items():
        path = CORPUS / "vulnerable" / fname
        findings = scan_file(path)
        need = _rank(lbl["min_severity"])
        top = max((_rank(s) for _, s, _ in findings), default=-1)
        hit = top >= need
        detected += int(hit)
        cat_recall.setdefault(lbl["category"], [0, 0])
        cat_recall[lbl["category"]][1] += 1
        cat_recall[lbl["category"]][0] += int(hit)
        vuln_rows.append((fname, lbl["category"], lbl["min_severity"], len(findings), hit))

    # ── clean half: false positives ──
    clean_rows = []
    fp_files = 0
    for fname, lbl in labels.CLEAN.items():
        path = CORPUS / "clean" / fname
        findings = scan_file(path)
        alarming = [(c, s, ln) for c, s, ln in findings if _rank(s) >= floor]
        is_fp = len(alarming) > 0
        fp_files += int(is_fp)
        clean_rows.append((fname, lbl["category"], len(findings), alarming, is_fp))

    n_vuln, n_clean = len(labels.VULNERABLE), len(labels.CLEAN)
    tp = detected
    fp = fp_files
    recall = tp / n_vuln if n_vuln else 0
    fp_rate = fp / n_clean if n_clean else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

    # ── scorecard ──
    print(f"\nVULNERABLE ({n_vuln})  — detection at expected severity")
    print(f"{'FILE':<28}{'CATEGORY':<13}{'NEED':<10}{'FINDINGS':<10}DETECTED")
    print("-" * 74)
    for fname, cat, need, nf, hit in vuln_rows:
        print(f"{fname:<28}{cat:<13}{need:<10}{nf:<10}{'YES' if hit else 'NO  <-- MISS'}")

    print(f"\nCLEAN ({n_clean})  — false positives at/above {labels.NOISE_FLOOR.upper()}")
    print(f"{'FILE':<28}{'CATEGORY':<13}{'TOTAL':<8}{'ALARMING':<10}FP?")
    print("-" * 74)
    for fname, cat, nf, alarming, is_fp in clean_rows:
        detail = "" if not alarming else "  " + ", ".join(f"{c}/{s}" for c, s, _ in alarming)
        print(f"{fname:<28}{cat:<13}{nf:<8}{len(alarming):<10}{'FP' if is_fp else 'ok'}{detail}")

    print("\n" + "=" * 74)
    print(f"DETECTION RATE (recall):  {tp}/{n_vuln}  = {recall:.0%}")
    print(f"FALSE-POSITIVE RATE:      {fp}/{n_clean}  = {fp_rate:.0%}")
    print(f"PRECISION (file-level):   {precision:.0%}")
    print(f"F1:                       {f1:.2f}")
    print("\nPer-category recall:")
    for cat, (p, a) in sorted(cat_recall.items()):
        print(f"  {cat:<14}{p}/{a}")

    summary = {"recall": round(recall, 3), "fp_rate": round(fp_rate, 3),
               "precision": round(precision, 3), "f1": round(f1, 3),
               "detected": tp, "n_vulnerable": n_vuln, "fp_files": fp, "n_clean": n_clean,
               "noise_floor": labels.NOISE_FLOOR}
    with open(RESULTS_PATH, "w") as f:
        json.dump({"summary": summary,
                   "vulnerable": [{"file": r[0], "category": r[1], "need": r[2],
                                   "findings": r[3], "detected": r[4]} for r in vuln_rows],
                   "clean": [{"file": r[0], "category": r[1], "findings": r[2],
                              "alarming": [{"check": a[0], "severity": a[1], "line": a[2]} for a in r[3]],
                              "false_positive": r[4]} for r in clean_rows]},
                  f, indent=2)
    print(f"\nWrote {RESULTS_PATH}")


if __name__ == "__main__":
    main()
