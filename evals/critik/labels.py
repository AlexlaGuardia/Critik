"""Ground-truth labels for the Critik detection benchmark.

Two halves:
  VULNERABLE — files that SHOULD trip a finding. Detection = at least one finding at or
               above `min_severity`. `category` is for the per-category recall table.
  CLEAN      — files that should stay quiet. Any finding at or above the noise floor
               (default MEDIUM) on these is a false positive — the metric the scanner's
               FP-cut overhaul could never measure because no clean corpus existed.

Keyed by filename (basename). Corpus lives in corpus/{vulnerable,clean}/.
"""

# file -> {category, min_severity}
VULNERABLE = {
    "bad_secrets.py":         {"category": "secrets",    "min_severity": "critical"},
    ".env.production":        {"category": "secrets",    "min_severity": "high"},
    "bad_injection.py":       {"category": "injection",  "min_severity": "high"},
    "bad_config.js":          {"category": "config",     "min_severity": "high"},
    "bad_firebase_rules.json":{"category": "frameworks", "min_severity": "critical"},
    "bad_nextjs_api.ts":      {"category": "frameworks", "min_severity": "critical"},
    "bad_supabase.ts":        {"category": "frameworks", "min_severity": "high"},
}

# file -> {category}  (expected: zero findings at/above the noise floor)
CLEAN = {
    "clean_secrets.py":        {"category": "secrets"},
    ".env.example":            {"category": "secrets"},
    "clean_injection.py":      {"category": "injection"},
    "clean_config.js":         {"category": "config"},
    "clean_firebase_rules.json":{"category": "frameworks"},
    "clean_nextjs_api.ts":     {"category": "frameworks"},
    "clean_supabase.ts":       {"category": "frameworks"},
    "clean_utils.py":          {"category": "none"},
}

# Findings at/above this rank on a clean file count as false positives.
# MEDIUM = a user-visible alarm; info/low are advisory and tolerated.
NOISE_FLOOR = "medium"
