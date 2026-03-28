"""JSON output formatter."""

import json
from vibecheck.models import ScanResult


def format_json(result: ScanResult) -> str:
    """Format scan results as JSON."""
    return json.dumps(result.to_dict(), indent=2)
