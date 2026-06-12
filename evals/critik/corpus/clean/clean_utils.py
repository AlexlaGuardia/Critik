"""Plain benign utility code — no security surface at all. Must produce zero findings."""
from datetime import datetime, timezone


def slugify(text: str) -> str:
    return "-".join(text.lower().split())


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def chunk(items: list, size: int) -> list[list]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def percent(part: float, whole: float) -> float:
    return 0.0 if not whole else round(100 * part / whole, 1)
