"""Per-provider call tally — a usage meter, not a bill.

Free tiers are quotas, and a quota you are not counting is a quota you find
out about from a 429 in the middle of a run. Every provider adapter calls
``record_call(provider)`` after a successful billed-or-metered request, and
the tally accumulates per provider per calendar month in a small JSON file.

This is deliberately a MEASUREMENT, not an enforcement point. Caps live where
the money is: Anymail enforces its own monthly ledger, Apollo its
CreditBudget. This file is how you answer "where did the Hunter quota go"
without opening four dashboards.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

_PATH = Path("data") / "usage.json"
_LOCK = threading.Lock()


def _month() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def record_call(provider: str, *, key_id: str | None = None, n: int = 1) -> None:
    """Add `n` calls to this month's tally for `provider` (optionally per key).

    Best-effort by design: a tally write failure is logged and swallowed,
    because the meter must never abort the enrichment that just succeeded.
    """
    label = f"{provider}:{key_id}" if key_id else provider
    try:
        with _LOCK:
            data: dict = {}
            if _PATH.exists():
                try:
                    data = json.loads(_PATH.read_text())
                except (json.JSONDecodeError, OSError):
                    data = {}
            month = data.get(_month()) or {}
            month[label] = int(month.get(label, 0)) + n
            data[_month()] = month
            _PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = _PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
            os.replace(tmp, _PATH)
    except OSError as e:
        log.warning("usage tally write failed: %s", e)


def month_tally() -> dict[str, int]:
    """This month's calls per provider label. Empty dict when nothing yet."""
    try:
        data = json.loads(_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    out = data.get(_month()) or {}
    return {str(k): int(v) for k, v in out.items()}
