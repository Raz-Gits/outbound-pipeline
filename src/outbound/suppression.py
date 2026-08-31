"""Append-only do-not-contact ledger.

The one file in an outbound system with legal consequences. Three properties
are load-bearing and every one is enforced here rather than trusted to
callers:

1. **Append-only.** The public API can add an address and can read the set.
   Nothing here removes one. An unsubscribe has to survive forever, and a
   ledger that can be edited or rebuilt can quietly resurrect someone who
   asked to be left alone.

2. **Checked at the last moment.** Callers filter immediately before the
   send/ship step, not at the start of a run — runs are long and people opt
   out during them. ``filter_leads`` exists so that check is one line.

3. **Case-insensitive, whitespace-tolerant.** ``Foo@Bar.com `` and
   ``foo@bar.com`` are the same person, and a suppression that can be
   defeated by capitalisation is not a suppression.

Format: one lowercased email per line, ``#`` comments allowed. Plain text on
purpose — greppable, diffable, auditable, and appendable from a shell.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_PATH = Path("data") / "do_not_contact.txt"
_LOCK = threading.Lock()


def _norm(email: str) -> str:
    return (email or "").strip().lower()


def load(path: str | Path = DEFAULT_PATH) -> set[str]:
    """The current suppression set. Missing file = empty set (a new install),
    but an UNREADABLE file raises — silently sending to everyone because the
    ledger failed to parse is the exact catastrophe this module exists to
    prevent, so that failure must be loud."""
    p = Path(path)
    if not p.exists():
        return set()
    out: set[str] = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.add(s.lower())
    return out


def add(emails: str | list[str], path: str | Path = DEFAULT_PATH) -> int:
    """Append address(es). Idempotent — already-present entries are skipped.
    Returns the number actually added."""
    if isinstance(emails, str):
        emails = [emails]
    p = Path(path)
    with _LOCK:
        current = load(p)
        new = [e for e in (_norm(x) for x in emails)
               if e and "@" in e and e not in current]
        if not new:
            return 0
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            for e in new:
                f.write(e + "\n")
    log.info("suppression: %d address(es) added", len(new))
    return len(new)


def is_suppressed(email: str, path: str | Path = DEFAULT_PATH) -> bool:
    return _norm(email) in load(path)


def filter_leads(leads: list[dict], path: str | Path = DEFAULT_PATH,
                 *, email_key: str = "email") -> tuple[list[dict], int]:
    """Drop suppressed leads. Returns (kept, dropped_count).

    Call this immediately before shipping — not earlier.
    """
    blocked = load(path)
    kept = [ld for ld in leads if _norm(str(ld.get(email_key, ""))) not in blocked]
    dropped = len(leads) - len(kept)
    if dropped:
        log.info("suppression: %d lead(s) dropped at ship time", dropped)
    return kept, dropped
