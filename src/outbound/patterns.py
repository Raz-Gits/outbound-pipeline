"""Generate candidate email addresses from a name and domain.

Output is ordered most-likely-first so the verifier can short-circuit on first hit.
"""

from __future__ import annotations

import re


def _normalize(s: str) -> str:
    """Lowercase, strip diacritics, keep [a-z0-9]."""
    s = s.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "", s)
    return s


def candidate_emails(first: str, last: str | None, domain: str) -> list[str]:
    """Return candidate email addresses, ordered most-likely first.

    If `last` is missing/None/the literal string "None" (which happens when
    an upstream extractor pulls a first name only), we generate ONLY
    the first-name-only patterns. Otherwise we'd produce nonsense like
    `anthony.none@acme.com` that catch-all domains accept and look real.
    """
    f = _normalize(first)
    if not (f and domain):
        return []

    # Guard against the literal "None" stringification bug (a real one)
    last_str = "" if last is None else str(last)
    if last_str.strip().lower() in ("", "none", "n/a", "null"):
        l = ""
    else:
        l = _normalize(last)

    if not l:
        # First-name-only patterns. Stops the failure where last="None" produced
        # `firstname.none@domain` and got accepted by catch-all domains.
        locals_ = [f]
    else:
        fi = f[0]
        # Ordered most-common-pattern first (based on common SMB usage)
        locals_ = [
            f"{f}.{l}",      # first.last      ← most common
            f"{f}",          # first
            f"{f}{l}",       # firstlast
            f"{fi}{l}",      # flast
            f"{f}_{l}",      # first_last
            f"{f}-{l}",      # first-last
            f"{l}",          # last
            f"{l}{f[0]}",    # lastf
            f"{fi}.{l}",     # f.last
            f"{l}.{f}",      # last.first
        ]
    seen: set[str] = set()
    out: list[str] = []
    for local in locals_:
        if local and local not in seen:
            seen.add(local)
            out.append(f"{local}@{domain}")
    return out
