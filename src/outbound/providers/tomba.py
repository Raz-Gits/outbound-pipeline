"""Tomba email-finder — name + domain → email via Tomba's v1/email-finder.

WHY: Fourth and last link in the quota'd-provider chain (after Snov,
GetProspect, Prospeo). 25 finds/mo on the free tier — smaller than the
others — so it fires last, only when the upstream three miss. Tomba's
database leans B2B SaaS / agency / startup, which complements Snov's
LinkedIn-heavy slant.

CACHE: 48-hour SQLite at data/tomba_cache.db, keyed on (first, last,
domain). Negative caching included so misses don't re-spend within TTL.

NEVER EXPOSES KEY: TOMBA_API_KEY + TOMBA_API_SECRET read from env at
call time (not import — picks up .env edits during long runs).
"""

# ssrf-safe: all outbound URLs are hardcoded provider API endpoints

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

log = logging.getLogger(__name__)


_CACHE_PATH = Path("data") / "tomba_cache.db"
_CACHE_TTL = timedelta(hours=48)
_CACHE_LOCK = threading.Lock()
_CACHE_INITIALIZED = False

# Per-process exhausted-key set. Each tuple (key, secret) pair that 401/402/
# 403/429s gets added — for the rest of the run that pair is skipped. The
# loop falls through to the next configured pair so two accounts' free
# quotas (25/mo each) stack into ~50/mo. Resets on next process start so
# a fresh run after the monthly reset re-enables them.
_EXHAUSTED_PAIRS: set[tuple[str, str]] = set()


def _ensure_cache() -> None:
    global _CACHE_INITIALIZED
    if _CACHE_INITIALIZED:
        return
    with _CACHE_LOCK:
        if _CACHE_INITIALIZED:
            return
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(_CACHE_PATH) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS find_email (
                    cache_key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    fetched_at TEXT NOT NULL
                )
            """)
        _CACHE_INITIALIZED = True


def _cache_key(first: str, last: str, domain: str) -> str:
    return f"{first.lower().strip()}|{last.lower().strip()}|{domain.lower().strip()}"


def _cache_get(key: str) -> dict | None:
    _ensure_cache()
    with sqlite3.connect(_CACHE_PATH) as db:
        row = db.execute(
            "SELECT payload, fetched_at FROM find_email WHERE cache_key = ?",
            (key,),
        ).fetchone()
    if not row:
        return None
    payload_json, fetched_at = row
    try:
        fetched = datetime.fromisoformat(fetched_at)
    except ValueError:
        return None
    if datetime.now(timezone.utc) - fetched > _CACHE_TTL:
        return None
    try:
        return json.loads(payload_json)
    except json.JSONDecodeError:
        return None


def _cache_put(key: str, payload: dict) -> None:
    _ensure_cache()
    with sqlite3.connect(_CACHE_PATH) as db:
        db.execute(
            "INSERT OR REPLACE INTO find_email (cache_key, payload, fetched_at) VALUES (?, ?, ?)",
            (key, json.dumps(payload), datetime.now(timezone.utc).isoformat()),
        )


def _all_credential_pairs() -> list[tuple[str, str, str]]:
    """Return [(label, key, secret)] for every configured Tomba account.

    Reads TOMBA_API_KEY/_SECRET, TOMBA_API_KEY_2/_SECRET_2, _3, ...
    Stops at the first incomplete slot (key OR secret missing). Order
    matters — pair 1 is tried first, etc. Each account has 25 free
    finds/mo, so stacking N accounts gives ~25N/mo of headroom.
    """
    pairs: list[tuple[str, str, str]] = []
    primary_k = os.getenv("TOMBA_API_KEY", "").strip()
    primary_s = os.getenv("TOMBA_API_SECRET", "").strip()
    if primary_k and primary_s:
        pairs.append(("TOMBA_API_KEY", primary_k, primary_s))
    i = 2
    while True:
        k = os.getenv(f"TOMBA_API_KEY_{i}", "").strip()
        s = os.getenv(f"TOMBA_API_SECRET_{i}", "").strip()
        if not (k and s):
            break
        pairs.append((f"TOMBA_API_KEY_{i}", k, s))
        i += 1
    return pairs


def _active_credential_pairs() -> list[tuple[str, str, str]]:
    """All configured pairs minus the ones flagged exhausted this run."""
    return [
        (label, k, s)
        for (label, k, s) in _all_credential_pairs()
        if (k, s) not in _EXHAUSTED_PAIRS
    ]


def _extract_email(body: dict) -> tuple[str, str]:
    """Pull email + status from Tomba's response.

    Live-verified shape: {"data": {"email": "...", "department": "...",
    "type": "personal"|"generic", "position": "...", "country": "...",
    "score": 0-100}}. Some plans also nest under "person" — probe both.
    """
    if not isinstance(body, dict):
        return "", ""
    for container in (body, body.get("data"), body.get("person")):
        if not isinstance(container, dict):
            continue
        email = (container.get("email") or "").strip().lower()
        if email and "@" in email:
            # Tomba doesn't expose smtp_status on the basic finder — they
            # have a separate /email-verifier endpoint. Treat a finder hit
            # as "found" with confidence reflected by Tomba's `score` if
            # present (0-100); map ≥50 to "verified", else "uncertain".
            score = container.get("score")
            try:
                if isinstance(score, (int, float)) and score >= 50:
                    return email, "verified"
            except (TypeError, ValueError):
                pass
            return email, "uncertain"
    return "", ""


def find_email(
    first_name: str,
    last_name: str,
    domain: str,
    *,
    client: httpx.Client | None = None,
    company_name: str | None = None,   # accepted for interface parity; unused
    timeout: float = 20.0,
) -> tuple[str, str] | None:
    """Find an email via Tomba's v1/email-finder.

    Returns (email, status) on hit, None on miss/no-key/quota/error.
    Status is "verified" (Tomba score >=50) or "uncertain" (<50 or absent).

    When multiple TOMBA_API_KEY pairs are configured (TOMBA_API_KEY,
    TOMBA_API_KEY_2, etc.), tries each in order and rotates on quota
    exhaustion (401/402/403/429), so two 25/mo pools stack into ~50/mo.
    """
    if not (first_name and last_name and domain):
        return None
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]

    cache_k = _cache_key(first_name, last_name, domain)
    cached = _cache_get(cache_k)
    if cached is not None:
        email = (cached.get("email") or "").strip()
        status = (cached.get("status") or "").strip()
        return (email, status) if email else None

    pairs = _active_credential_pairs()
    if not pairs:
        return None

    own_client = client is None
    c = httpx.Client(timeout=timeout) if own_client else client
    payload: dict | None = None
    try:
        # Try each non-exhausted pair in order. Quota errors flag that
        # specific pair as exhausted for the run; we move to the next.
        for label, api_key, api_secret in pairs:
            try:
                r = c.get(
                    "https://api.tomba.io/v1/email-finder",
                    params={
                        "domain": domain,
                        "first_name": first_name.strip(),
                        "last_name": last_name.strip(),
                    },
                    headers={
                        "X-Tomba-Key": api_key,
                        "X-Tomba-Secret": api_secret,
                    },
                )
            except httpx.HTTPError as e:
                log.warning("tomba[%s]: %s for %s",
                            label, type(e).__name__, domain)
                return None

            if r.status_code in (401, 403):
                log.error("tomba[%s]: %d — key rejected, rotating", label, r.status_code)
                _EXHAUSTED_PAIRS.add((api_key, api_secret))
                continue
            if r.status_code in (402, 429):
                log.warning("tomba[%s]: %d — quota exhausted, rotating", label, r.status_code)
                _EXHAUSTED_PAIRS.add((api_key, api_secret))
                continue
            if r.status_code == 404:
                # Real miss for this lead — cache + return None.
                _cache_put(cache_k, {"email": "", "status": ""})
                return None
            if r.status_code != 200:
                log.info("tomba[%s]: http %d for %s/%s",
                         label, r.status_code, first_name, domain)
                return None

            try:
                payload = r.json() or {}
            except ValueError:
                return None
            from outbound import usage as billing
            # Map env-var label back to billing key_id ("primary" / "key_N").
            key_id = "primary" if label == "TOMBA_API_KEY" else label.replace("TOMBA_API_KEY_", "key_")
            billing.record_call("tomba", key_id=key_id)
            break  # success — stop trying other pairs

        if payload is None:
            log.warning("tomba: all configured pairs exhausted; %s skipped", domain)
            return None

        email, status = _extract_email(payload)
        if email:
            _cache_put(cache_k, {"email": email, "status": status})
            return email, status
        _cache_put(cache_k, {"email": "", "status": ""})
        return None
    finally:
        if own_client:
            c.close()
