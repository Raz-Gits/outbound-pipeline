"""GetProspect email-finder — name + domain → email, single-shot GET.

WHY: Cheapest of the three quota'd providers to call (no OAuth, no
polling) so it's a tight loop in the cascade. 50 free credits/mo per
key. Same role as Snov: catch leads where MailTester's pattern guesses
all bounce but the address is sittin' in someone else's corpus.

CACHE: 48-hour SQLite at data/getprospect_cache.db, keyed on
(first, last, domain). Negative caching included so misses don't
re-spend within TTL.

NEVER EXPOSES KEY: GETPROSPECT_API_KEY read from env at call time.
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


_CACHE_PATH = Path("data") / "getprospect_cache.db"
_CACHE_TTL = timedelta(hours=48)
_CACHE_LOCK = threading.Lock()
_CACHE_INITIALIZED = False

_EXHAUSTED = False


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


def _api_key() -> str:
    return os.getenv("GETPROSPECT_API_KEY", "").strip()


def _extract_email(body: dict) -> tuple[str, str]:
    """Pull an email + status out of GetProspect's response shape.

    The v2/email-finder body is undocumented past "you'll get the email if
    found" — so we probe a few known shapes. If the API ever changes its
    field names this is the only place that needs updating.
    """
    if not isinstance(body, dict):
        return "", ""
    # Common shapes seen in the wild for GetProspect / similar providers:
    #   { "email": "...", "status": "valid" }
    #   { "data": { "email": "...", ... } }
    #   { "result": { "email": "...", ... } }
    for container in (body, body.get("data"), body.get("result"), body.get("person")):
        if not isinstance(container, dict):
            continue
        email = (container.get("email") or "").strip().lower()
        if email:
            status = (
                container.get("status")
                or container.get("smtp_status")
                or container.get("verification")
                or ""
            )
            if isinstance(status, dict):
                status = status.get("status") or ""
            return email, str(status).lower()
    # Fallback: array form { "emails": [{"email": "...", "status": "..."}] }
    arr = body.get("emails")
    if isinstance(arr, list) and arr:
        first = arr[0]
        if isinstance(first, dict):
            email = (first.get("email") or first.get("value") or "").strip().lower()
            status = (first.get("status") or first.get("smtp_status") or "").lower()
            if email:
                return email, status
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
    """Find an email via GetProspect.

    Returns (email, status) on hit, None on miss/no-key/quota/error.
    """
    global _EXHAUSTED
    if _EXHAUSTED:
        return None
    if not (first_name and last_name and domain):
        return None
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]

    key = _cache_key(first_name, last_name, domain)
    cached = _cache_get(key)
    if cached is not None:
        email = (cached.get("email") or "").strip()
        status = (cached.get("status") or "").strip()
        return (email, status) if email else None

    api_key = _api_key()
    if not api_key:
        return None

    own_client = client is None
    c = httpx.Client(timeout=timeout) if own_client else client
    try:
        try:
            r = c.get(
                "https://api.getprospect.com/v2/email-finder",
                params={
                    "domain": domain,
                    "full_name": f"{first_name.strip()} {last_name.strip()}".strip(),
                },
                headers={"X-API-KEY": api_key},
            )
        except httpx.HTTPError as e:
            log.warning("getprospect: %s for %s", type(e).__name__, domain)
            return None
        if r.status_code == 401 or r.status_code == 403:
            log.warning("getprospect: %d — bad/expired key, disabling provider", r.status_code)
            _EXHAUSTED = True
            return None
        if r.status_code == 402 or r.status_code == 429:
            _EXHAUSTED = True
            log.warning("getprospect: %d — quota exhausted, disabling provider", r.status_code)
            return None
        if r.status_code == 404:
            # Some providers use 404 for "no match" — treat as miss + cache it.
            _cache_put(key, {"email": "", "status": ""})
            return None
        if r.status_code != 200:
            log.info("getprospect: http %d for %s/%s", r.status_code, first_name, domain)
            return None
        try:
            body = r.json() or {}
        except ValueError:
            return None
        from outbound import usage as billing
        billing.record_call("getprospect")
        email, status = _extract_email(body)
        if email:
            _cache_put(key, {"email": email, "status": status})
            return email, status
        _cache_put(key, {"email": "", "status": ""})
        return None
    finally:
        if own_client:
            c.close()
