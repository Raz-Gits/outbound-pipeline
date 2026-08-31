"""Prospeo email-finder — name + domain (+optional company) → email.

WHY: Third leg of the quota'd cascade. Prospeo's enrich-person endpoint
draws from yet another corpus and, unlike Snov/GetProspect, accepts a
company-name hint that materially improves match accuracy on small
biz with weak domains. 75 free credits/mo. We always pass
only_verified_email=true so a hit is something we can ship without a
re-verify trip through MailTester.

CACHE: 48-hour SQLite at data/prospeo_cache.db, keyed on
(first, last, domain). Negative caching included.

NEVER EXPOSES KEY: PROSPEO_API_KEY read from env at call time.
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


_CACHE_PATH = Path("data") / "prospeo_cache.db"
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
    return os.getenv("PROSPEO_API_KEY", "").strip()


def _extract_email(body: dict) -> tuple[str, str]:
    """Walk Prospeo's response for the first usable email + status.

    Documented shape is {"person": {...}, "company": {...}}. Email may
    sit under person.email, person.work_email, or person.emails[0]
    depending on the variant of the endpoint that's live. We probe each.
    """
    if not isinstance(body, dict):
        return "", ""
    # Some Prospeo deployments return {"response": {...}} as the wrapper.
    body = body.get("response") if isinstance(body.get("response"), dict) else body
    person = body.get("person") if isinstance(body.get("person"), dict) else body
    if not isinstance(person, dict):
        return "", ""
    # Direct fields first
    for field in ("email", "work_email", "professional_email"):
        v = person.get(field)
        if isinstance(v, str) and v.strip():
            return v.strip().lower(), "verified"
        if isinstance(v, dict):
            email = (v.get("email") or v.get("value") or "").strip().lower()
            status = (v.get("status") or v.get("verification") or "verified").lower()
            if email:
                return email, status
    # Array form
    arr = person.get("emails")
    if isinstance(arr, list):
        for item in arr:
            if isinstance(item, str) and item.strip():
                return item.strip().lower(), "verified"
            if isinstance(item, dict):
                email = (item.get("email") or item.get("value") or "").strip().lower()
                if email:
                    status = (item.get("status") or item.get("verification") or "verified").lower()
                    return email, status
    return "", ""


def find_email(
    first_name: str,
    last_name: str,
    domain: str,
    *,
    client: httpx.Client | None = None,
    company_name: str | None = None,
    timeout: float = 25.0,
) -> tuple[str, str] | None:
    """Find an email via Prospeo enrich-person.

    Returns (email, status) on hit; None on miss/no-key/quota/error.
    Always sends only_verified_email=true so a hit is shippable.
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

    payload: dict = {
        "data": {
            "first_name": first_name.strip(),
            "last_name": last_name.strip(),
            "company_website": domain,
        },
        "only_verified_email": True,
    }
    if company_name:
        payload["data"]["company_name"] = company_name.strip()

    own_client = client is None
    c = httpx.Client(timeout=timeout) if own_client else client
    try:
        try:
            r = c.post(
                "https://api.prospeo.io/enrich-person",
                headers={"X-KEY": api_key, "Content-Type": "application/json"},
                json=payload,
            )
        except httpx.HTTPError as e:
            log.warning("prospeo: %s for %s", type(e).__name__, domain)
            return None
        if r.status_code in (401, 403):
            log.warning("prospeo: %d — bad key, disabling provider", r.status_code)
            _EXHAUSTED = True
            return None
        if r.status_code in (402, 429):
            _EXHAUSTED = True
            log.warning("prospeo: %d — quota exhausted, disabling provider", r.status_code)
            return None
        if r.status_code == 404:
            _cache_put(key, {"email": "", "status": ""})
            return None
        if r.status_code != 200:
            log.info("prospeo: http %d for %s/%s", r.status_code, first_name, domain)
            return None
        try:
            body = r.json() or {}
        except ValueError:
            return None
        # Prospeo flags some endpoint variants as deprecated by returning
        # {"error": "...", "deprecated": true} with a 200. Surface once.
        if isinstance(body, dict) and body.get("error"):
            log.info("prospeo: error in body — %s", str(body.get("error"))[:120])
            return None
        from outbound import usage as billing
        billing.record_call("prospeo")
        email, status = _extract_email(body)
        if email:
            _cache_put(key, {"email": email, "status": status})
            return email, status
        _cache_put(key, {"email": "", "status": ""})
        return None
    finally:
        if own_client:
            c.close()
