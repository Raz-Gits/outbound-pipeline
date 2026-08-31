"""Snov.io email-finder — name + domain → email, OAuth-gated.

WHY: Snov sits between MailTester (free per-call but requires we already
*have* an email candidate to verify) and Apollo (paid per match). When
team-page extraction gave us first+last but our pattern matcher's
candidates all bounce, Snov's "emails-by-domain-by-name" endpoint will
sometimes return the address directly (it draws from a different corpus
than Hunter — chiefly LinkedIn signal data). 50 free credits/mo per
(client_id, client_secret) pair burns first before Apollo is touched.

QUOTA: 1 credit per email returned with smtp_status in {valid, unknown}.
We accept both since MailTester downstream re-verifies anyway.

CACHE: 48-hour SQLite at data/snov_cache.db, keyed on (first, last,
domain). Avoids duplicate spend on re-runs and backfills.

NEVER EXPOSES KEY: SNOV_API_ID + SNOV_API_SECRET read from env at call
time so .env edits during long runs are picked up.
"""

# ssrf-safe: all outbound URLs are hardcoded provider API endpoints

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

log = logging.getLogger(__name__)


_CACHE_PATH = Path("data") / "snov_cache.db"
_CACHE_TTL = timedelta(hours=48)
_CACHE_LOCK = threading.Lock()
_CACHE_INITIALIZED = False

# Per-process token cache. Snov tokens last 1h; we re-mint when the cached
# token is within 60s of its expiry to avoid mid-call 401s.
_TOKEN: dict[str, float | str] = {"value": "", "expires_at": 0.0}
_TOKEN_LOCK = threading.Lock()

# One-shot quota flag: when Snov returns "not_enough_credits" we stop
# calling for the rest of the process to avoid log noise + wasted RTTs.
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


def _credentials() -> tuple[str, str] | None:
    cid = os.getenv("SNOV_API_ID", "").strip()
    sec = os.getenv("SNOV_API_SECRET", "").strip()
    if not (cid and sec):
        return None
    return cid, sec


def _get_token(c: httpx.Client) -> str | None:
    """Mint or reuse an OAuth token. Returns None if creds missing or
    auth fails — caller treats as "skip provider"."""
    creds = _credentials()
    if not creds:
        return None
    cid, sec = creds
    now = time.time()
    with _TOKEN_LOCK:
        cached = _TOKEN.get("value")
        exp = float(_TOKEN.get("expires_at") or 0)
        if cached and now < exp - 60:
            return str(cached)
        try:
            r = c.post(
                "https://api.snov.io/v1/oauth/access_token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": cid,
                    "client_secret": sec,
                },
                timeout=20.0,
            )
        except httpx.HTTPError as e:
            log.warning("snov: token fetch %s", type(e).__name__)
            return None
        if r.status_code != 200:
            log.warning("snov: token http %d", r.status_code)
            return None
        try:
            data = r.json() or {}
        except ValueError:
            return None
        tok = (data.get("access_token") or "").strip()
        ttl = int(data.get("expires_in") or 3600)
        if not tok:
            return None
        _TOKEN["value"] = tok
        _TOKEN["expires_at"] = now + ttl
        return tok


def find_email(
    first_name: str,
    last_name: str,
    domain: str,
    *,
    client: httpx.Client | None = None,
    company_name: str | None = None,    # accepted for interface parity; unused
    timeout: float = 20.0,
    max_poll_seconds: float = 30.0,
) -> tuple[str, str] | None:
    """Find an email via Snov's name+domain endpoint.

    Returns (email, smtp_status) on hit, None on miss/error/no-key/quota.
    smtp_status is Snov's own ("valid"|"unknown"|...) — caller decides
    whether to re-verify with MailTester.
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
        status = (cached.get("smtp_status") or "").strip()
        return (email, status) if email else None

    if not _credentials():
        return None

    own_client = client is None
    c = httpx.Client(timeout=timeout) if own_client else client
    try:
        token = _get_token(c)
        if not token:
            return None
        headers = {"Authorization": f"Bearer {token}"}

        # Step 1 — start the async job. Single-row payload; we never batch
        # at this layer because the cascade calls us per-lead and caching
        # would get murky with multi-lead responses.
        try:
            start = c.post(
                "https://api.snov.io/v2/emails-by-domain-by-name/start",
                headers=headers,
                json={"rows": [{
                    "first_name": first_name.strip(),
                    "last_name": last_name.strip(),
                    "domain": domain,
                }]},
            )
        except httpx.HTTPError as e:
            log.warning("snov start: %s", type(e).__name__)
            return None
        if start.status_code == 401:
            # Token went stale mid-call (rare but possible). Drop it and bail.
            _TOKEN["value"] = ""
            _TOKEN["expires_at"] = 0.0
            log.warning("snov start: 401 — token rejected")
            return None
        if start.status_code == 402 or start.status_code == 403:
            _EXHAUSTED = True
            log.warning("snov start: %d — quota exhausted, disabling provider", start.status_code)
            return None
        if start.status_code != 200:
            log.info("snov start: http %d for %s/%s", start.status_code, first_name, domain)
            return None
        try:
            task_hash = (start.json() or {}).get("task_hash") or ""
        except ValueError:
            return None
        if not task_hash:
            return None

        # Step 2 — poll. Snov's pipeline is usually sub-5s for one row but
        # we cap at max_poll_seconds to stay sync-friendly inside the cascade.
        deadline = time.time() + max_poll_seconds
        backoff = 1.0
        result_payload: dict | None = None
        while time.time() < deadline:
            try:
                rr = c.get(
                    "https://api.snov.io/v2/emails-by-domain-by-name/result",
                    headers=headers,
                    params={"task_hash": task_hash},
                )
            except httpx.HTTPError as e:
                log.warning("snov poll: %s", type(e).__name__)
                return None
            if rr.status_code != 200:
                log.info("snov poll: http %d", rr.status_code)
                return None
            try:
                body = rr.json() or {}
            except ValueError:
                return None
            status = (body.get("status") or "").lower()
            if status == "completed":
                result_payload = body
                from outbound import usage as billing
                billing.record_call("snov")
                break
            if status == "not_enough_credits":
                _EXHAUSTED = True
                log.warning("snov poll: not_enough_credits — disabling provider")
                return None
            # in_progress / queued — sleep and try again
            time.sleep(backoff)
            backoff = min(backoff * 1.5, 4.0)
        if result_payload is None:
            log.info("snov: poll timeout for %s/%s", first_name, domain)
            return None

        rows = result_payload.get("data") or []
        # Each row should map to one of our input rows — we sent one, take
        # the first that has a usable email.
        for row in rows:
            email = (row.get("email") or "").strip().lower()
            if not email:
                continue
            smtp_status = (row.get("smtp_status") or "").strip().lower()
            # Cache hit (positive). We accept valid + unknown — MailTester
            # downstream is the source of truth on deliverability.
            _cache_put(key, {"email": email, "smtp_status": smtp_status})
            return email, smtp_status
        # Negative cache too: avoids re-querying for misses within TTL.
        _cache_put(key, {"email": "", "smtp_status": ""})
        return None
    finally:
        if own_client:
            c.close()
