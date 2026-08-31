"""Hunter.io enrichment fallback — domain search + email verification.

WHY: When team-page extraction returns no decision-maker for a domain we DO
have a verified domain for (the bulk of our "domain found, no name" pile),
Hunter's domain-search endpoint often returns:
  - The email pattern that domain uses (e.g. "{first}.{last}")
  - A list of named employees Hunter has seen in public sources

Either gets us unstuck: a name we can pair with the existing MailTester
chain, or — better — a verified email Hunter has already confirmed.

QUOTA (Free plan, verified live 2026-05-05):
  - 50 domain-search calls/month
  - 100 email-verification calls/month
  - Resets monthly

CACHE: 24-hour SQLite cache keyed by domain. Hits don't count against
quota. Stretches the 50/mo budget across re-runs and backfills.

NEVER EXPOSES KEY: API key read once from $HUNTER_API_KEY at import. Not
logged, not embedded in errors.
"""

# ssrf-safe: all outbound URLs are hardcoded provider API endpoints

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

log = logging.getLogger(__name__)


_CACHE_PATH = Path("data") / "hunter_cache.db"
_CACHE_TTL = timedelta(hours=24)
_CACHE_LOCK = threading.Lock()
_CACHE_INITIALIZED = False


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
                CREATE TABLE IF NOT EXISTS domain_search (
                    domain TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    fetched_at TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS email_verify (
                    email TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    fetched_at TEXT NOT NULL
                )
            """)
        _CACHE_INITIALIZED = True


def _cache_get(table: str, key: str) -> dict | None:
    _ensure_cache()
    with sqlite3.connect(_CACHE_PATH) as db:
        row = db.execute(
            f"SELECT payload, fetched_at FROM {table} WHERE {('domain' if table == 'domain_search' else 'email')} = ?",
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


def _cache_put(table: str, key: str, payload: dict) -> None:
    _ensure_cache()
    col = "domain" if table == "domain_search" else "email"
    with sqlite3.connect(_CACHE_PATH) as db:
        db.execute(
            f"INSERT OR REPLACE INTO {table} ({col}, payload, fetched_at) VALUES (?, ?, ?)",
            (key, json.dumps(payload), datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class HunterCandidate:
    first_name: str
    last_name: str
    email: str
    position: str
    confidence: int             # 0-100, Hunter's own score
    verification_status: str    # 'verified' | 'webmail' | 'invalid' | 'unknown'


@dataclass
class HunterDomainResult:
    domain: str
    pattern: str | None         # e.g. "{first}.{last}" — Hunter's inferred format
    organization: str | None
    candidates: list[HunterCandidate]


# --- Multi-key rotation ----------------------------------------------------
# Free Hunter accounts cap at 50 searches/month per key. We support multiple
# keys (HUNTER_API_KEY, HUNTER_API_KEY_2, _3, …) and rotate through them when
# one returns 429 (quota exhausted). Skip-list is per-process — keys flagged
# 429 in one run won't be retried until the script restarts.

_EXHAUSTED_KEYS: set[str] = set()


def _all_api_keys() -> list[tuple[str, str]]:
    """Return [(env_var_name, key)] for all configured Hunter keys.

    Reads HUNTER_API_KEY, HUNTER_API_KEY_2, _3, …. Stops at the first
    missing slot. Order matters — KEY1 is tried first, etc.
    """
    keys: list[tuple[str, str]] = []
    primary = os.getenv("HUNTER_API_KEY", "").strip()
    if primary:
        keys.append(("HUNTER_API_KEY", primary))
    i = 2
    while True:
        name = f"HUNTER_API_KEY_{i}"
        v = os.getenv(name, "").strip()
        if not v:
            break
        keys.append((name, v))
        i += 1
    return keys


def _active_api_keys() -> list[tuple[str, str]]:
    """Configured keys minus the ones flagged exhausted this run."""
    return [(n, k) for (n, k) in _all_api_keys() if k not in _EXHAUSTED_KEYS]


def _check_response_quota(resp: httpx.Response, key_name: str) -> None:
    """Hunter returns rate-limit info in headers. Log when quota is low."""
    remaining = resp.headers.get("x-ratelimit-remaining")
    if remaining and remaining.isdigit() and int(remaining) <= 5:
        log.warning("hunter[%s] quota low: %s remaining", key_name, remaining)


def _proxy_url() -> str | None:
    """Return PROXY_URL env normalized to http:// form, or None.

    Routing Hunter through a proxy reduces IP-fingerprinting when multiple
    keys hit Hunter's API back-to-back from one machine. Each call still
    uses the original keys; only the network egress IP rotates.
    """
    raw = os.getenv("PROXY_URL", "").strip()
    if not raw:
        return None
    return raw if raw.startswith(("http://", "https://")) else f"http://{raw}"


def domain_search(
    domain: str,
    *,
    client: httpx.Client | None = None,
    limit: int = 10,
    timeout: float = 20.0,
    use_proxy: bool = True,
) -> HunterDomainResult | None:
    """Look up a domain on Hunter. Returns None on no-key, no-result, or error.

    Cache hits are free; misses cost 1 search against the monthly quota.
    """
    if not domain:
        return None
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]

    cached = _cache_get("domain_search", domain)
    if cached is not None:
        log.debug("hunter cache hit: %s", domain)
        return _parse_domain_payload(domain, cached)

    keys = _active_api_keys()
    if not keys:
        log.debug("hunter: no usable API keys (all exhausted or unset), skipping")
        return None

    own_client = client is None
    if own_client:
        proxy = _proxy_url() if use_proxy else None
        c = httpx.Client(timeout=timeout, proxy=proxy)
    else:
        c = client
    payload = None
    try:
        # Try each non-exhausted key in order. A 429 marks that key for
        # the rest of the run; we move on to the next.
        for key_name, key in keys:
            try:
                r = c.get(
                    "https://api.hunter.io/v2/domain-search",
                    params={"domain": domain, "limit": limit, "api_key": key},
                )
            except (httpx.HTTPError, ValueError) as e:
                log.warning("hunter[%s]: %s for %s", key_name, type(e).__name__, domain)
                return None
            _check_response_quota(r, key_name)
            if r.status_code == 401:
                log.error("hunter[%s]: 401 — bad API key, skipping", key_name)
                _EXHAUSTED_KEYS.add(key)
                continue
            if r.status_code == 429:
                log.warning("hunter[%s]: 429 — quota exhausted, rotating", key_name)
                _EXHAUSTED_KEYS.add(key)
                continue
            if r.status_code >= 500:
                log.warning("hunter[%s]: %d server error for %s", key_name, r.status_code, domain)
                return None
            if r.status_code != 200:
                # 4xx other than auth/quota (e.g. 400 invalid domain) — give up on this domain
                log.info("hunter[%s]: %d for %s; skipping", key_name, r.status_code, domain)
                return None
            try:
                payload = r.json()
                log.debug("hunter[%s]: 200 for %s", key_name, domain)
            except ValueError:
                return None
            from outbound import usage as billing
            billing.record_call("hunter")
            break  # success — stop trying other keys
    finally:
        if own_client:
            c.close()

    if payload is None:
        log.warning("hunter: all keys exhausted; %s skipped", domain)
        return None

    _cache_put("domain_search", domain, payload)
    return _parse_domain_payload(domain, payload)


def _parse_domain_payload(domain: str, payload: dict) -> HunterDomainResult | None:
    data = (payload or {}).get("data") or {}
    if not data:
        return None
    pattern = data.get("pattern") or None
    organization = data.get("organization") or None
    cands_raw = data.get("emails") or []
    candidates: list[HunterCandidate] = []
    for e in cands_raw:
        first = (e.get("first_name") or "").strip()
        last = (e.get("last_name") or "").strip()
        email = (e.get("value") or "").strip()
        if not (email and first and last):
            continue
        candidates.append(HunterCandidate(
            first_name=first,
            last_name=last,
            email=email,
            position=(e.get("position") or "").strip(),
            confidence=int(e.get("confidence") or 0),
            verification_status=(e.get("verification") or {}).get("status") or "unknown",
        ))
    return HunterDomainResult(
        domain=domain,
        pattern=pattern,
        organization=organization,
        candidates=candidates,
    )


def verify_email(
    email: str,
    *,
    client: httpx.Client | None = None,
    timeout: float = 20.0,
    use_proxy: bool = True,
) -> dict | None:
    """Hunter's email verifier. Returns the raw `data` block on success, or
    None on no-key/error. Cache hits are free.
    """
    if not email:
        return None
    email = email.lower().strip()

    cached = _cache_get("email_verify", email)
    if cached is not None:
        return (cached or {}).get("data") or None

    keys = _active_api_keys()
    if not keys:
        return None

    own_client = client is None
    if own_client:
        proxy = _proxy_url() if use_proxy else None
        c = httpx.Client(timeout=timeout, proxy=proxy)
    else:
        c = client
    payload = None
    try:
        for key_name, key in keys:
            try:
                r = c.get(
                    "https://api.hunter.io/v2/email-verifier",
                    params={"email": email, "api_key": key},
                )
            except (httpx.HTTPError, ValueError) as e:
                log.warning("hunter verifier[%s]: %s", key_name, type(e).__name__)
                return None
            _check_response_quota(r, key_name)
            if r.status_code in (401, 429):
                log.warning("hunter verifier[%s]: %d, rotating", key_name, r.status_code)
                _EXHAUSTED_KEYS.add(key)
                continue
            if r.status_code >= 500 or r.status_code != 200:
                log.warning("hunter verifier[%s]: %d", key_name, r.status_code)
                return None
            try:
                payload = r.json()
            except ValueError:
                return None
            from outbound import usage as billing
            billing.record_call("hunter")
            break
    finally:
        if own_client:
            c.close()
    if payload is None:
        return None

    _cache_put("email_verify", email, payload)
    return (payload or {}).get("data") or None


def pick_best_candidate(
    result: HunterDomainResult,
    *,
    role_hint: str | None = None,
) -> HunterCandidate | None:
    """Rank Hunter candidates and pick the most-likely decision-maker.

    Heuristic:
      1. Verified-status emails first
      2. Decision-maker titles next (CEO/owner/founder/director/principal)
      3. Highest confidence score within tie groups
    """
    if not result or not result.candidates:
        return None

    DECISION_TITLES = (
        "ceo", "cfo", "coo", "cto", "founder", "owner", "president",
        "principal", "managing", "director", "head of", "vp ", "chief",
        "executive", "partner",
    )

    def _rank(c: HunterCandidate) -> tuple[int, int, int]:
        title_l = c.position.lower()
        verified = 0 if c.verification_status == "verified" else 1
        decision = 0 if any(t in title_l for t in DECISION_TITLES) else 1
        return (verified, decision, -c.confidence)

    return min(result.candidates, key=_rank)
