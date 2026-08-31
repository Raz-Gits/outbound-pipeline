"""Anymail Finder — PAID, pay-per-FOUND email finder (person search only).

This module deliberately uses ONLY the person-search endpoint, which charges
1 credit and ONLY when a *valid* email is found (risky / not_found /
blacklisted are free, and repeat searches within 30 days are free). The
decision-maker / company-first endpoints charge 2 credits and/or resolve a
company first — far more expensive — so this module never calls them.
No name => no call.

  POST https://api.anymailfinder.com/v5.1/find-email/person
    body: {full_name | first_name+last_name} + {domain | company_name}
    auth: header  Authorization: <key>   (NO "Bearer" prefix)
    returns: {credits_charged, email, email_status, valid_email, ...}

A result is accepted ONLY when email_status == "valid" — "risky" is discarded
even though it is free, because a risky address costs sender reputation later,
which is more expensive than the credit ever was.

DOUBLE-GATED so paid spend is never accidental:
  1. ENABLE_ANYMAIL=1 in the environment, AND
  2. a key present (ANYMAIL_API_KEY, plus optional _2, _3 rotation).
Both must be true or find_email() is a no-op. A stray key in an environment
must never be enough to start spending — that is the house rule for every
paid provider in this repo.

MONTHLY SPEND CAP: a persistent atomic counter at data/anymail_billing.json
bounds *charged* credits to ANYMAIL_MONTHLY_CAP (default 2000) per calendar
month (UTC). Checked BEFORE each call and incremented by the response's
`credits_charged`. Interprocess-locked so two overlapping runs cannot lose an
increment. Because the charge is only known AFTER the call, the cap can
overshoot by at most the worker count — acceptable against a 2000 ceiling.
ANYMAIL_RUN_CAP bounds attempts per process as a runaway guard.

A 30-day result cache (data/anymail_cache.json, keyed by name+domain) skips
re-calling the same person — the API treats those repeats as free anyway,
this just saves the round-trip on re-runs. Misses are cached too.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

import httpx

from outbound._filelock import file_lock

log = logging.getLogger(__name__)

PERSON_URL = "https://api.anymailfinder.com/v5.1/find-email/person"
ACCOUNT_URL = "https://api.anymailfinder.com/v5.1/account"  # live balance (read-only, free)

_RUN_CAP = int(os.getenv("ANYMAIL_RUN_CAP", "5000") or "5000")          # attempts/process
_MONTHLY_CAP = int(os.getenv("ANYMAIL_MONTHLY_CAP", "2000") or "2000")  # charged credits/month
_CACHE_TTL_DAYS = 30

_BILLING_PATH = Path("data") / "anymail_billing.json"
_BILLING_LOCK_PATH = Path("data") / "anymail_billing.lock"
_CACHE_PATH = Path("data") / "anymail_cache.json"
_LOCK = threading.Lock()          # guards _attempts + cache writes (in-process)
_attempts = 0
_cap_logged = False


def _keys() -> list[str]:
    """ANYMAIL_API_KEY plus ANYMAIL_API_KEY_2, _3, ... in order."""
    keys: list[str] = []
    primary = (os.getenv("ANYMAIL_API_KEY") or "").strip()
    if primary:
        keys.append(primary)
    n = 2
    while True:
        k = (os.getenv(f"ANYMAIL_API_KEY_{n}") or "").strip()
        if not k:
            break
        if k not in keys:
            keys.append(k)
        n += 1
    return keys


def is_enabled() -> bool:
    """Double gate: ENABLE_ANYMAIL truthy AND a key present. Default OFF."""
    if (os.getenv("ENABLE_ANYMAIL") or "").strip().lower() not in ("1", "true", "yes", "on"):
        return False
    return bool(_keys())


# ---------- monthly billing ledger ----------

def _month() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _ledger() -> dict:
    """{'month': 'YYYY-MM', 'credits': N} for the CURRENT month.

    Fails CLOSED on a corrupt file: a MISSING file is a legitimate empty
    month, but an unparseable one pins the counter AT cap so the spend gate
    REFUSES rather than reading 0 and spending unbounded. When money and
    correctness conflict, the ledger errs on the side of not spending."""
    fresh = {"month": _month(), "credits": 0}
    if not _BILLING_PATH.exists():
        return fresh
    try:
        d = json.loads(_BILLING_PATH.read_text())
        if d.get("month") != _month():
            return fresh
        return {"month": d["month"], "credits": int(d.get("credits", 0) or 0)}
    except Exception as e:
        log.error("anymail: billing ledger %s is unreadable (%s) — failing "
                  "CLOSED (refusing paid calls) until it is fixed by hand",
                  _BILLING_PATH, e)
        return {"month": _month(), "credits": _MONTHLY_CAP, "corrupt": True}


def credits_used() -> int:
    """This month's charged credits recorded through this module."""
    return int(_ledger()["credits"])


def monthly_cap() -> int:
    return _MONTHLY_CAP


def credits_left(client: httpx.Client | None = None) -> int | None:
    """LIVE remaining credits from the Anymail account (authoritative), or
    None on error. Read-only GET — free, charges nothing. The local ledger
    only counts spend routed through this module, so it can drift below the
    truth; prefer this for "how are we doing" checks."""
    keys = _keys()
    if not keys:
        return None
    owns = client is None
    if owns:
        client = httpx.Client(timeout=20)
    try:
        r = client.get(ACCOUNT_URL, headers={"Authorization": keys[0]}, timeout=20)
        if r.status_code != 200:
            return None
        return int(r.json().get("credits_left"))
    except Exception:
        return None
    finally:
        if owns:
            client.close()


def _record_credits(n: int) -> None:
    """Add n charged credits to this month's ledger.

    Fails LOUD, never silent: if the write raises, real money was spent that
    could not be persisted, so the monthly cap now under-counts. That is a
    cost-safety alarm (log.error), not a debug line — but it must not
    propagate and abort the enrichment either, or the lead would be lost on
    top of the money."""
    if n <= 0:
        return
    try:
        with file_lock(_BILLING_LOCK_PATH):
            led = _ledger()
            led["credits"] = int(led["credits"]) + int(n)
            led.pop("corrupt", None)
            _BILLING_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = _BILLING_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(led, indent=2))
            os.replace(tmp, _BILLING_PATH)
    except OSError as e:
        log.error("anymail: SPENT %d credit(s) but FAILED to record them (%s) "
                  "— monthly cap now under-counts; reconcile against the "
                  "Anymail dashboard", n, e)


# ---------- 30-day result cache ----------

def _cache_key(full_name: str, domain: str, company: str) -> str:
    raw = f"{full_name.lower()}|{(domain or company).lower()}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _cache_get(key: str) -> dict | None:
    """Cached find for this key if <= 30 days old, else None. A cached MISS
    is a record with email="" so re-runs skip the call entirely."""
    try:
        rec = json.loads(_CACHE_PATH.read_text()).get(key)
    except Exception:
        return None
    if not rec:
        return None
    try:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(rec["ts"])).days
    except Exception:
        return None
    if age > _CACHE_TTL_DAYS:
        return None
    return {
        "email": rec.get("email") or "",
        "found_company": rec.get("found_company") or "",
        "found_title": rec.get("found_title") or "",
    }


def _cache_put(key: str, email: str, status: str,
               found_company: str = "", found_title: str = "") -> None:
    """Best-effort persistent cache write."""
    try:
        with _LOCK:
            try:
                data = json.loads(_CACHE_PATH.read_text())
            except Exception:
                data = {}
            data[key] = {"email": email, "status": status,
                         "found_company": found_company,
                         "found_title": found_title,
                         "ts": datetime.now(timezone.utc).isoformat()}
            _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = _CACHE_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data))
            os.replace(tmp, _CACHE_PATH)
    except OSError as e:
        log.warning("anymail cache write failed: %s", e)


# ---------- response parsing ----------

def _base_domain(host: str) -> str:
    host = (host or "").lower().strip()
    if host.startswith("www."):          # removeprefix, NOT lstrip (lstrip strips chars)
        host = host[4:]
    return host


def _domain_core(host: str) -> str:
    """The second-level label of a domain: examplebank.com -> 'examplebank'."""
    h = _base_domain(host)
    return h.split(".")[0] if h else ""


def _domain_matches(email_domain: str, requested: str) -> bool:
    """True if the found email's domain is the SAME COMPANY as the one asked
    for. Anymail can return the person's email at a different domain; that is
    either (a) a genuine job change (-> treat as cross-company), or (b) the
    same company on an alias/rebrand domain (a company using acme.io mail on
    an acmegroup.com website, say). We accept (b) as same-company.

    Same-company when: equal registrable domain, OR sub/parent domain, OR one
    domain CORE is a prefix/suffix of the other (rebrand / .com-vs-.org /
    added 'go'/'group'/'partners') with the shorter core >= 5 chars so
    unrelated short tokens don't merge. A short common prefix alone (two
    different 'summit*' firms, say) is NOT enough — those stay cross-company
    for review."""
    a, b = _base_domain(email_domain), _base_domain(requested)
    if not a or not b:
        return True  # nothing to compare against -> don't block
    if a == b or a.endswith("." + b) or b.endswith("." + a):
        return True
    ca, cb = _domain_core(a), _domain_core(b)
    if ca and cb and min(len(ca), len(cb)) >= 5:
        lo, hi = sorted((ca, cb), key=len)
        if hi.startswith(lo) or hi.endswith(lo):
            return True
    return False


_COMPANY_STOP = {"inc", "llc", "ltd", "corp", "co", "company", "group", "the",
                 "pllc", "pc", "lp", "llp", "holdings", "partners"}


def _norm_company(name: str | None) -> str:
    """Core label of a company name for same-vs-different comparison, dropping
    legal suffixes/noise: 'Acme Building Services, Inc.' -> 'acmebuildingservices'."""
    toks = [t for t in re.findall(r"[a-z0-9]+", (name or "").lower())
            if t not in _COMPANY_STOP]
    return "".join(toks)


def is_job_change(found_company: str | None, found_domain: str | None,
                  scraped_company: str | None, scraped_domain: str | None) -> bool:
    """Positive evidence the person is now at a DIFFERENT company than the one
    scraped — the ONLY case set aside as 'cross-company'.

    Conservative on purpose: a FALSE cross sidelines a same-company email that
    was already paid for. The dominant real-world case is a company whose
    EMAIL domain simply differs from its WEBSITE domain (jane@acmemail.com at
    Acme Building Services, say) — a domain mismatch alone is NOT a job
    change. A genuinely differing company NAME is required.

    Same company when the found company name OR found email-domain core
    overlaps the scraped company name OR scraped domain core (equal, or
    containment with the shorter token >= 5 chars). An empty found company
    name => cannot confirm a move => NOT a job change."""
    fc, fd = _norm_company(found_company), _domain_core(found_domain or "")
    sc, sd = _norm_company(scraped_company), _domain_core(scraped_domain or "")
    found_toks = [t for t in (fc, fd) if t]
    scraped_toks = [t for t in (sc, sd) if t]
    if not found_toks or not scraped_toks:
        return False
    for ft in found_toks:
        for st in scraped_toks:
            if ft == st or (min(len(ft), len(st)) >= 5 and (ft in st or st in ft)):
                return False
    # No identity overlap. Only call it a move when there is an actual company
    # NAME — a bare differing domain is too often the same company on another
    # domain.
    return bool(fc)


def _parse(data: dict) -> dict:
    """Parse the v5.1 person response. Never raises. Returns a dict:
      email          valid email, or "" when not status=="valid"
      status         the API email_status (valid / risky / not_found / ...)
      credits        credits_charged (so the ledger matches what was billed)
      found_company  person_company_name, when the source exposes it
      found_title    person_job_title, same
    ONLY a valid email is accepted; risky/not_found/blacklisted -> email=""."""
    if not isinstance(data, dict):
        return {"email": "", "status": "error", "credits": 0,
                "found_company": "", "found_title": ""}
    status = str(data.get("email_status") or "").strip().lower()
    valid = str(data.get("valid_email") or "").strip().lower()
    return {
        "email": valid if (status == "valid" and "@" in valid) else "",
        "status": status or "not_found",
        "credits": int(data.get("credits_charged") or 0),
        "found_company": str(data.get("person_company_name") or "").strip(),
        "found_title": str(data.get("person_job_title") or "").strip(),
    }


def find_email(
    first: str | None,
    last: str | None,
    domain: str | None,
    *,
    client: httpx.Client | None = None,
    company_name: str | None = None,
    flag_cross_company: bool = True,
) -> dict | None:
    """Person-search finder. Returns a dict on a valid hit, else None:
      {email, status: "valid" | "cross_company", found_domain, found_company,
       found_title}

    No-op unless is_enabled(), a NAME is present (person search REQUIRES it —
    never falls back to the pricier company/decision-maker search), and a
    domain or company_name exists. Bounded by the per-process run cap AND the
    persistent monthly credit cap.

    flag_cross_company (default True): when the valid email's company is not
    the requested one, the person changed jobs — status "cross_company" so
    the caller can set it aside for separate review instead of merging it
    (the scraped company context is stale). The result is still returned;
    the provider charges the credit regardless of where the person now works.
    """
    global _attempts, _cap_logged
    if not is_enabled():
        return None

    full_name = " ".join(p for p in ((first or "").strip(), (last or "").strip()) if p).strip()
    company = (company_name or "").strip()
    dom = (domain or "").strip()
    # Person search needs a name AND a company signal. No name => skip (never
    # call the 2-credit decision-maker endpoint).
    if not full_name or not (dom or company):
        return None

    def _result(email: str, found_company: str, found_title: str) -> dict | None:
        """Build the result dict (cache-hit and fresh paths share this so they
        cannot diverge). Flags cross-company; never discards a valid email."""
        if not email:
            return None
        found_dom = email.rsplit("@", 1)[-1]
        cross = bool(flag_cross_company
                     and is_job_change(found_company, found_dom, company, dom))
        if cross:
            log.info("anymail: job-change hit %s — scraped %s/%s, now %s at %s "
                     "— set aside for the job-changers list", email,
                     company or "?", dom or "?", found_company or "?", found_dom)
        return {
            "email": email,
            "status": "cross_company" if cross else "valid",
            "found_domain": found_dom,
            "found_company": found_company,
            "found_title": found_title,
        }

    key_id = _cache_key(full_name, dom, company)
    cached = _cache_get(key_id)
    if cached is not None:
        return _result(cached["email"], cached["found_company"], cached["found_title"])

    # Monthly money cap (persistent) + runaway cap (per process).
    with _LOCK:
        if credits_used() >= _MONTHLY_CAP:
            if not _cap_logged:
                log.warning("anymail: MONTHLY CAP %d credits reached for %s — refusing",
                            _MONTHLY_CAP, _month())
                _cap_logged = True
            return None
        if _attempts >= _RUN_CAP:
            return None
        _attempts += 1

    payload: dict[str, str] = {"full_name": full_name}
    if dom:
        payload["domain"] = dom          # domain is most accurate; preferred
    if company:
        payload["company_name"] = company

    owns_client = client is None
    if owns_client:
        client = httpx.Client(timeout=180, transport=httpx.HTTPTransport(retries=0))
    try:
        for key in _keys():
            try:
                r = client.post(
                    PERSON_URL, json=payload,
                    headers={"Authorization": key, "Content-Type": "application/json"},
                    timeout=180,  # docs: real-time SMTP, up to 180s
                )
            except Exception as e:
                # Do NOT rotate to another key on a network error / timeout: a
                # 180s SMTP search can time out on the RESPONSE after the
                # provider already found+charged, so re-POSTing with key #2
                # would double charge. Bail; the lead can be re-run later
                # (cache / 30-day-free repeat).
                log.warning("anymail request error (%s): %s — not retrying (a "
                            "timeout may have still charged)",
                            dom or company, type(e).__name__)
                return None
            # Auth / payment / rate issues -> rotate to the next account's key.
            if r.status_code in (401, 402, 403, 429):
                log.info("anymail key unavailable (HTTP %s) — rotating", r.status_code)
                continue
            if r.status_code >= 400:
                # 400 bad-request etc. -> a clean (free) miss; don't retry.
                return None
            try:
                p = _parse(r.json())
            except Exception:
                return None
            if p["credits"]:
                _record_credits(p["credits"])
            _cache_put(key_id, p["email"], p["status"],
                       p["found_company"], p["found_title"])
            return _result(p["email"], p["found_company"], p["found_title"])
        return None
    finally:
        if owns_client:
            client.close()
