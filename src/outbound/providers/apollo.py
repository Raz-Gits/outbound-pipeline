"""Apollo.io API client — search and people/match.

⚠️ Billing warning, learned empirically: on some plans Apollo BILLS for
endpoints its documentation describes as free, including
/mixed_companies/search and /mixed_people/api_search, and /usage_stats can
404 so spend cannot be auto-tracked. Verify billing behaviour on YOUR plan
with a single test call before trusting any endpoint to be free.

Every method below therefore routes through CreditBudget.try_spend() so any
Apollo call is gated by the per-run + daily caps, regardless of what the
docs claim.
"""

# ssrf-safe: all outbound URLs are hardcoded provider API endpoints

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

BASE = "https://api.apollo.io/api/v1"

DEFAULT_TITLES = [
    "CEO", "Chief Executive Officer", "Founder", "Co-Founder", "Owner",
    "President", "Managing Partner", "Managing Director",
    "COO", "Chief Operating Officer", "Operations Manager",
    "Director of Operations", "Head of Operations",
]


_DAILY_STATE_FILE = Path("data") / "apollo_daily.json"


def _load_daily_spent(state_path: Path) -> int:
    """Read today's already-spent credits from the on-disk daily ledger.
    Returns 0 if the file doesn't exist or is for a different day."""
    if not state_path.exists():
        return 0
    try:
        data = json.loads(state_path.read_text())
        if data.get("date") == date.today().isoformat():
            return int(data.get("spent", 0))
    except (json.JSONDecodeError, ValueError, OSError):
        pass
    return 0


def _persist_daily_spent(state_path: Path, spent: int) -> None:
    """Write today's daily total back to the ledger so the next run sees it."""
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps({
            "date": date.today().isoformat(),
            "spent": int(spent),
        }))
    except OSError as e:
        log.warning("Could not persist Apollo daily ledger: %s", e)


class CreditBudget:
    """Thread-safe counter that enforces TWO limits:
      - per-run cap (`limit`) — refuses any spend past N this process
      - per-day cap (`daily_cap`, optional) — refuses spend that would push
        the cross-run cumulative day total past M. Persisted to a small
        JSON file so it survives restart.
    """

    def __init__(self, limit: int, daily_cap: int | None = None,
                 state_path: Path | None = None):
        self.limit = max(0, int(limit))
        self.spent = 0  # this run only
        self.daily_cap = max(0, int(daily_cap)) if daily_cap is not None else None
        self.state_path = state_path or _DAILY_STATE_FILE
        self.daily_spent_at_start = (
            _load_daily_spent(self.state_path) if self.daily_cap is not None else 0
        )
        self._lock = threading.Lock()

    def try_spend(self, n: int = 1) -> bool:
        with self._lock:
            if self.spent + n > self.limit:
                return False
            if self.daily_cap is not None:
                if self.daily_spent_at_start + self.spent + n > self.daily_cap:
                    return False
            self.spent += n
            if self.daily_cap is not None:
                _persist_daily_spent(
                    self.state_path,
                    self.daily_spent_at_start + self.spent,
                )
            return True

    @property
    def remaining(self) -> int:
        run_remaining = max(0, self.limit - self.spent)
        if self.daily_cap is None:
            return run_remaining
        day_remaining = max(0, self.daily_cap - self.daily_spent_at_start - self.spent)
        return min(run_remaining, day_remaining)

    @property
    def daily_total_today(self) -> int:
        return self.daily_spent_at_start + self.spent


@dataclass(frozen=True)
class ApolloPerson:
    first_name: str | None
    last_name: str | None
    title: str | None
    email: str | None
    email_status: str | None
    linkedin_url: str | None


class Apollo:
    def __init__(self, api_key: str, *, budget: CreditBudget):
        # Paid provider, so instantiation is opt-in: APOLLO_ENABLE=true must
        # be set in the environment or this raises. A key alone is not
        # consent to spend — a stray key in an environment must never be
        # enough to start paying, which is the house rule for every paid
        # provider in this repo.
        if os.environ.get("APOLLO_ENABLE", "").strip().lower() not in (
            "1", "true", "yes", "on",
        ):
            raise RuntimeError(
                "Apollo is a paid provider and is disabled by default. "
                "Set APOLLO_ENABLE=true to allow spend, alongside "
                "APOLLO_API_KEY and a CreditBudget."
            )
        if not api_key:
            raise ValueError("Apollo API key required")
        self.api_key = api_key
        self.budget = budget
        self._client = httpx.Client(
            timeout=25.0,
            headers={
                "X-Api-Key": api_key,
                "Content-Type": "application/json",
                "Cache-Control": "no-cache",
            },
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Apollo:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def find_domain(self, company_name: str) -> str | None:
        """Resolves company name to domain via mixed_companies/search.

        ⚠️ NOT free on all plans — this account billed for it. Gated by budget.
        """
        if not company_name or not company_name.strip():
            return None
        if not self.budget.try_spend(1):
            log.info("Apollo budget exhausted (%d/%d) — skipping company search",
                     self.budget.spent, self.budget.limit)
            return None
        try:
            r = self._client.post(
                f"{BASE}/mixed_companies/search",
                json={"q_organization_name": company_name, "per_page": 1, "page": 1},
            )
        except Exception as e:
            log.warning("Apollo company search failed for %s: %s", company_name, e)
            return None
        if r.status_code != 200:
            log.warning("Apollo company search %s -> %s",
                        company_name, r.status_code)
            return None
        orgs = r.json().get("organizations") or r.json().get("accounts") or []
        if not orgs:
            return None
        o = orgs[0]
        domain = o.get("primary_domain")
        if domain:
            # lstrip("www.") is a charset op, not a prefix — would mangle
            # e.g. "wwx.com" → "x.com". Use removeprefix.
            return domain.lower().removeprefix("www.")
        # Fallback: parse the website_url field if primary_domain missing
        url = o.get("website_url") or ""
        if url:
            from urllib.parse import urlparse
            netloc = urlparse(url if "://" in url else f"http://{url}").netloc.lower()
            if netloc.startswith("www."):
                netloc = netloc[4:]
            return netloc or None
        return None

    def search_decision_maker(
        self, domain: str, *, titles: list[str] | None = None
    ) -> ApolloPerson | None:
        """Returns partial info (first_name, title). last_name/email masked.

        ⚠️ NOT free on all plans — this account billed for it. Gated by budget.
        """
        if not domain:
            return None
        if not self.budget.try_spend(1):
            log.info("Apollo budget exhausted (%d/%d) — skipping people search",
                     self.budget.spent, self.budget.limit)
            return None
        try:
            r = self._client.post(
                f"{BASE}/mixed_people/api_search",
                json={
                    "q_organization_domains_list": [domain],
                    "person_titles": titles or DEFAULT_TITLES,
                    "per_page": 5,
                    "page": 1,
                },
            )
        except Exception as e:
            log.warning("Apollo search failed for %s: %s", domain, e)
            return None
        if r.status_code != 200:
            log.warning("Apollo search %s -> %s", domain, r.status_code)
            return None
        people = r.json().get("people", []) or []
        # Highest-priority title first
        priority = {t.lower(): i for i, t in enumerate(titles or DEFAULT_TITLES)}
        people.sort(key=lambda p: priority.get((p.get("title") or "").lower(), 999))
        for p in people:
            if p.get("first_name") or p.get("name"):
                return ApolloPerson(
                    first_name=p.get("first_name"),
                    last_name=p.get("last_name"),
                    title=p.get("title"),
                    email=p.get("email"),
                    email_status=p.get("email_status"),
                    linkedin_url=p.get("linkedin_url"),
                )
        return None

    def match(
        self,
        *,
        domain: str,
        first_name: str | None = None,
        last_name: str | None = None,
    ) -> ApolloPerson | None:
        """COSTS 1 CREDIT — returns full record. Refuses if over budget."""
        if not self.budget.try_spend(1):
            log.info("Apollo budget exhausted (%d/%d) — skipping match",
                     self.budget.spent, self.budget.limit)
            return None
        body: dict = {"domain": domain, "reveal_personal_emails": False}
        if first_name:
            body["first_name"] = first_name
        if last_name:
            body["last_name"] = last_name
        try:
            r = self._client.post(f"{BASE}/people/match", json=body)
        except Exception as e:
            log.warning("Apollo match failed for %s: %s", domain, e)
            return None
        if r.status_code != 200:
            log.warning("Apollo match %s -> %s", domain, r.status_code)
            return None
        p = r.json().get("person") or {}
        if not (p.get("first_name") or p.get("email")):
            return None
        return ApolloPerson(
            first_name=p.get("first_name"),
            last_name=p.get("last_name"),
            title=p.get("title"),
            email=p.get("email"),
            email_status=p.get("email_status"),
            linkedin_url=p.get("linkedin_url"),
        )
