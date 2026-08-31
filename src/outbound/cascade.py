"""The enrichment cascade — cheapest first, verified-only out.

One lead goes in as {company, domain, first_name, last_name}. What comes out
is either a VERIFIED email with provenance, or an honest miss. Nothing in
between: an unverified address is a bounce waiting to spend your domain
reputation, which costs more than every provider on this list combined.

Order is strictly by cost, and the order IS the product:

  0. suppression   — never spend a cent enriching someone who opted out
  1. patterns      — generate likely addresses from the name, free
     + mailtester  — SMTP-verify the guesses, effectively free
  2. hunter        — domain search, free monthly quota; returns the domain's
                     email PATTERN and known people, either of which feeds
                     back into step 1
  3. snov / getprospect / prospeo / tomba — name+domain finders with free
                     monthly quotas, tried in quota order; each result is
                     re-verified unless the provider already verified it
  4. anymail       — PAID per valid hit; double-gated (env flag + key),
                     monthly spend cap
  5. apollo        — PAID; triple-gated, per-run and daily credit budgets

Every stage can be absent (no key = skipped, silently and safely) and the
cascade degrades to whatever is configured. With no keys at all it still
does patterns+nothing, which is at least honest about what it can't know.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from . import suppression
from .patterns import candidate_emails
from .providers import anymail
from .providers import getprospect
from .providers import hunter
from .providers import prospeo
from .providers import snov
from .providers import tomba
from .providers.mailtester import MailTester

log = logging.getLogger(__name__)


@dataclass
class EnrichResult:
    email: str = ""
    status: str = "not_found"    # verified | catch_all | cross_company | suppressed | not_found
    provider: str = ""           # which stage produced the email
    notes: list[str] = field(default_factory=list)


def _mailtester() -> MailTester | None:
    key = (os.getenv("MAILTESTER_API_KEY") or "").strip()
    return MailTester(key) if key else None


# The quota'd name+domain finders, cheapest/most-generous quota first. Each
# entry: (name, find_email callable, provider_says_verified statuses).
_QUOTA_FINDERS = (
    ("snov", snov.find_email, {"valid"}),
    ("getprospect", getprospect.find_email, {"valid", "verified"}),
    ("prospeo", prospeo.find_email, {"verified"}),
    ("tomba", tomba.find_email, {"verified"}),
)


def enrich_lead(
    lead: dict,
    *,
    mt: MailTester | None = None,
    allow_paid: bool = False,
) -> EnrichResult:
    """Run one lead through the cascade.

    `mt` may be shared across calls (it rate-limits internally). `allow_paid`
    gates stages 3-5; even True only enables what the environment has also
    enabled — a paid provider with its gate closed stays closed.
    """
    first = str(lead.get("first_name") or "").strip()
    last = str(lead.get("last_name") or "").strip()
    domain = str(lead.get("domain") or "").strip().lower().removeprefix("www.")
    company = str(lead.get("company") or "").strip()
    res = EnrichResult()

    if not domain:
        res.notes.append("no domain — nothing to enrich against")
        return res

    # Stage 0 — if we already know an email for this person is suppressed,
    # spending anything on them is wasted by definition. (Suppression is
    # keyed by email, so this only catches re-runs; the authoritative check
    # is at ship time.)
    known = str(lead.get("email") or "").strip().lower()
    if known and suppression.is_suppressed(known):
        res.status = "suppressed"
        res.notes.append("known email is on the do-not-contact ledger")
        return res

    own_mt = mt is None
    if own_mt:
        mt = _mailtester()

    try:
        # Stage 1 — pattern guesses, verified. Free, and right more often
        # than the price suggests.
        if mt and first:
            cands = candidate_emails(first, last or None, domain)
            hit = mt.first_valid(cands) if cands else None
            if hit and hit.is_valid:
                res.email, res.status, res.provider = hit.email, "verified", "patterns+mailtester"
                return res
            if hit and hit.is_uncertain:
                # Catch-all domain: remember the best guess but keep going —
                # a finder with corpus data beats an unverifiable guess.
                res.email, res.status, res.provider = hit.email, "catch_all", "patterns+mailtester"

        # Stage 2 — Hunter domain search: the domain's pattern and known
        # people. If it returns the pattern, regenerate + verify (still free
        # for us); if it returns a verified person outright, take it.
        hr = hunter.domain_search(domain)
        if hr:
            best = hunter.pick_best_candidate(hr)
            if best and best.verification_status == "verified":
                # Prefer the named person we were ASKED about when present.
                if not first or best.first_name.lower() == first.lower():
                    res.email, res.status, res.provider = best.email, "verified", "hunter"
                    return res
            if hr.pattern and mt and first and last:
                guess = (hr.pattern.replace("{first}", first.lower())
                         .replace("{last}", last.lower())
                         .replace("{f}", first[:1].lower())
                         .replace("{l}", last[:1].lower()) + "@" + domain)
                v = mt.verify(guess)
                if v.is_valid:
                    res.email, res.status, res.provider = v.email, "verified", "hunter-pattern+mailtester"
                    return res

        if not allow_paid:
            return res

        # Stage 3 — quota'd finders, in order. Anything not provider-verified
        # is re-verified before it counts.
        if first and last:
            for name, finder, verified_statuses in _QUOTA_FINDERS:
                got = finder(first, last, domain, company_name=company or None)
                if not got:
                    continue
                email, status = got
                if status in verified_statuses:
                    res.email, res.status, res.provider = email, "verified", name
                    return res
                if mt:
                    v = mt.verify(email)
                    if v.is_valid:
                        res.email, res.status, res.provider = email, "verified", f"{name}+mailtester"
                        return res
                res.notes.append(f"{name} returned {email} ({status}) — unverifiable, discarded")

        # Stage 4 — Anymail, paid per valid hit, own env gate + monthly cap.
        got = anymail.find_email(first, last, domain, company_name=company or None)
        if got:
            res.email = got["email"]
            res.status = "verified" if got["status"] == "valid" else got["status"]
            res.provider = "anymail"
            return res

        # Stage 5 (Apollo) is deliberately NOT called from the cascade.
        # It is the most expensive path and the least predictable billing;
        # use it as an explicit, budgeted backfill (see providers.apollo),
        # not as one more automatic fallthrough.
        return res
    finally:
        if own_mt and mt:
            mt.close()


def enrich_many(leads: list[dict], *, allow_paid: bool = False) -> list[dict]:
    """Enrich a list of lead dicts; returns new dicts with email/status/
    provider/notes merged in. Sequential on purpose: MailTester allows one
    concurrent connection, and a cascade that respects provider limits in
    series beats one that trips them in parallel."""
    mt = _mailtester()
    out = []
    try:
        for lead in leads:
            r = enrich_lead(lead, mt=mt, allow_paid=allow_paid)
            merged = dict(lead)
            merged.update({
                "email": r.email or merged.get("email", ""),
                "email_status": r.status,
                "email_provider": r.provider,
                "email_notes": "; ".join(r.notes),
            })
            out.append(merged)
    finally:
        if mt:
            mt.close()
    return out
