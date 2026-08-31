"""Decision-maker generic-email fallback (opt-in).

When personalized email discovery fails, fall back to role-titled inboxes
that are LIKELY to reach a real decision-maker:
  founder@, owner@, ceo@, admin@

We deliberately exclude functional inboxes (info@, contact@, sales@,
support@, hello@) because at the small-biz ICP we target, those route
to junior support staff or shared inboxes that ignore cold outreach.
Spending MailTester budget on them produces "valid" emails that never
convert.

Hit rate is lower than the old broad list (~10-20% vs ~30-50%), but
the contacts that DO come back are far more likely to land with the
person who can actually buy. Quality > quantity.

Off by default. Enable deliberately, never as a silent fallback.
"""

from __future__ import annotations

# Ordered most-likely-to-exist first. All of these imply decision-maker
# routing — at a small business "admin@" is usually the owner or office
# manager, not a generic helpdesk.
GENERIC_LOCALS: tuple[str, ...] = (
    "founder",
    "owner",
    "ceo",
    "cfo",
    "admin",
)


def generic_candidates(domain: str, *, first_name: str | None = None) -> list[str]:
    if not domain:
        return []
    # If no real person was found, role-titled guessing isn't appropriate —
    # outbound to founder@<domain> with no name in the body looks like spam.
    if not (first_name or "").strip():
        return []
    return [f"{local}@{domain}" for local in GENERIC_LOCALS]


# Functional/shared inboxes for the NO-NAME bucket — leads where a domain was
# resolved but never a decision-maker name. The default stance is that these
# convert poorly at an SMB ICP, so this is a SEPARATE, explicitly opt-in path
# for callers who accept the volume-over-quality trade. Every candidate must be
# verified before use, and ship VERIFIED-only (no catch-all) to protect the
# sending domain's reputation.
# Ordered most-likely-to-be-monitored-by-an-owner first.
FUNCTIONAL_LOCALS: tuple[str, ...] = (
    "info",
    "contact",
    "office",
    "hello",
    "admin",
)


def functional_candidates(domain: str) -> list[str]:
    """Functional-inbox guesses for a domain with NO decision-maker name.

    Distinct from generic_candidates(): no first_name required, targeting
    shared inboxes (info@, contact@) rather than role inboxes (owner@). Only
    appropriate when the caller has already exhausted personalized discovery
    and will verify + gate hard on the result.
    """
    if not domain:
        return []
    return [f"{local}@{domain}" for local in FUNCTIONAL_LOCALS]
