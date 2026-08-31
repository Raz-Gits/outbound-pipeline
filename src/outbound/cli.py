"""CLI: CSV in, enriched CSV out, optional ship to the sequencer.

Report-only is the default on anything that acts. `ship` prints what it
WOULD send unless --send is passed, and even --send still has to clear the
Instantly client's own env + confirm gates. Three independent gates on the
one action that reaches strangers' inboxes is the intended amount.

    python -m outbound enrich leads.csv -o enriched.csv [--paid]
    python -m outbound ship enriched.csv --campaign <uuid> [--send]
    python -m outbound suppress someone@example.com [...]
    python -m outbound usage
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from pathlib import Path

from . import suppression, usage
from .cascade import enrich_many


def _read_csv(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        sys.exit(f"{path}: no rows")
    return rows


def _write_csv(path: str, rows: list[dict]) -> None:
    fields: list[str] = []
    for r in rows:
        for k in r:
            if k not in fields:
                fields.append(k)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def cmd_enrich(args: argparse.Namespace) -> int:
    rows = _read_csv(args.csv)
    need = {"company", "domain"}
    missing = need - set(rows[0])
    if missing:
        sys.exit(f"CSV needs columns {sorted(need)} (missing {sorted(missing)}); "
                 f"first_name/last_name strongly recommended")
    out = enrich_many(rows, allow_paid=args.paid)
    _write_csv(args.out, out)
    verified = sum(1 for r in out if r.get("email_status") == "verified")
    print(f"{len(out)} leads -> {verified} verified emails "
          f"({verified / len(out) * 100:.0f}%). Written to {args.out}")
    by = {}
    for r in out:
        p = r.get("email_provider") or "-"
        by[p] = by.get(p, 0) + 1
    for p, n in sorted(by.items(), key=lambda kv: -kv[1]):
        print(f"   {n:5d}  {p}")
    return 0


def cmd_ship(args: argparse.Namespace) -> int:
    from .delivery.instantly import InstantlyClient, resolve_instantly_key

    rows = _read_csv(args.csv)
    verified = [r for r in rows if r.get("email_status") == "verified"]
    skipped_unverified = len(rows) - len(verified)

    # Suppression happens HERE, at the last moment before the send — not at
    # enrich time, because people opt out between the two.
    kept, dropped = suppression.filter_leads(verified)

    print(f"{len(rows)} rows: {skipped_unverified} not verified (never ship), "
          f"{dropped} suppressed, {len(kept)} to ship")
    for r in kept[:20]:
        print(f"   {r.get('email'):40s} {r.get('company', '')}")
    if len(kept) > 20:
        print(f"   ... and {len(kept) - 20} more")

    if not args.send:
        print("\nREPORT-ONLY (the default). Nothing was sent. "
              "Re-run with --send to ship these.")
        return 0
    if not kept:
        return 0

    key = resolve_instantly_key()
    if not key:
        sys.exit("INSTANTLY_API_KEY is not set")
    leads = [{
        "email": r.get("email", ""),
        "first_name": r.get("first_name", ""),
        "last_name": r.get("last_name", ""),
        "company_name": r.get("company", ""),
        "website": r.get("domain", ""),
    } for r in kept]
    with InstantlyClient(key) as c:
        result = c.add_leads_to_campaign(leads, campaign_id=args.campaign,
                                         confirm=True)
    print(f"added={result['added']} skipped={result['skipped']} "
          f"failed={result['failed']}")
    for e in result["errors"][:10]:
        print(f"   {e}")
    return 0 if not result["failed"] else 1


def cmd_suppress(args: argparse.Namespace) -> int:
    n = suppression.add(args.emails)
    total = len(suppression.load())
    print(f"{n} added; ledger now holds {total} address(es)")
    return 0


def cmd_usage(args: argparse.Namespace) -> int:
    tally = usage.month_tally()
    if not tally:
        print("no provider calls recorded this month")
        return 0
    for label, n in sorted(tally.items(), key=lambda kv: -kv[1]):
        print(f"   {n:6d}  {label}")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level="INFO", format="%(levelname)s | %(message)s")
    ap = argparse.ArgumentParser(prog="outbound", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("enrich", help="CSV -> enriched CSV (free tier by default)")
    e.add_argument("csv")
    e.add_argument("-o", "--out", default="enriched.csv")
    e.add_argument("--paid", action="store_true",
                   help="allow the quota'd + paid finder stages (each paid "
                        "provider still requires its own env gate)")
    e.set_defaults(fn=cmd_enrich)

    s = sub.add_parser("ship", help="enriched CSV -> Instantly campaign "
                                    "(REPORT-ONLY unless --send)")
    s.add_argument("csv")
    s.add_argument("--campaign", required=True, help="Instantly campaign id")
    s.add_argument("--send", action="store_true",
                   help="actually ship (also requires INSTANTLY_ALLOW_WRITES=1)")
    s.set_defaults(fn=cmd_ship)

    p = sub.add_parser("suppress", help="add address(es) to the do-not-contact ledger")
    p.add_argument("emails", nargs="+")
    p.set_defaults(fn=cmd_suppress)

    u = sub.add_parser("usage", help="this month's provider-call tally")
    u.set_defaults(fn=cmd_usage)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
