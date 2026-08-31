# outbound-pipeline

Lead enrichment, verification and delivery, extracted from an outbound engine
that ran in production across three client workspaces and 71,000+ sends.
Source-agnostic: leads come in as a CSV, from wherever you get leads.

The design is three rules, and the code is what happens when you refuse to
break them:

1. **Cheapest provider first.** Verified pattern-guessing before free-quota
   finders, free-quota finders before anything paid, and the paid ones behind
   explicit gates with hard monthly caps. Moving from list-buying to this
   cascade is mostly a cost decision that turns out to also be a quality one.

2. **Verified-only out.** An unverified address is a bounce waiting to spend
   your domain reputation, which costs more than every provider here
   combined. The engine this comes from took bounce rates from double digits
   to under one percent by enforcing exactly this rule, and nothing else
   about the sending changed.

3. **Report-only by default.** The ship step prints what it *would* send.
   Actually sending requires a flag, plus an environment variable, plus a
   `confirm=True` in the code path. That is three independent gates on the one
   action that reaches strangers' inboxes.

## Install

```bash
git clone https://github.com/Raz-Gits/outbound-pipeline.git
cd outbound-pipeline
pip install -e .
cp .env.example .env     # add your own keys; every provider is optional
```

Python 3.10+. One dependency (`httpx`).

## Use

```bash
# leads.csv: company,domain,first_name,last_name
outbound enrich leads.csv -o enriched.csv          # free tier only
outbound enrich leads.csv -o enriched.csv --paid   # + quota'd/paid finders

outbound ship enriched.csv --campaign <uuid>       # REPORT-ONLY: prints the plan
outbound ship enriched.csv --campaign <uuid> --send

outbound suppress person@example.com               # append to do-not-contact
outbound usage                                     # month's provider-call tally
```

With no keys configured at all, `enrich` still runs and honestly reports
what it cannot know. Every provider is optional and skipped when unconfigured.

## The cascade

| Stage | What | Cost |
| --- | --- | --- |
| 0 | append-only suppression ledger | never spend on someone who opted out |
| 1 | pattern guesses (`first.last@…`, ten variants, most-common first) verified over SMTP | effectively free |
| 2 | Hunter domain search: the domain's email *pattern* and known people; a returned pattern feeds back into stage 1 | free monthly quota |
| 3 | Snov, GetProspect, Prospeo, Tomba name+domain finders, in quota order; anything not provider-verified is re-verified before it counts | free monthly quotas |
| 4 | Anymail Finder, person-search only (1 credit, charged only on a *valid* hit) | paid, double-gated, monthly cap |
| 5 | Apollo | paid, and deliberately **not** in the automatic cascade; explicit budgeted use only |

## The parts that took the longest to learn

**A stray key must never be enough to spend.** Every paid provider requires
its key AND an explicit `ENABLE_*` flag. Keys leak into environments; intent
shouldn't be inferable from an environment variable's mere existence.

**Don't retry a timed-out paid call with a second key.** A 180-second SMTP
search can time out on the *response* after the provider already found and
charged. Re-POSTing on another account double-pays. The Anymail adapter
bails instead, and the 30-day free-repeat window makes the retry safe later.

**Fail closed on a corrupt ledger.** If the monthly spend counter can't be
parsed, it reads as *at cap*, not as zero. A missing file is a fresh month; a
mangled one refuses to spend until a human looks.

**Fail loud on unrecorded spend.** If money was spent and the ledger write
failed, that's `log.error` and a reconciliation instruction, never a debug
line, because the cap now under-counts and someone needs to know.

**"Risky" is discarded even when it's free.** Accepting risky addresses is
trading tomorrow's deliverability for today's list size, which is the whole
disease this pipeline exists to cure.

**Suppression is append-only and checked at ship time.** The public API can
add to the do-not-contact ledger and read it; nothing can remove from it. It
is checked immediately before sending, not at the start of a run, because
people opt out mid-run. This is the one file with legal consequences, and it
is a plain greppable text file on purpose.

**A job change is a company-name question, not a domain question.** Finders
sometimes return the person's address at a different domain. Usually that's
the same company on an alias or mail domain; occasionally the person actually
moved. Treating every domain mismatch as a move throws away paid, valid
emails; the adapter requires a genuinely different company *name* and sets
real moves aside as `cross_company` instead of merging stale context.

**SSRF is a real concern the day you fetch scraped URLs.** `safe_fetch.py`
resolves once, validates every IP against private/loopback/link-local/
metadata ranges, then pins DNS for the duration of the request to close the
rebinding race, and bounds the response size. If you extend this pipeline to
fetch anything derived from scraped input, use it.

## Delivery guardrails

The Instantly client blocks every write unless BOTH an environment variable
(`INSTANTLY_ALLOW_WRITES=1`) and a `confirm=True` kwarg are present. An env
var alone is too easy to leave exported, a kwarg alone means any code path
can write. Bulk deletes have an extra ceiling and a third flag. Every write
attempt, executed or blocked, is appended to an audit log, so "what touched
the account" always has an answer.

## What this is not

No scraping and no sourcing: it starts from a CSV you already have. No
sending logic beyond handing verified leads to your sequencer. And no
LinkedIn anything.

## License

MIT.
