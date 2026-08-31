"""MailTester Ninja API client — sequential, rate-limited.

Plan limits at time of writing: 50,000 verifications/day, 1 req/sec, 1 concurrent
connection. We enforce 1 req/sec via a simple monotonic clock gate.

API:
  GET https://happy.mailtester.ninja/ninja?email=<email>&key=<key>
  Returns JSON like:
    {"code":"ok","message":"Accepted","domain":"...","mx":"...","email":"..."}
  Status codes returned via the "code" field:
    "ok"      - mailbox exists and accepts mail
    "mb"      - mailbox check inconclusive (catch-all or greylist)
    "ko"      - mailbox does not exist
    "--"      - error (disabled key, bad domain, etc)
"""

# ssrf-safe: all outbound URLs are hardcoded provider API endpoints

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Iterable

import httpx

log = logging.getLogger(__name__)

ENDPOINT = "https://happy.mailtester.ninja/ninja"


@dataclass(frozen=True)
class VerifyResult:
    email: str
    code: str            # "ok" | "mb" | "ko" | "--"
    message: str
    is_valid: bool       # True only when code == "ok"
    is_uncertain: bool   # True when code == "mb" (catch-all/greylist)


class MailTester:
    def __init__(self, api_key: str, *, min_interval: float = 1.05, timeout: float = 10.0):
        if not api_key:
            raise ValueError("MailTester API key required")
        self.api_key = api_key
        self.min_interval = min_interval
        self._last_call = 0.0
        self._client = httpx.Client(timeout=timeout)
        # Serializes _gate() + request across threads. Required because the
        # provider documents 1 concurrent connection + 1 req/sec, and a single
        # MailTester instance may be shared by several enrichment workers.
        self._lock = threading.Lock()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> MailTester:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _gate(self) -> None:
        """Enforce min interval between requests (token-bucket-lite, sequential)."""
        elapsed = time.monotonic() - self._last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_call = time.monotonic()

    def verify(self, email: str) -> VerifyResult:
        with self._lock:
            self._gate()
            try:
                r = self._client.get(ENDPOINT, params={"email": email, "key": self.api_key})
                text = r.text or ""
                if not text.strip():
                    # Empty body sometimes returned under burst — wait and retry once
                    time.sleep(self.min_interval)
                    r = self._client.get(ENDPOINT, params={"email": email, "key": self.api_key})
                    text = r.text or ""
                import json
                data = json.loads(text)
            except Exception as e:
                log.warning("MailTester request failed for %s: %s", email, type(e).__name__)
                return VerifyResult(email, "--", type(e).__name__, False, False)
        code = (data.get("code") or "").lower()
        msg = data.get("message") or ""
        return VerifyResult(
            email=email,
            code=code,
            message=msg,
            is_valid=(code == "ok"),
            is_uncertain=(code == "mb"),
        )

    def first_valid(self, candidates: Iterable[str]) -> VerifyResult | None:
        """Verify candidates in order; return on first 'ok'.

        Short-circuits if the first response says "No MX" — all candidates on
        that domain would fail identically, no point burning calls.

        Falls back to the first 'mb' (catch-all) if no 'ok' is found, since on
        catch-all domains MailTester can't disprove any address — best effort.
        """
        first_uncertain: VerifyResult | None = None
        transport_errors = 0
        for i, email in enumerate(candidates):
            res = self.verify(email)
            log.debug("verify %s -> %s (%s)", email, res.code, res.message)
            if res.is_valid:
                return res
            if res.is_uncertain and first_uncertain is None:
                first_uncertain = res
            # Domain-level failure — no point trying the rest of the candidates
            if i == 0 and res.code == "ko" and "no mx" in res.message.lower():
                log.info("Skipping remaining candidates — domain has no MX")
                return res
            # Circuit-breaker: code "--" is a transport failure (verify() puts the
            # exception type in `message`). A timeout/connect error means the mail
            # server isn't answering — EVERY candidate on this domain will fail the
            # same way, so one bad guess used to drag a whole ten-candidate pattern
            # list through full-timeout calls, ~200 seconds for a single dead
            # domain. Bail on the first timeout/connect error, or after 2
            # transport errors of any kind.
            if res.code == "--":
                transport_errors += 1
                m = (res.message or "").lower()
                if "timeout" in m or "connect" in m or transport_errors >= 2:
                    log.info("MailTester circuit-break on %s after %s — skipping "
                             "remaining candidates", email, res.message or "errors")
                    break
            else:
                transport_errors = 0
        return first_uncertain
