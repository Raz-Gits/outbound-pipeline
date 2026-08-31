"""Safe-by-default Instantly API client.

The sequencer is where a code bug turns into emails real people receive, so
this client treats write access the way a bank treats a vault: possible, and
never casual.

- READS are always allowed: list_campaigns, get_campaign, analytics,
  list_accounts, list_leads.

- WRITES are BLOCKED by default. Any method that creates / deletes / pauses /
  resumes is guarded by `_require_write_permission()`, which raises
  InstantlyWriteBlocked unless BOTH are true:
    1. Env var `INSTANTLY_ALLOW_WRITES=1` is set
    2. The caller passed `confirm=True` to the method

  Set the env var at the start of an explicit, deliberate operation and
  unset it after. Leaving it exported in a shell profile defeats the design.

- Bulk-destructive operations (deleting more than 50 leads at once) have an
  additional ceiling and require `confirm_destructive=True` on top.

Why both env + kwarg: an env var alone is too easy to leave on accidentally,
and a kwarg alone means any imported code path can write. Requiring both
forces the environment AND the code to acknowledge intent independently.

Audit: every write attempt — executed or blocked — is appended to
data/instantly_audit.log with timestamp, method, args summary and outcome,
so what touched the account is always reconstructable.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger(__name__)

BASE_URL = "https://api.instantly.ai/api/v2"
ENV_ALLOW_WRITES = "INSTANTLY_ALLOW_WRITES"
AUDIT_LOG = Path("data") / "instantly_audit.log"


def resolve_instantly_key() -> str:
    """The workspace API key from INSTANTLY_API_KEY.

    An Instantly key is scoped to ONE workspace. If you run several
    workspaces, run several environments — do not build silent fallbacks
    between accounts, because "which workspace did that ship to" must never
    have a surprising answer.
    """
    return (os.getenv("INSTANTLY_API_KEY") or "").strip()


class InstantlyWriteBlocked(RuntimeError):
    """Raised when a write attempt is blocked by the guardrail policy."""


def _audit(method: str, status: str, detail: str = "") -> None:
    """Append a single audit-log line. Fail-soft: log errors don't
    propagate (we never want audit to break an actual op)."""
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "status": status,
            "detail": detail,
        })
        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as e:
        log.warning("instantly audit write failed: %s", e)


class InstantlyClient:
    """Thin v2-API wrapper with hard-coded write protection.

    Default usage (READ ONLY, safe):
        c = InstantlyClient(api_key)
        campaigns = c.list_campaigns()

    Write (intentionally awkward — both gates required):
        # First in shell: export INSTANTLY_ALLOW_WRITES=1
        c = InstantlyClient(api_key)
        c.delete_leads([...], campaign_id="<uuid>", confirm=True)
    """

    def __init__(self, api_key: str, timeout: float = 30.0):
        if not api_key:
            raise ValueError("api_key required")
        self._client = httpx.Client(
            base_url=BASE_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> InstantlyClient:
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    # ---------- guardrails ----------

    @staticmethod
    def _require_write_permission(method: str, confirm: bool) -> None:
        env_ok = os.environ.get(ENV_ALLOW_WRITES, "").strip() == "1"
        if not env_ok:
            _audit(method, "BLOCKED_NO_ENV", "INSTANTLY_ALLOW_WRITES not set to 1")
            raise InstantlyWriteBlocked(
                f"{method}: writes are disabled. Set INSTANTLY_ALLOW_WRITES=1 "
                f"in env AND pass confirm=True to enable."
            )
        if not confirm:
            _audit(method, "BLOCKED_NO_CONFIRM", "confirm=False")
            raise InstantlyWriteBlocked(
                f"{method}: writes require confirm=True even with env set."
            )

    # ---------- read helpers ----------

    def _get(self, path: str, **params: Any) -> Any:
        r = self._client.get(path, params={k: v for k, v in params.items() if v is not None})
        r.raise_for_status()
        return r.json()

    def _post_read(self, path: str, body: dict | None = None) -> Any:
        """For endpoints that use POST for read operations (e.g. /leads/list)."""
        r = self._client.post(path, json=body or {})
        r.raise_for_status()
        return r.json()

    # ---------- reads (always allowed) ----------

    def list_campaigns(self, limit: int = 100) -> list[dict]:
        out: list[dict] = []
        starting_after = None
        while True:
            params: dict[str, Any] = {"limit": limit}
            if starting_after:
                params["starting_after"] = starting_after
            data = self._get("/campaigns", **params)
            items = data.get("items") if isinstance(data, dict) else data
            if not items:
                break
            out.extend(items)
            starting_after = data.get("next_starting_after") if isinstance(data, dict) else None
            if not starting_after:
                break
        return out

    def get_campaign(self, campaign_id: str) -> dict:
        return self._get(f"/campaigns/{campaign_id}")

    def get_campaign_analytics(
        self, campaign_id: str, start_date: str, end_date: str
    ) -> dict:
        return self._get(
            "/campaigns/analytics",
            id=campaign_id, start_date=start_date, end_date=end_date,
        )

    def get_campaign_analytics_daily(
        self, campaign_id: str, start_date: str, end_date: str
    ) -> list[dict]:
        data = self._get(
            "/campaigns/analytics/daily",
            campaign_id=campaign_id, start_date=start_date, end_date=end_date,
        )
        if isinstance(data, dict) and "items" in data:
            return data["items"]
        return data if isinstance(data, list) else []

    def list_accounts(self, campaign_id: str | None = None) -> list[dict]:
        params: dict[str, Any] = {"limit": 100}
        if campaign_id:
            params["campaign_id"] = campaign_id
        out: list[dict] = []
        starting_after = None
        while True:
            p = {**params}
            if starting_after:
                p["starting_after"] = starting_after
            data = self._get("/accounts", **p)
            items = data.get("items") if isinstance(data, dict) else data
            if not items:
                break
            out.extend(items)
            starting_after = data.get("next_starting_after") if isinstance(data, dict) else None
            if not starting_after:
                break
        return out

    def list_leads(
        self,
        campaign_id: str | None = None,
        status: int | None = None,
        limit: int = 100,
        max_pages: int = 50,
    ) -> list[dict]:
        """List leads via POST /leads/list. status: 3=replied, 5=bounced, etc.

        v2 takes filter params at the top level — not under a `filter` key
        — which we found out the hard way after a 400. When status is set
        but campaign_id is not, the API requires a campaign scope, so we
        fan out across all campaigns and merge.
        """
        if status is not None and not campaign_id:
            # Fan out: query each campaign separately.
            campaigns = self.list_campaigns()
            out: list[dict] = []
            for c in campaigns:
                cid = c.get("id") or c.get("_id")
                if not cid:
                    continue
                try:
                    out.extend(self.list_leads(campaign_id=cid, status=status,
                                               limit=limit, max_pages=max_pages))
                except httpx.HTTPStatusError as e:
                    log.warning("list_leads failed for campaign %s: %s", cid, e)
            return out

        body: dict[str, Any] = {"limit": limit}
        if campaign_id:
            body["campaign"] = campaign_id
        if status is not None:
            body["status"] = status
        out = []
        for _ in range(max_pages):
            data = self._post_read("/leads/list", body)
            items = data.get("items") if isinstance(data, dict) else data
            if not items:
                break
            out.extend(items)
            cursor = data.get("next_starting_after") if isinstance(data, dict) else None
            if not cursor:
                break
            body["starting_after"] = cursor
        return out

    # ---------- writes (BLOCKED by policy) ----------

    def create_lead(self, *_args: Any, confirm: bool = False, **_kwargs: Any) -> dict:
        self._require_write_permission("create_lead", confirm)
        raise NotImplementedError(
            "create_lead is intentionally unimplemented — use "
            "add_leads_to_campaign, which is the single audited entry point "
            "for leads. One door in means one place to guard."
        )

    BULK_DELETE_CEILING = 50

    def delete_leads(
        self,
        lead_ids: list[str],
        *,
        campaign_id: str,
        confirm: bool = False,
        confirm_destructive: bool = False,
    ) -> dict:
        # v2 DELETE /leads requires {campaign_id, ids, limit}. Omitting `ids`
        # nukes the whole campaign — we always pass the explicit list and
        # set `limit` as a defensive ceiling to match list length.
        self._require_write_permission("delete_leads", confirm)
        if not lead_ids:
            return {"deleted": 0}
        if len(lead_ids) > self.BULK_DELETE_CEILING and not confirm_destructive:
            _audit("delete_leads", "BLOCKED_NO_DESTRUCTIVE_CONFIRM",
                   f"campaign={campaign_id} count={len(lead_ids)} ceiling={self.BULK_DELETE_CEILING}")
            raise InstantlyWriteBlocked(
                f"delete_leads: {len(lead_ids)} ids exceeds bulk-delete ceiling "
                f"({self.BULK_DELETE_CEILING}). Pass confirm_destructive=True to override."
            )
        body = {"campaign_id": campaign_id, "ids": lead_ids, "limit": len(lead_ids)}
        r = self._client.request("DELETE", "/leads", json=body)
        r.raise_for_status()
        _audit("delete_leads", "EXECUTED",
               f"campaign={campaign_id} count={len(lead_ids)} bulk={len(lead_ids) > self.BULK_DELETE_CEILING}")
        return r.json()

    def add_leads_to_campaign(
        self,
        leads: list[dict],
        *,
        campaign_id: str,
        confirm: bool = False,
    ) -> dict:
        """Add already-enriched, already-VERIFIED leads to a campaign.

        The caller is responsible for suppression-filtering immediately
        before this call (see outbound.suppression.filter_leads) and for
        shipping verified-only. Instantly also dedups within a campaign,
        but that is a convenience, not the guard.

        Each lead dict: {email, first_name?, last_name?, company_name?,
        website?, phone?, custom_variables?: {...}}. Returns counts + errors.
        """
        self._require_write_permission("add_leads_to_campaign", confirm)
        added, skipped, errors = 0, 0, []
        for ld in leads:
            email = (ld.get("email") or "").strip()
            if not email:
                skipped += 1
                continue
            body: dict[str, Any] = {"campaign": campaign_id, "email": email}
            for k in ("first_name", "last_name", "company_name", "website", "phone"):
                if ld.get(k):
                    body[k] = ld[k]
            cv = ld.get("custom_variables")
            if cv:
                # Instantly v2 stores merge variables (personalization, Icebreaker1,
                # ...) as TOP-LEVEL payload keys, NOT under a nested
                # "custom_variables" object. Verified 2026-06-24: a nested object is
                # silently dropped (the value never reaches the lead). Merge each var
                # in at top level; setdefault so a custom key can't clobber a
                # standard field above. DO NOT revert to body["custom_variables"]=cv.
                for vk, vv in cv.items():
                    body.setdefault(vk, vv)
            try:
                r = self._client.post("/leads", json=body)
                r.raise_for_status()
                added += 1
            except httpx.HTTPStatusError as e:
                errors.append({"email": email, "status": e.response.status_code,
                               "detail": e.response.text[:160]})
        _audit("add_leads_to_campaign", "EXECUTED",
               f"campaign={campaign_id} added={added} skipped={skipped} failed={len(errors)}")
        return {"added": added, "skipped": skipped, "failed": len(errors), "errors": errors}

    def pause_campaign(self, campaign_id: str, *, confirm: bool = False) -> dict:
        self._require_write_permission("pause_campaign", confirm)
        r = self._client.post(f"/campaigns/{campaign_id}/pause")
        r.raise_for_status()
        _audit("pause_campaign", "EXECUTED", campaign_id)
        return r.json()

    def resume_campaign(self, campaign_id: str, *, confirm: bool = False) -> dict:
        self._require_write_permission("resume_campaign", confirm)
        r = self._client.post(f"/campaigns/{campaign_id}/resume")
        r.raise_for_status()
        _audit("resume_campaign", "EXECUTED", campaign_id)
        return r.json()
