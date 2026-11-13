"""Campaign read/verify/write through the TikTok Ads MCP, behind the safety gate.

The tool schemas are checked at run time (they can change). If the live schema no
longer has the arguments this code relies on, everything fails closed with a clear
message instead of guessing.
"""
from affiliate_scheduler import mcp_client
from affiliate_scheduler.safety import (
    ADVERTISER_ID, APPROVED_AFFILIATES, PROTECTED_IDS, Campaign, verify_live_campaign,
)

READ_TOOL = "gmv_max_campaign_get"
WRITE_TOOL = "campaign_status_update"
READ_ARGS = ("advertiser_id", "filtering")
WRITE_ARGS = ("advertiser_id", "campaign_ids", "operation_status")
TYPE_KEYS = ("gmv_max_promotion_type", "promotion_type", "gmv_max_campaign_type")


class SchemaChanged(mcp_client.McpError):
    pass


def check_schema(tools, name, required):
    tool = tools.get(name)
    if not tool:
        similar = sorted(t for t in tools if "gmv" in t or "status" in t)[:15]
        raise SchemaChanged(f"Tool {name} is not offered by the MCP server. Similar: {similar}")
    props = (tool.get("inputSchema") or {}).get("properties") or {}
    missing = [a for a in required if a not in props]
    if missing:
        raise SchemaChanged(f"Tool {name} no longer accepts {missing}; refusing to guess")
    return tool


def _find_items(payload, campaign_id):
    found = []
    def walk(x):
        if isinstance(x, dict):
            if str(x.get("campaign_id", "")) and "campaign_name" in x:
                found.append(x)
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(payload)
    return found


def make_fetcher(session, tools):
    """Return fetch(advertiser_id, campaign_id) -> Campaign for verify_live_campaign."""
    check_schema(tools, READ_TOOL, READ_ARGS)

    def fetch(advertiser_id, campaign_id):
        if advertiser_id != ADVERTISER_ID or campaign_id not in APPROVED_AFFILIATES:
            raise ValueError("Refusing to look up an unapproved campaign")
        args = {"advertiser_id": advertiser_id,
                "filtering": {"gmv_max_promotion_types": ["LIVE_GMV_MAX"],
                              "campaign_ids": [campaign_id]}}
        payload = mcp_client.tool_payload(session.call_tool(READ_TOOL, args))
        items = _find_items(payload, campaign_id)
        matches = [i for i in items if str(i["campaign_id"]) == campaign_id]
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one campaign {campaign_id}, got {len(matches)}")
        item = matches[0]
        explicit = next((item[k] for k in TYPE_KEYS if item.get(k)), None)
        # The query filtered on LIVE_GMV_MAX, so a returned row is LIVE GMV Max unless the
        # row itself says otherwise.
        ptype = str(explicit) if explicit else "LIVE_GMV_MAX"
        adv = str(item.get("advertiser_id") or advertiser_id)
        campaign = Campaign(adv, str(item["campaign_id"]), str(item["campaign_name"]), ptype)
        fetch.last_status = item.get("operation_status") or item.get("status")
        return campaign

    fetch.last_status = None
    return fetch


def read_campaign(session, tools, campaign_id):
    """Read-only verification used by the manual verify workflow (affiliate_scheduler.verify)."""
    fetch = make_fetcher(session, tools)
    campaign = verify_live_campaign(fetch, campaign_id, "DISABLE")  # read only; no write follows
    return campaign, fetch.last_status


def set_status(session, tools, campaign_id, operation, live):
    """Verify, then (only if live) change status of exactly one approved campaign.

    Returns (result, detail) where result is 'dry_run' or 'succeeded'. Raises on any failure.
    """
    fetch = make_fetcher(session, tools)
    campaign = verify_live_campaign(fetch, campaign_id, operation)
    before = fetch.last_status
    if not live:
        return "dry_run", (f"Verified {campaign.name} ({campaign.campaign_id}), status {before}. "
                           f"Would {operation}. No change made.")
    check_schema(tools, WRITE_TOOL, WRITE_ARGS)
    ids = [campaign.campaign_id]
    # Final hard gate right next to the write.
    if (len(ids) != 1 or ids[0] not in APPROVED_AFFILIATES or ids[0] in PROTECTED_IDS
            or operation not in ("ENABLE", "DISABLE")):
        raise ValueError("Final gate rejected the write")
    if before == operation:
        return "succeeded", f"{campaign.name} already {operation}; nothing to change"
    session.call_tool(WRITE_TOOL, {"advertiser_id": ADVERTISER_ID, "campaign_ids": ids,
                                   "operation_status": operation})
    verify_live_campaign(fetch, campaign_id, operation)
    if fetch.last_status != operation:
        raise mcp_client.McpError(
            f"Status after update is {fetch.last_status}, expected {operation}")
    return "succeeded", f"{campaign.name} changed {before} -> {operation} (verified)"
