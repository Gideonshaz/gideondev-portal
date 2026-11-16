"""Read-only LIVE stats for the app: today's GMV Max cost / GMV / ROI / orders for the
approved campaign, plus whether its host is live right now (from the per-room report).

Only read tools are called. A failure here never affects the ON/OFF operations; the runner
calls this after them and only logs problems.
"""
import datetime

from affiliate_scheduler import mcp_client
from affiliate_scheduler.safety import ADVERTISER_ID

INFO_TOOL = "campaign_gmv_max_info_get"
REPORT_TOOL = "gmv_max_report_get"
TOOLS = (INFO_TOOL, REPORT_TOOL)
MYT = datetime.timezone(datetime.timedelta(hours=8))
MONEY = ("cost", "gross_revenue", "roi", "orders")


def _num(v):
    try:
        return round(float(v), 2)
    except (TypeError, ValueError):
        return 0.0


def _data(payload, tool):
    if not isinstance(payload, dict) or payload.get("code", 0) != 0:
        msg = payload.get("message") if isinstance(payload, dict) else payload
        raise mcp_client.McpError(f"{tool}: {msg}")
    return payload.get("data") or {}


def _myt_iso(text):
    """Report times look like '2026-11-16 13:19:42' (UTC). Returned in Malaysia time, like
    every other portal timestamp the app reads."""
    try:
        t = datetime.datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        return t.replace(tzinfo=datetime.timezone.utc).astimezone(MYT).isoformat()
    except (TypeError, ValueError):
        return ""


def collect(session, campaign_id, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    day = now.astimezone(MYT).strftime("%Y-%m-%d")
    info = _data(mcp_client.tool_payload(session.call_tool(
        INFO_TOOL, {"advertiser_id": ADVERTISER_ID, "campaign_id": campaign_id})), INFO_TOOL)
    store = str(info.get("store_id") or "")
    if not store:
        raise mcp_client.McpError("campaign has no store_id")
    base = {"advertiser_id": ADVERTISER_ID, "store_ids": [store], "start_date": day, "end_date": day,
            "filtering": {"campaign_ids": [campaign_id]}}

    totals = _data(mcp_client.tool_payload(session.call_tool(REPORT_TOOL, dict(
        base, dimensions=["campaign_id"], metrics=list(MONEY)))), REPORT_TOOL)
    row = next((r.get("metrics") or {} for r in totals.get("list") or []
                if str((r.get("dimensions") or {}).get("campaign_id")) == str(campaign_id)), {})

    rooms = _data(mcp_client.tool_payload(session.call_tool(REPORT_TOOL, dict(
        base, dimensions=["room_id"],
        metrics=["live_status", "live_launched_time", "live_duration", "live_views"] + list(MONEY)))), REPORT_TOOL)
    room_rows = []
    for r in rooms.get("list") or []:
        m = r.get("metrics") or {}
        room_rows.append({
            "room_id": str((r.get("dimensions") or {}).get("room_id", "")),
            "status": str(m.get("live_status", "")).upper(),
            "started_at": _myt_iso(m.get("live_launched_time")),
            "duration": str(m.get("live_duration", ""))[:20],
            "views": int(_num(m.get("live_views"))),
            "cost": _num(m.get("cost")), "gmv": _num(m.get("gross_revenue")),
            "roi": _num(m.get("roi")), "orders": int(_num(m.get("orders"))),
        })
    room_rows.sort(key=lambda x: x["started_at"], reverse=True)
    ongoing = next((x for x in room_rows if x["status"] == "ONGOING"), None)
    return {
        "date": day,
        "campaign_status": str(info.get("operation_status", "")),
        "budget": _num(info.get("budget")),
        "roas_bid": _num(info.get("roas_bid")),
        "cost": _num(row.get("cost")), "gmv": _num(row.get("gross_revenue")),
        "roi": _num(row.get("roi")), "orders": int(_num(row.get("orders"))),
        "is_live": ongoing is not None,
        "live": ongoing or (room_rows[0] if room_rows else None),
    }
