"""Daily LIVE GMV Max history for the app (read only).

One row per approved campaign per Malaysia day: cost, GMV, orders, LIVE views, 10-second views,
new follows, and minutes/sessions of LIVEs that ran with ads. ROI and cost per order are worked
out from these when read, so totals over any range stay correct.

Only the report and info read tools are called. A failure here never affects ON/OFF operations.
TikTok does not offer product impressions/clicks, CTR, CTOR or tap-through rate for LIVE GMV Max
campaigns through this report (it answers "Invalid metric"), so they are not collected.
"""
import datetime
import re

from affiliate_scheduler import mcp_client
from affiliate_scheduler.live_stats import INFO_TOOL, MYT, REPORT_TOOL, _data, _num
from affiliate_scheduler.safety import ADVERTISER_ID

MONEY = ["cost", "gross_revenue", "orders"]
TRAFFIC = ["live_views", "10_second_live_views", "live_follows"]
DAY_SPAN = 30            # TikTok: ranges split by day can be at most 30 days
MAX_BACK = 364           # and nothing older than a year


def minutes(text):
    """'2h 1m' -> 121, '0h 54m' -> 54, '' -> None"""
    m = re.fullmatch(r"\s*(?:(\d+)\s*h)?\s*(?:(\d+)\s*m)?\s*", text or "")
    if not m or not (m.group(1) or m.group(2)):
        return None
    return int(m.group(1) or 0) * 60 + int(m.group(2) or 0)


def _utc(text):
    try:
        return datetime.datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


def campaign_info(session, campaign_id):
    """(first day the campaign could have run, store id)."""
    info = _data(mcp_client.tool_payload(session.call_tool(
        INFO_TOOL, {"advertiser_id": ADVERTISER_ID, "campaign_id": campaign_id})), INFO_TOOL)
    store = str(info.get("store_id") or "")
    if not store:
        raise mcp_client.McpError("campaign has no store_id")
    start = _utc(info.get("schedule_start_time"))
    return (start.astimezone(MYT).date() if start else None), store


def _report(session, args):
    return _data(mcp_client.tool_payload(session.call_tool(REPORT_TOOL, args)), REPORT_TOOL).get("list") or []


def collect(session, campaign_id, store, start, end, now=None):
    """Rows for every day from start to end (inclusive), zero where nothing ran."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    start = max(start, end - datetime.timedelta(days=MAX_BACK))
    days, d = {}, start
    while d <= end:
        days[d.isoformat()] = {"day": d.isoformat(), "cost": 0.0, "gmv": 0.0, "orders": 0, "live_views": None,
                               "views_10s": None, "follows": None, "live_minutes": 0, "sessions": 0}
        d += datetime.timedelta(days=1)
    base = {"advertiser_id": ADVERTISER_ID, "store_ids": [store], "filtering": {"campaign_ids": [campaign_id]},
            "page_size": 100}

    chunk = start
    while chunk <= end:
        last = min(end, chunk + datetime.timedelta(days=DAY_SPAN - 1))
        span = dict(base, start_date=chunk.isoformat(), end_date=last.isoformat(),
                    dimensions=["campaign_id", "stat_time_day"])
        for r in _report(session, dict(span, metrics=MONEY)):
            row = days.get(str((r.get("dimensions") or {}).get("stat_time_day", ""))[:10])
            if row is not None:
                m = r.get("metrics") or {}
                row.update(cost=_num(m.get("cost")), gmv=_num(m.get("gross_revenue")), orders=int(_num(m.get("orders"))))
        try:                                   # traffic is a bonus: never lose the money figures over it
            for r in _report(session, dict(span, metrics=TRAFFIC)):
                row = days.get(str((r.get("dimensions") or {}).get("stat_time_day", ""))[:10])
                if row is not None:
                    m = r.get("metrics") or {}
                    row.update(live_views=int(_num(m.get("live_views"))),
                               views_10s=int(_num(m.get("10_second_live_views"))),
                               follows=int(_num(m.get("live_follows"))))
        except mcp_client.McpError:
            pass
        chunk = last + datetime.timedelta(days=1)

    # LIVE sessions that ran with ads, counted on the Malaysia day they started
    rooms = _report(session, dict(base, start_date=start.isoformat(), end_date=end.isoformat(),
                                  dimensions=["room_id"], metrics=["live_launched_time", "live_duration", "cost"]))
    for r in rooms:
        m = r.get("metrics") or {}
        began = _utc(m.get("live_launched_time"))
        if not began or _num(m.get("cost")) <= 0:
            continue
        row = days.get(began.astimezone(MYT).date().isoformat())
        if row is None:
            continue
        mins = minutes(m.get("live_duration"))
        if mins is None:                       # still live: count up to now
            mins = max(0, int((now - began).total_seconds() // 60))
        row["live_minutes"] += mins
        row["sessions"] += 1
    return [days[k] for k in sorted(days)]


SESSION_METRICS = ["live_status", "live_launched_time", "live_duration", "cost", "gross_revenue", "orders"]


def sessions(session, campaign_id, store, start, end, now=None):
    """One entry per LIVE room that ran with ads (or sold through the campaign) between start
    and end: start time, minutes, still live?, and that LIVE's own cost / GMV / orders. These are
    the per-LIVE figures the GMV Max dashboard shows, used for the morning report."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    rooms = _report(session, {"advertiser_id": ADVERTISER_ID, "store_ids": [store],
                              "filtering": {"campaign_ids": [campaign_id]}, "page_size": 100,
                              "start_date": start.isoformat(), "end_date": end.isoformat(),
                              "dimensions": ["room_id"], "metrics": SESSION_METRICS})
    out = []
    for r in rooms:
        m = r.get("metrics") or {}
        room = str((r.get("dimensions") or {}).get("room_id", ""))
        began = _utc(m.get("live_launched_time"))
        cost, gmv = _num(m.get("cost")), _num(m.get("gross_revenue"))
        if not room or not began or (cost <= 0 and gmv <= 0):
            continue
        mins = minutes(m.get("live_duration"))
        ongoing = str(m.get("live_status", "")).upper() == "ONGOING" or mins is None
        if mins is None:
            mins = max(0, int((now - began).total_seconds() // 60))
        out.append({"room_id": room, "started_at": began.isoformat(), "minutes": mins, "ongoing": ongoing,
                    "cost": cost, "gmv": gmv, "orders": int(_num(m.get("orders")))})
    return out
