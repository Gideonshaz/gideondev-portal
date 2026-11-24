"""Read-only discovery for the LIVE history feature (manual GitHub workflow).

For each approved affiliate campaign: which daily metrics TikTok returns for a LIVE GMV Max
campaign (campaign x day, room x day), and when the campaign started. Only the report and
info read tools are called. Nothing is changed anywhere.
"""
import datetime
import json
import os
import sys

from affiliate_scheduler import mcp_client
from affiliate_scheduler.runner import Portal
from affiliate_scheduler.safety import ADVERTISER_ID, APPROVED_AFFILIATES

MYT = datetime.timezone(datetime.timedelta(hours=8))
MONEY = ["cost", "gross_revenue", "roi", "orders", "cost_per_order"]
TRAFFIC = ["product_impressions", "product_clicks", "product_click_rate", "ad_click_rate",
           "ad_conversion_rate", "live_views", "10_second_live_views", "live_follows"]
ROOM = ["live_name", "live_launched_time", "live_duration"]


def log(**kw):
    print(json.dumps(kw, default=str)[:8000], flush=True)


def main():
    portal = Portal(os.environ["PORTAL_URL"], os.environ["SCHEDULER_RUNNER_TOKEN"])
    status, tok = portal.post("/api/scheduler/runner/tiktok-token", {})
    if status != 200:
        log(step="token", ok=False, error=tok.get("error"))
        return 1
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::add-mask::{tok['access_token']}", flush=True)
    s = mcp_client.McpSession(tok["mcp_url"], tok["access_token"])
    s.initialize()

    def call(tool, args, label):
        try:
            p = mcp_client.tool_payload(s.call_tool(tool, args))
            log(step=label, ok=True, result=p)
            return p
        except mcp_client.McpError as e:
            log(step=label, ok=False, error=str(e)[:600])
            return None

    today = datetime.datetime.now(MYT).date()
    start = (today - datetime.timedelta(days=6)).isoformat()
    for cid, name in APPROVED_AFFILIATES.items():
        info = call("campaign_gmv_max_info_get", {"advertiser_id": ADVERTISER_ID, "campaign_id": cid},
                    f"{name}:info") or {}
        d = info.get("data") or {}
        log(step=f"{name}:info_keys", keys=sorted(d.keys()),
            dates={k: d.get(k) for k in d if "time" in k or "date" in k})
        store = str(d.get("store_id") or "")
        base = {"advertiser_id": ADVERTISER_ID, "store_ids": [store], "start_date": start,
                "end_date": today.isoformat(), "filtering": {"campaign_ids": [cid]}, "page_size": 100}
        call("gmv_max_report_get", dict(base, dimensions=["campaign_id", "stat_time_day"], metrics=MONEY),
             f"{name}:day_money")
        call("gmv_max_report_get", dict(base, dimensions=["campaign_id", "stat_time_day"], metrics=TRAFFIC),
             f"{name}:day_traffic")
        for m in TRAFFIC:                     # one by one, so one bad metric does not hide the rest
            call("gmv_max_report_get", dict(base, dimensions=["campaign_id"], metrics=[m]), f"{name}:only:{m}")
        call("gmv_max_report_get", dict(base, dimensions=["room_id"], metrics=ROOM + MONEY[:2]),
             f"{name}:rooms")
        call("gmv_max_report_get", dict(base, dimensions=["room_id", "stat_time_day"], metrics=["live_duration", "cost"]),
             f"{name}:room_day")
        year = dict(base, start_date=(today - datetime.timedelta(days=364)).isoformat())
        call("gmv_max_report_get", dict(year, dimensions=["campaign_id"], metrics=MONEY), f"{name}:year_total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
