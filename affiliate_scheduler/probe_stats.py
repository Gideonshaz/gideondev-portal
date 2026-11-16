"""Read-only discovery for the LIVE stats feature (manual GitHub workflow).

Lists the TikTok Ads MCP tools that could supply LIVE GMV / cost / ROI or a
"host is live" signal, and tries ONE read call per candidate for campaign tashafrh.
It never calls a tool whose name suggests a write. Nothing is changed anywhere.
"""
import json, os, sys, datetime

from affiliate_scheduler import mcp_client
from affiliate_scheduler.runner import Portal
from affiliate_scheduler.safety import ADVERTISER_ID, APPROVED_AFFILIATES

WRITE_WORDS = ("update", "create", "delete", "set", "enable", "disable", "pause", "remove", "edit", "upload", "status")
INTEREST = ("report", "live", "gmv", "stat", "metric", "insight", "room", "session")


def log(**kw):
    print(json.dumps(kw, default=str)[:6000], flush=True)


def is_read_only(name):
    n = name.lower()
    return not any(w in n for w in WRITE_WORDS)


def shape(x, depth=0):
    """Keys and a few sample values, so we learn the format without dumping everything."""
    if depth > 4:
        return "…"
    if isinstance(x, dict):
        return {k: shape(v, depth + 1) for k, v in list(x.items())[:40]}
    if isinstance(x, list):
        return [shape(x[0], depth + 1), f"({len(x)} items)"] if x else []
    return x


def main():
    portal = Portal(os.environ["PORTAL_URL"], os.environ["SCHEDULER_RUNNER_TOKEN"])
    status, tok = portal.post("/api/scheduler/runner/tiktok-token", {})
    if status != 200:
        log(step="token", ok=False, error=tok.get("error"), message=tok.get("message"))
        return 1
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::add-mask::{tok['access_token']}", flush=True)
    session = mcp_client.McpSession(tok["mcp_url"], tok["access_token"])
    session.initialize()
    tools = session.list_tools()
    log(step="all_tools", count=len(tools), names=sorted(tools))
    cands = [n for n in sorted(tools) if any(w in n.lower() for w in INTEREST)]
    for n in cands:
        schema = tools[n].get("inputSchema") or {}
        log(step="schema", tool=n, read_only=is_read_only(n), description=(tools[n].get("description") or "")[:400],
            required=schema.get("required"), properties=shape(schema.get("properties") or {}))

    campaign_id = os.environ.get("PROBE_CAMPAIGN_ID", "1881634554090609")
    for n in ("gmv_max_report_get", "identity_live_get", "campaign_gmv_max_info_get"):
        if n in tools:
            sch = tools[n].get("inputSchema") or {}
            print(json.dumps({"step": "full_schema", "tool": n, "description": tools[n].get("description"),
                              "schema": sch}, default=str)[:20000], flush=True)

    def call(n, args):
        if n not in tools or not is_read_only(n):
            log(step="try", tool=n, ok=False, error="not offered or not read-only"); return None
        try:
            payload = mcp_client.tool_payload(session.call_tool(n, args))
            print(json.dumps({"step": "try", "tool": n, "ok": True, "result": payload}, default=str)[:12000], flush=True)
            return payload
        except mcp_client.McpError as e:
            log(step="try", tool=n, ok=False, error=str(e)[:800]); return None

    info = call("campaign_gmv_max_info_get", {"advertiser_id": ADVERTISER_ID, "campaign_id": campaign_id}) or {}
    flat = json.dumps(info)
    import re
    store = (re.findall(r'"store_id": "?(\d+)', flat) or [None])[0]
    ident = re.findall(r'"identity_id": "?([\w-]+)', flat)
    itype = re.findall(r'"identity_type": "?(\w+)', flat)
    log(step="found", store_id=store, identity_ids=ident[:5], identity_types=itype[:5])
    today = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d")
    if store:
        call("gmv_max_report_get", {"advertiser_id": ADVERTISER_ID, "store_ids": [store], "start_date": today,
                                    "end_date": today, "dimensions": ["campaign_id"],
                                    "metrics": ["cost", "gross_revenue", "roi", "orders"],
                                    "filtering": {"campaign_ids": [campaign_id]}})
    if store:
        call("gmv_max_report_get", {"advertiser_id": ADVERTISER_ID, "store_ids": [store], "start_date": today,
                                    "end_date": today, "dimensions": ["room_id"],
                                    "metrics": ["live_name", "live_status", "live_launched_time", "live_duration",
                                                "live_views", "cost", "gross_revenue", "roi", "orders"],
                                    "filtering": {"campaign_ids": [campaign_id]}})
    bc = (re.findall(r'"identity_authorized_bc_id": "?(\d+)', flat) or [None])[0]
    if ident:
        call("identity_live_get", {"advertiser_id": ADVERTISER_ID, "identity_id": ident[0], "cursor": 0,
                                   "identity_type": itype[0] if itype else "TT_USER",
                                   "identity_authorized_bc_id": bc})
    return 0


if __name__ == "__main__":
    sys.exit(main())
