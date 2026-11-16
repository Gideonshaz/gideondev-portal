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
    today = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    day = today.strftime("%Y-%m-%d")
    attempts = {
        "gmv_max_report_get": {"advertiser_id": ADVERTISER_ID, "store_ids": [], "start_date": day, "end_date": day,
                               "dimensions": ["campaign_id"], "metrics": ["cost", "gross_revenue", "roi", "orders"],
                               "filtering": {"campaign_ids": [campaign_id]}},
    }
    for n, args in attempts.items():
        if n in tools and is_read_only(n):
            try:
                res = session.call_tool(n, args)
                log(step="try", tool=n, ok=True, result=shape(mcp_client.tool_payload(res)))
            except mcp_client.McpError as e:
                log(step="try", tool=n, ok=False, error=str(e)[:600])
    return 0


if __name__ == "__main__":
    sys.exit(main())
