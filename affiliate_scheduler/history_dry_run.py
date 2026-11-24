"""Dry run of the daily history step against real TikTok data (manual workflow).

Gets the TikTok token from the portal like a normal run, then prints the day rows the
scheduler WOULD save. Nothing is written to the portal database or to TikTok.
"""
import json
import os
import sys

from affiliate_scheduler import live_stats, mcp_client, runner


class PrintOnly:
    """Real portal for the token; every history write is printed instead of sent."""

    def __init__(self, real):
        self.real = real

    def post(self, path, body):
        if path.endswith("/tiktok-token"):
            return self.real.post(path, body)
        if path.endswith("/history-coverage"):
            return 200, {"campaigns": {}}                  # pretend empty: shows the full backfill
        for r in body.get("rows", []):
            print(json.dumps({"campaign_id": body["campaign_id"], **r}), flush=True)
        return 200, {"ok": True}


def main():
    p = PrintOnly(runner.Portal(os.environ["PORTAL_URL"], os.environ["SCHEDULER_RUNNER_TOKEN"]))
    status, tok = p.post("/api/scheduler/runner/tiktok-token", {})
    if status != 200:
        print("token failed", tok.get("error"))
        return 1
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::add-mask::{tok['access_token']}", flush=True)
    s = mcp_client.McpSession(tok["mcp_url"], tok["access_token"])
    s.initialize()
    tools = s.list_tools(wanted=list(live_stats.TOOLS))
    runner.report_history(p, s, tools, None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
