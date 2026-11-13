"""GitHub Actions scheduler entrypoint.

Flow per run:
  1. Claim due operations from the portal (atomic; duplicates impossible).
  2. Get a short-lived TikTok MCP access token from the portal (refresh happens there).
  3. For each claim: fetch the campaign fresh via MCP and pass every safety check.
  4. DRY RUN (default): report what would happen. LIVE only when BOTH the portal switch
     and the repository variable SCHEDULER_LIVE_ARMED=true are on.
  5. Report the result back to the portal.

Exit code is 0 unless the run itself broke (so GitHub shows a red run you can see).
"""
import json
import os
import sys
import urllib.parse

from affiliate_scheduler import mcp_client, tiktok_ops
from affiliate_scheduler.safety import ADVERTISER_ID, APPROVED_AFFILIATES, PROTECTED_IDS


def log(**kw):
    print(json.dumps(kw, default=str), flush=True)


class Portal:
    def __init__(self, base, token, http=mcp_client._http):
        if not base.startswith("https://") and not base.startswith("http://127.0.0.1"):
            raise SystemExit("PORTAL_URL must be https")
        self.base, self.token, self.http = base.rstrip("/"), token, http

    def post(self, path, body):
        status, _, text = self.http("POST", self.base + path, body,
                                    {"Authorization": f"Bearer {self.token}", "Accept": "application/json"})
        try:
            data = json.loads(text)
        except ValueError:
            data = {"error": "BAD_RESPONSE", "message": text[:200]}
        return status, data


def precheck(op):
    """Reject anything that is not the exact approved campaign before any network call."""
    cid = str(op.get("campaign_id", ""))
    if cid in PROTECTED_IDS:
        return "Protected campaign"
    if cid not in APPROVED_AFFILIATES or op.get("campaign_name") != APPROVED_AFFILIATES[cid]:
        return "Campaign not approved"
    if op.get("advertiser_id") != ADVERTISER_ID:
        return "Wrong advertiser"
    if op.get("operation") not in ("ENABLE", "DISABLE"):
        return "Unsupported operation"
    return None


def run(portal, armed_env, run_id, http=mcp_client._http):
    status, claim = portal.post("/api/scheduler/runner/claim", {"run_id": run_id})
    if status != 200:
        log(event="claim_failed", status=status, error=claim.get("error"), message=claim.get("message"))
        return 1
    ops = claim.get("operations", [])
    live = bool(claim.get("live_enabled")) and armed_env
    mode = "LIVE" if live else "DRY_RUN"
    log(event="claimed", count=len(ops), mode=mode, portal_live=claim.get("live_enabled"), armed_env=armed_env)
    if not ops:
        return 0

    session = tools = None
    auth_problem = None
    status, tok = portal.post("/api/scheduler/runner/tiktok-token", {})
    if status == 200:
        token = tok["access_token"]
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::add-mask::{token}", flush=True)
        host = urllib.parse.urlsplit(tok["mcp_url"]).netloc
        if host != "business-api.tiktok.com":
            auth_problem = f"Refusing MCP host {host}"
        else:
            try:
                session = mcp_client.McpSession(tok["mcp_url"], token, http=http)
                session.initialize()
                tools = session.list_tools(wanted=[tiktok_ops.READ_TOOL, tiktok_ops.WRITE_TOOL])
            except mcp_client.McpError as e:
                auth_problem = f"MCP connection failed: {e}"
    else:
        auth_problem = f"{tok.get('error')}: {tok.get('message')}"

    broken = 0
    for op in ops:
        result, message = "failed", ""
        reason = precheck(op)
        if reason:
            result, message = "rejected", reason
        elif auth_problem:
            message = auth_problem
        else:
            try:
                result, message = tiktok_ops.set_status(session, tools, op["campaign_id"],
                                                        op["operation"], live)
            except ValueError as e:          # safety gate said no
                result, message = "rejected", str(e)
            except mcp_client.AuthError as e:
                message = f"TikTok authorization problem: {e}"
            except mcp_client.McpError as e:
                message = str(e)
        rs, rb = portal.post("/api/scheduler/runner/report", {
            "operation_id": op["operation_id"], "claim_token": op["claim_token"],
            "status": result, "message": message[:1000], "mode": mode})
        log(event="operation", operation_id=op["operation_id"], operation=op["operation"],
            result=result, message=message, attempt=op.get("attempt"), report_status=rs)
        if rs != 200:
            broken = 1
    return broken


def main():
    base = os.environ.get("PORTAL_URL", "")
    token = os.environ.get("SCHEDULER_RUNNER_TOKEN", "")
    if not base or not token:
        log(event="not_configured", message="PORTAL_URL / SCHEDULER_RUNNER_TOKEN secrets missing. Nothing done.")
        return 0
    armed = os.environ.get("SCHEDULER_LIVE_ARMED", "").strip().lower() == "true"
    run_id = f"{os.environ.get('GITHUB_RUN_ID', 'local')}-{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}"
    return run(Portal(base, token), armed, run_id)


if __name__ == "__main__":
    sys.exit(main())
