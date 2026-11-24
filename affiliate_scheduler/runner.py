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
import datetime
import json
import os
import sys
import urllib.parse

from affiliate_scheduler import live_history, live_stats, mcp_client, tiktok_ops
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
                tools = session.list_tools(
                    wanted=[tiktok_ops.READ_TOOL, tiktok_ops.WRITE_TOOL] + list(live_stats.TOOLS))
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
    report_history(portal, session, tools, auth_problem)
    report_stats(portal, session, tools, auth_problem)
    return broken


def report_history(portal, session, tools, auth_problem, now=None):
    """Read-only daily history for the app: today and yesterday every run (TikTok adds late
    orders to yesterday), and every day since the campaign started the first time. Never raises."""
    if auth_problem or session is None or any(t not in (tools or {}) for t in live_stats.TOOLS):
        return
    now = now or datetime.datetime.now(datetime.timezone.utc)
    today = now.astimezone(live_stats.MYT).date()
    try:
        status, cov = portal.post("/api/scheduler/runner/history-coverage", {})
    except Exception as e:
        status, cov = 0, {"message": str(e)}
    if status != 200:
        log(event="history", ok=False, error=f"coverage {status}: {cov.get('message', '')}"[:300])
        return
    for cid in APPROVED_AFFILIATES:
        try:
            first_run, store = live_history.campaign_info(session, cid)
            have = (cov.get("campaigns") or {}).get(cid)
            start = today - datetime.timedelta(days=1)
            if first_run and (not have or have > first_run.isoformat()):
                start = min(start, first_run)            # first time: fill every day since it started
            rows = live_history.collect(session, cid, store, start, today, now)
            rs, rb = portal.post("/api/scheduler/runner/history", {"campaign_id": cid, "rows": rows})
            log(event="history", campaign_id=cid, ok=rs == 200, days=len(rows), start=str(start),
                error="" if rs == 200 else str(rb.get("message", ""))[:200])
        except Exception as e:          # history must never break the scheduler
            log(event="history", campaign_id=cid, ok=False, error=str(e)[:300])


def report_stats(portal, session, tools, auth_problem):
    """Read-only LIVE stats for the app, after any ON/OFF work. Never raises."""
    for cid in APPROVED_AFFILIATES:
        try:
            if auth_problem or session is None:
                raise mcp_client.McpError(auth_problem or "no TikTok session")
            missing = [t for t in live_stats.TOOLS if t not in (tools or {})]
            if missing:
                raise mcp_client.McpError(f"TikTok MCP no longer offers {missing}")
            stats, error = live_stats.collect(session, cid), ""
        except Exception as e:          # stats must never break the scheduler
            stats, error = None, str(e)[:300]
        rs, _ = portal.post("/api/scheduler/runner/stats", {"campaign_id": cid, "stats": stats, "error": error})
        log(event="stats", campaign_id=cid, ok=stats is not None, error=error,
            is_live=(stats or {}).get("is_live"), report_status=rs)


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
