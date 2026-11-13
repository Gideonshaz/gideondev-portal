"""Manual, read-only verification run from GitHub Actions (workflow_dispatch).

Step 1 (no secrets): confirm the TikTok MCP endpoint is reachable from GitHub's network
and that its OAuth metadata still supports what this project relies on: dynamic client
registration, authorization code + PKCE S256, refresh tokens, public client.

Step 2 (needs the portal connected): get an access token from the portal, open an MCP
session, check the two tool schemas, and READ campaign tashafrh. Never writes.
The result is sent to the portal and shown on the scheduler page.
"""
import os
import sys

from affiliate_scheduler import mcp_client, tiktok_ops
from affiliate_scheduler.runner import Portal, log
from affiliate_scheduler.safety import APPROVED_AFFILIATES

REQUIRED = {
    "registration_endpoint": None,
    "code_challenge_methods_supported": "S256",
    "grant_types_supported": "refresh_token",
}


def probe(mcp_url, http=mcp_client._http):
    meta = mcp_client.discover(mcp_url, http=http)
    problems = []
    for key, needed in REQUIRED.items():
        val = meta.get(key)
        if not val or (needed and needed not in val):
            problems.append(f"{key} missing {needed or ''}".strip())
    methods = meta.get("token_endpoint_auth_methods_supported") or []
    if methods and "none" not in methods:
        problems.append("public clients (token_endpoint_auth_method=none) not allowed")
    # Status-quo check that the MCP endpoint itself demands auth (not open, not gone).
    status, headers, _ = http("POST", mcp_url, {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                              {"Accept": "application/json, text/event-stream"})
    if status != 401:
        problems.append(f"unauthenticated MCP call returned HTTP {status}, expected 401")
    return meta, problems


def read_check(session, tools):
    campaign, status = tiktok_ops.read_campaign(session, tools, next(iter(APPROVED_AFFILIATES)))
    try:
        tiktok_ops.check_schema(tools, tiktok_ops.WRITE_TOOL, tiktok_ops.WRITE_ARGS)
        write = "matches"
    except tiktok_ops.SchemaChanged as e:
        write = f"CHANGED ({e})"
    return (f"OK: {campaign.name} ({campaign.campaign_id}) is {campaign.promotion_type}, status {status}. "
            f"{tiktok_ops.WRITE_TOOL} schema {write}. Read only, nothing changed.")


def main(http=mcp_client._http):
    mcp_url = os.environ.get("TIKTOK_MCP_URL") or mcp_client.DEFAULT_MCP_URL
    try:
        meta, problems = probe(mcp_url, http)
    except mcp_client.McpError as e:
        log(step="probe", ok=False, error=str(e))
        return 1
    log(step="probe", ok=not problems, problems=problems,
        authorization_endpoint=meta["authorization_endpoint"], token_endpoint=meta["token_endpoint"],
        registration_endpoint=meta.get("registration_endpoint"))
    if problems:
        return 1

    base, token = os.environ.get("PORTAL_URL", ""), os.environ.get("SCHEDULER_RUNNER_TOKEN", "")
    if not base or not token:
        log(step="read", skipped=True, reason="Portal secrets not set yet; endpoint check passed.")
        return 0
    portal = Portal(base, token, http)
    status, tok = portal.post("/api/scheduler/runner/tiktok-token", {})
    if status != 200:
        log(step="read", ok=False, error=tok.get("error"), message=tok.get("message"))
        return 0 if tok.get("error") == "TIKTOK_REAUTH_REQUIRED" and "not connected" in str(tok.get("message")) else 1
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::add-mask::{tok['access_token']}", flush=True)
    try:
        session = mcp_client.McpSession(tok["mcp_url"], tok["access_token"], http=http)
        session.initialize()
        tools = session.list_tools(wanted=[tiktok_ops.READ_TOOL, tiktok_ops.WRITE_TOOL])
        result = read_check(session, tools)
        ok = True
    except (mcp_client.McpError, ValueError) as e:
        result, ok = f"FAILED: {e}", False
    portal.post("/api/scheduler/runner/verify-result", {"result": result})
    log(step="read", ok=ok, result=result)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
