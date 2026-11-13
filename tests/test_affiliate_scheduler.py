"""Affiliate LIVE scheduler: timing, portal API, claiming, OAuth storage, runner, verify.

No test talks to TikTok. A fake MCP server (FakeTikTok) stands in for it and records
every tool call, so the tests can prove what was (and was not) written.
"""
import json
import os
from datetime import date, datetime, time, timedelta, timezone

import psycopg
import pytest

import app as portal_app
from affiliate_scheduler import mcp_client, portal, runner, timing, verify
from affiliate_scheduler.safety import ADVERTISER_ID, PROTECTED_IDS

APPROVED = "1881634554090609"
MYT = timing.MYT
RUNNER_TOKEN = "r" * 40
MCP = "https://business-api.tiktok.com/open_mcp/tt-ads-mcp-flat"


def utc(y, mo, d, h, mi, tz=MYT):
    return datetime(y, mo, d, h, mi, tzinfo=tz).astimezone(timezone.utc)


# ------------------------------------------------------------------ timing
def test_myt_conversion_and_lead():
    enable, end = timing.window(date(2026, 11, 20), time(17, 0), time(19, 0), 10)
    assert enable == datetime(2026, 11, 20, 8, 50, tzinfo=timezone.utc)   # 16:50 MYT
    assert end == datetime(2026, 11, 20, 11, 0, tzinfo=timezone.utc)      # 19:00 MYT


def test_overnight_window_ends_next_day():
    enable, end = timing.window(date(2026, 11, 20), time(22, 0), time(0, 30), 0)
    assert end - enable == timedelta(hours=2, minutes=30)
    assert end.astimezone(MYT).date() == date(2026, 11, 21)


def sched(**kw):
    d = {"id": 1, "schedule_type": "once", "live_date": date(2026, 11, 20), "weekdays": [],
         "live_start": time(17, 0), "live_end": time(19, 0), "lead_minutes": 10,
         "effective_from": utc(2026, 11, 1, 0, 0)}
    d.update(kw)
    return d


def test_classify_due_missed_pending():
    ops = timing.operations(sched(), utc(2026, 11, 20, 17, 0))
    en, dis = ops
    assert timing.classify(en, utc(2026, 11, 20, 16, 40)) == "pending"
    assert timing.classify(en, utc(2026, 11, 20, 16, 55)) == "due"
    assert timing.classify(en, utc(2026, 11, 20, 18, 59)) == "due"      # late but LIVE still on
    assert timing.classify(en, utc(2026, 11, 20, 19, 0)) == "missed"    # never enable after LIVE
    assert timing.classify(dis, utc(2026, 11, 20, 19, 0)) == "due"
    assert timing.classify(dis, utc(2026, 11, 21, 0, 59)) == "due"      # late OFF is still safe
    assert timing.classify(dis, utc(2026, 11, 21, 1, 0)) == "missed"


def test_weekly_dates_and_effective_from():
    s = sched(schedule_type="weekly", live_date=None, weekdays=[4])   # Fridays
    ops = timing.operations(s, utc(2026, 11, 20, 12, 0))               # Fri 20 Nov
    assert {o.occurrence for o in ops} == {date(2026, 11, 20)}
    s["effective_from"] = utc(2026, 11, 20, 20, 0)                     # created after window
    assert timing.operations(s, utc(2026, 11, 20, 21, 0)) == []


# ------------------------------------------------------------------ validation
def payload(**kw):
    tomorrow = (datetime.now(MYT) + timedelta(days=1)).date().isoformat()
    d = {"campaign_id": APPROVED, "schedule_type": "once", "live_date": tomorrow,
         "live_start": "17:00", "live_end": "19:00", "lead_minutes": 10}
    d.update(kw)
    return d


@pytest.mark.parametrize("bad,msg", [
    ({"campaign_id": "1869666392557778"}, "protected"),
    ({"campaign_id": "1869665454413026"}, "protected"),
    ({"campaign_id": "1869665286717649"}, "protected"),
    ({"campaign_id": "123"}, "not approved"),
    ({"schedule_type": "daily"}, "schedule_type"),
    ({"live_end": "17:00"}, "same time"),
    ({"lead_minutes": 500}, "lead_minutes"),
    ({"live_date": "2020-01-01"}, "already ended"),
    ({"schedule_type": "weekly", "weekdays": [7]}, "weekdays"),
    ({"live_start": "5pm"}, "HH:MM"),
])
def test_validate_rejects(bad, msg):
    with pytest.raises(ValueError, match=msg):
        portal.validate(payload(**bad))


def test_validate_ignores_client_name_and_advertiser():
    v = portal.validate(payload(campaign_name="ViVid HAIR", advertiser_id="999"))
    assert v["campaign_name"] == "tashafrh" and v["advertiser_id"] == ADVERTISER_ID


# ------------------------------------------------------------------ portal fixtures
@pytest.fixture
def env(monkeypatch, client):
    monkeypatch.setenv("SCHEDULER_RUNNER_TOKEN", RUNNER_TOKEN)
    client.get("/health")  # runs migrations
    return client


@pytest.fixture
def device(env):
    import hashlib
    tok = "gds_" + "d" * 40
    with portal_app.db() as conn:
        conn.execute("INSERT INTO sched_devices (name, token_hash) VALUES ('t', %s)",
                     (hashlib.sha256(tok.encode()).hexdigest(),))
    return {"Authorization": f"Bearer {tok}"}


def conn():
    return psycopg.connect(os.environ["DATABASE_URL"])


def add_schedule(**kw):
    d = {"schedule_type": "once", "live_date": date(2026, 11, 20), "weekdays": [], "live_start": time(17, 0),
         "live_end": time(19, 0), "lead_minutes": 10, "active": True}
    d.update(kw, adv=ADVERTISER_ID, cid=APPROVED)
    with conn() as c:
        return c.execute("""INSERT INTO sched_schedules (advertiser_id, campaign_id, campaign_name, schedule_type,
                live_date, weekdays, live_start, live_end, lead_minutes, active, effective_from, created_at)
                VALUES (%(adv)s,%(cid)s,'tashafrh',%(schedule_type)s,%(live_date)s,%(weekdays)s,%(live_start)s,
                %(live_end)s,%(lead_minutes)s,%(active)s,'2026-11-01','2026-11-01') RETURNING id""",
                         d).fetchone()[0]


# ------------------------------------------------------------------ database guard
def test_db_refuses_other_campaigns(env):
    for cid in list(PROTECTED_IDS) + ["123"]:
        with conn() as c, pytest.raises(psycopg.errors.CheckViolation):
            c.execute("""INSERT INTO sched_schedules (advertiser_id, campaign_id, campaign_name, schedule_type,
                         live_date, live_start, live_end) VALUES (%s,%s,'tashafrh','once','2026-11-20','17:00','19:00')""",
                      (ADVERTISER_ID, cid))


def test_existing_portal_tables_untouched(env):
    with conn() as c:
        names = {r[0] for r in c.execute("SELECT name FROM schema_migrations")}
    assert "007_team_accounts" in names and "008_affiliate_scheduler" in names


# ------------------------------------------------------------------ Android API
def test_api_requires_device_token(env):
    assert env.get("/api/scheduler/v1/schedules").status_code == 401
    assert env.get("/api/scheduler/v1/schedules", headers={"Authorization": "Bearer nope-nope-nope-nope-nope"}).status_code == 401


def test_api_crud(env, device):
    r = env.post("/api/scheduler/v1/schedules", json=payload(label="Tasha evening"), headers=device)
    assert r.status_code == 201, r.json
    s = r.json["schedule"]
    assert s["campaign_name"] == "tashafrh" and s["timezone"] == "Asia/Kuala_Lumpur"
    assert [o["operation"] for o in s["next_operations"]] == ["ENABLE", "DISABLE"]
    sid = s["id"]
    r = env.put(f"/api/scheduler/v1/schedules/{sid}", json=payload(live_start="18:00", live_end="20:00"), headers=device)
    assert r.json["schedule"]["live_start"] == "18:00"
    r = env.post(f"/api/scheduler/v1/schedules/{sid}/active", json={"active": False}, headers=device)
    assert r.json["schedule"]["active"] is False and r.json["schedule"]["next_operations"] == []
    assert env.delete(f"/api/scheduler/v1/schedules/{sid}", headers=device).status_code == 200
    assert env.get("/api/scheduler/v1/schedules", headers=device).json["schedules"] == []
    bad = env.post("/api/scheduler/v1/schedules", json=payload(campaign_id="1869665286717649"), headers=device)
    assert bad.status_code == 400 and "protected" in bad.json["message"]


def test_api_status_and_campaigns(env, device):
    st = env.get("/api/scheduler/v1/status", headers=device).json
    assert st["live_enabled"] is False and st["mode"] == "DRY_RUN" and st["tiktok"]["state"] == "NOT_CONNECTED"
    camps = env.get("/api/scheduler/v1/campaigns", headers=device).json["campaigns"]
    assert [c["campaign_id"] for c in camps] == [APPROVED]


# ------------------------------------------------------------------ claiming
def claim(now):
    with conn() as c:
        return portal.claim_due(c, now, "test")


def test_claim_once_only(env):
    add_schedule()
    first = claim(utc(2026, 11, 20, 16, 55))
    assert [o["operation"] for o in first] == ["ENABLE"]
    assert claim(utc(2026, 11, 20, 16, 56)) == []          # duplicate run gets nothing


def test_failed_retries_then_stops(env):
    add_schedule()
    op = claim(utc(2026, 11, 20, 16, 55))[0]
    for attempt in (2, 3):
        with conn() as c:
            c.execute("UPDATE sched_executions SET status='failed' WHERE operation_id=%s", (op["operation_id"],))
        again = claim(utc(2026, 11, 20, 16, 57))
        assert again[0]["attempt"] == attempt
    with conn() as c:
        c.execute("UPDATE sched_executions SET status='failed' WHERE operation_id=%s", (op["operation_id"],))
    assert claim(utc(2026, 11, 20, 16, 59)) == []          # MAX_ATTEMPTS reached


def test_stale_claim_is_reclaimed(env):
    add_schedule()
    assert claim(utc(2026, 11, 20, 16, 55))[0]["attempt"] == 1
    assert claim(utc(2026, 11, 20, 17, 4)) == []            # 9 min: still owned by the first run
    assert claim(utc(2026, 11, 20, 17, 6))[0]["attempt"] == 2  # 11 min: assumed crashed, retried


def test_missed_enable_recorded_not_run(env):
    add_schedule()
    ops = claim(utc(2026, 11, 20, 19, 30))                  # runner was down for the whole LIVE
    assert [o["operation"] for o in ops] == ["DISABLE"]
    with conn() as c:
        st = c.execute("SELECT status FROM sched_executions WHERE operation LIKE 'ENABLE'").fetchone()[0]
    assert st == "missed"


def test_overlap_keeps_campaign_on(env):
    add_schedule(live_start=time(17, 0), live_end=time(19, 0))
    add_schedule(live_start=time(18, 30), live_end=time(21, 0), lead_minutes=0)
    ops = claim(utc(2026, 11, 20, 19, 5))
    assert all(o["operation"] != "DISABLE" for o in ops)
    with conn() as c:
        assert c.execute("SELECT count(*) FROM sched_executions WHERE status='skipped_overlap'").fetchone()[0] == 1


def test_deactivated_mid_live_still_turns_off(env):
    sid = add_schedule()
    op = claim(utc(2026, 11, 20, 16, 55))[0]
    with conn() as c:
        c.execute("UPDATE sched_executions SET status='succeeded' WHERE operation_id=%s", (op["operation_id"],))
        c.execute("UPDATE sched_schedules SET active=false, updated_at=now() WHERE id=%s", (sid,))
    assert [o["operation"] for o in claim(utc(2026, 11, 20, 19, 2))] == ["DISABLE"]


def test_deactivated_before_live_does_nothing(env):
    sid = add_schedule()
    with conn() as c:
        c.execute("UPDATE sched_schedules SET active=false, updated_at=now() WHERE id=%s", (sid,))
    assert claim(utc(2026, 11, 20, 16, 55)) == [] and claim(utc(2026, 11, 20, 19, 2)) == []


def test_runner_endpoints_need_token(env, monkeypatch):
    assert env.post("/api/scheduler/runner/claim", json={}).status_code == 401
    monkeypatch.setenv("SCHEDULER_RUNNER_TOKEN", "short")
    assert env.post("/api/scheduler/runner/claim", json={},
                    headers={"Authorization": "Bearer short"}).status_code == 503


def test_report_requires_matching_claim(env):
    h = {"Authorization": f"Bearer {RUNNER_TOKEN}"}
    r = env.post("/api/scheduler/runner/report", json={"operation_id": "x", "claim_token": "y", "status": "dry_run"},
                 headers=h)
    assert r.status_code == 409


# ------------------------------------------------------------------ OAuth storage / refresh
def connect(access="AT1", refresh="RT1", expires_in=3600, authorized=None):
    now = datetime.now(timezone.utc)
    with portal_app.db() as c:
        c.execute("""INSERT INTO sched_tiktok_auth (id, mcp_url, client_id, token_endpoint, resource,
                       access_token_enc, access_expires_at, refresh_token_enc, authorized_at)
                     VALUES (1,%s,'cid',%s,%s,%s,%s,%s,%s)""",
                  (MCP, MCP + "/oauth/token", MCP, portal.enc(access), now + timedelta(seconds=expires_in),
                   portal.enc(refresh), authorized or now))


def test_token_returned_when_fresh(env):
    connect()
    tok, url, _ = portal.get_access_token(http=lambda *a, **k: pytest.fail("no refresh expected"))
    assert tok == "AT1" and url == MCP


def test_token_refresh_rotates(env):
    connect(expires_in=60)
    calls = []

    def http(method, url, data=None, headers=None, form=False):
        calls.append(data)
        return 200, {}, json.dumps({"access_token": "AT2", "refresh_token": "RT2", "expires_in": 7200})
    tok, _, _ = portal.get_access_token(http=http)
    assert tok == "AT2" and calls[0]["grant_type"] == "refresh_token" and calls[0]["refresh_token"] == "RT1"
    tok, _, _ = portal.get_access_token(http=lambda *a, **k: pytest.fail("cached"))
    assert tok == "AT2"


def test_expired_authorization_needs_reauth(env):
    connect(expires_in=60)

    def http(*a, **k):
        return 400, {}, json.dumps({"error": "invalid_grant"})
    with pytest.raises(portal.ReauthRequired):
        portal.get_access_token(http=http)
    h = {"Authorization": f"Bearer {RUNNER_TOKEN}"}
    r = env.post("/api/scheduler/runner/tiktok-token", headers=h)
    assert r.status_code == 503 and r.json["error"] == "TIKTOK_REAUTH_REQUIRED"


def test_not_connected_token_endpoint(env):
    r = env.post("/api/scheduler/runner/tiktok-token", headers={"Authorization": f"Bearer {RUNNER_TOKEN}"})
    assert r.status_code == 503


def test_oauth_connect_and_finish(admin, monkeypatch):
    from conftest import token as csrf_token
    meta = {"authorization_endpoint": "https://business-api.tiktok.com/portal/mcp-tt4b-authorize",
            "token_endpoint": MCP + "/oauth/token", "registration_endpoint": MCP + "/oauth/register",
            "resource": MCP, "scopes": ["mcp:tt4b"]}
    monkeypatch.setattr(mcp_client, "discover", lambda url: meta)
    monkeypatch.setattr(mcp_client, "register_client", lambda m, r: {"client_id": "cid-1"})
    r = admin.post("/scheduler/tiktok/connect", data={"csrf": csrf_token(admin)})
    assert r.status_code == 200 and b"Authorize on TikTok" in r.data
    with portal_app.db() as c:
        state = c.execute("SELECT state FROM sched_oauth_pending").fetchone()[0]
    page = admin.get(f"/scheduler/tiktok/callback?code=abc&state={state}")
    assert b"Finish" in page.data
    seen = {}

    def exchange(ep, cid, code, ruri, verifier, resource, secret):
        seen.update(cid=cid, code=code, verifier=verifier)
        return {"access_token": "AT", "refresh_token": "RT", "expires_in": 3600}
    monkeypatch.setattr(mcp_client, "exchange_code", exchange)
    r = admin.get(f"/scheduler/tiktok/finish?code=abc&state={state}")
    assert r.status_code == 302 and seen["cid"] == "cid-1" and len(seen["verifier"]) > 40
    # state is single use
    r = admin.get(f"/scheduler/tiktok/finish?code=abc&state={state}")
    assert r.status_code == 302
    with portal_app.db() as c:
        row = c.execute("SELECT access_token_enc FROM sched_tiktok_auth").fetchone()
    assert row[0] != "AT" and portal.dec(row[0]) == "AT"     # stored encrypted


def test_scheduler_page_admin_only(env, admin):
    assert env.get("/scheduler").status_code in (200, 302)
    assert admin.get("/scheduler").status_code == 200


def test_live_switch_needs_typed_confirmation(admin):
    from conftest import token as csrf_token
    admin.post("/scheduler/live", data={"csrf": csrf_token(admin), "live": "on", "confirm": "yes"})
    with portal_app.db() as c:
        assert c.execute("SELECT live_enabled FROM sched_settings").fetchone()[0] is False


# ------------------------------------------------------------------ fake TikTok MCP
class FakeTikTok:
    def __init__(self, campaign=None, write_schema=True, read_schema=True):
        self.campaign = campaign or {"campaign_id": APPROVED, "campaign_name": "tashafrh",
                                     "advertiser_id": ADVERTISER_ID, "operation_status": "DISABLE"}
        self.calls = []
        self.write_schema, self.read_schema = write_schema, read_schema

    def tools(self):
        read_props = {"advertiser_id": {}, "filtering": {}} if self.read_schema else {"advertiser_id": {}}
        t = [{"name": "gmv_max_campaign_get", "inputSchema": {"properties": read_props}}]
        if self.write_schema:
            t.append({"name": "campaign_status_update", "inputSchema": {"properties": {
                "advertiser_id": {}, "campaign_ids": {}, "operation_status": {}}}})
        return t

    def __call__(self, method, url, data=None, headers=None, form=False):
        assert url.startswith("https://business-api.tiktok.com/")
        m = data.get("method")
        if "id" not in data:
            return 202, {}, ""
        if m == "initialize":
            res = {"protocolVersion": "2025-06-18"}
        elif m == "tools/list":
            res = {"tools": self.tools()}
        elif m == "tools/call":
            name, args = data["params"]["name"], data["params"]["arguments"]
            self.calls.append((name, args))
            if name == "campaign_status_update":
                self.campaign["operation_status"] = args["operation_status"]
                res = {"content": [{"type": "text", "text": json.dumps({"code": 0})}]}
            else:
                payload = {"code": 0, "data": {"list": [dict(self.campaign)]}}
                res = {"content": [{"type": "text", "text": json.dumps(payload)}]}
        body = "event: message\ndata: " + json.dumps({"jsonrpc": "2.0", "id": data["id"], "result": res}) + "\n\n"
        return 200, {"Mcp-Session-Id": "sess"}, body

    def writes(self):
        return [c for c in self.calls if c[0] == "campaign_status_update"]


class FakePortal:
    def __init__(self, ops, live=False, token_status=200):
        self.ops, self.live, self.token_status = ops, live, token_status
        self.reports = []

    def post(self, path, body):
        if path.endswith("/claim"):
            return 200, {"live_enabled": self.live, "operations": self.ops}
        if path.endswith("/tiktok-token"):
            if self.token_status != 200:
                return self.token_status, {"error": "TIKTOK_REAUTH_REQUIRED", "message": "renew"}
            return 200, {"access_token": "AT", "mcp_url": MCP}
        self.reports.append(body)
        return 200, {"ok": True}


def op(operation="ENABLE", **kw):
    d = {"operation_id": f"s1-2026-11-20-{operation}", "claim_token": "t", "campaign_id": APPROVED,
         "campaign_name": "tashafrh", "advertiser_id": ADVERTISER_ID, "operation": operation, "attempt": 1}
    d.update(kw)
    return d


def test_runner_dry_run_never_writes():
    tk, p = FakeTikTok(), FakePortal([op("ENABLE")], live=True)
    assert runner.run(p, armed_env=False, run_id="t", http=tk) == 0     # repo variable off
    assert tk.writes() == [] and p.reports[0]["status"] == "dry_run" and p.reports[0]["mode"] == "DRY_RUN"
    tk, p = FakeTikTok(), FakePortal([op("ENABLE")], live=False)
    runner.run(p, armed_env=True, run_id="t", http=tk)                   # portal switch off
    assert tk.writes() == [] and p.reports[0]["status"] == "dry_run"


def test_runner_live_writes_only_approved_id():
    """Only reachable when BOTH switches are on; exercised here against the fake server only."""
    tk, p = FakeTikTok(), FakePortal([op("ENABLE")], live=True)
    runner.run(p, armed_env=True, run_id="t", http=tk)
    assert tk.writes() == [("campaign_status_update", {"advertiser_id": ADVERTISER_ID,
                                                        "campaign_ids": [APPROVED], "operation_status": "ENABLE"})]
    assert p.reports[0]["status"] == "succeeded" and "verified" in p.reports[0]["message"]


@pytest.mark.parametrize("bad", [
    {"campaign_id": "1869666392557778", "campaign_name": "ViVid HAIR Malaysia"},
    {"campaign_id": "1869665454413026"}, {"campaign_id": "1869665286717649"},
    {"campaign_id": "999"}, {"advertiser_id": "123"}, {"operation": "DELETE"},
    {"campaign_name": "ViVid HAIR"},
])
def test_runner_rejects_before_any_call(bad):
    tk, p = FakeTikTok(), FakePortal([op(**bad)], live=True)
    runner.run(p, armed_env=True, run_id="t", http=tk)
    assert p.reports[0]["status"] == "rejected"
    assert tk.calls == []                                                # never even read


@pytest.mark.parametrize("campaign,why", [
    ({"campaign_id": APPROVED, "campaign_name": "tasha", "operation_status": "DISABLE"}, "approved"),
    ({"campaign_id": APPROVED, "campaign_name": "tashafrh", "gmv_max_promotion_type": "PRODUCT_GMV_MAX",
      "operation_status": "DISABLE"}, "LIVE GMV Max"),
    ({"campaign_id": APPROVED, "campaign_name": "tashafrh", "advertiser_id": "1",
      "operation_status": "DISABLE"}, "advertiser"),
])
def test_runner_rejects_on_live_lookup_mismatch(campaign, why):
    tk, p = FakeTikTok(campaign=campaign), FakePortal([op("ENABLE")], live=True)
    runner.run(p, armed_env=True, run_id="t", http=tk)
    assert p.reports[0]["status"] == "rejected" and why.lower() in p.reports[0]["message"].lower()
    assert tk.writes() == []


def test_runner_schema_change_fails_closed():
    tk, p = FakeTikTok(write_schema=False), FakePortal([op("ENABLE")], live=True)
    runner.run(p, armed_env=True, run_id="t", http=tk)
    assert p.reports[0]["status"] == "failed" and "campaign_status_update" in p.reports[0]["message"]
    tk, p = FakeTikTok(read_schema=False), FakePortal([op("ENABLE")], live=True)
    runner.run(p, armed_env=True, run_id="t", http=tk)
    assert p.reports[0]["status"] == "failed" and tk.writes() == []


def test_runner_auth_failure_reported():
    tk, p = FakeTikTok(), FakePortal([op("DISABLE")], live=True, token_status=503)
    runner.run(p, armed_env=True, run_id="t", http=tk)
    assert p.reports[0]["status"] == "failed" and "REAUTH" in p.reports[0]["message"] and tk.calls == []


def test_runner_mcp_401_is_auth_error():
    def http(*a, **k):
        return 401, {}, ""
    p = FakePortal([op("ENABLE")], live=False)
    runner.run(p, armed_env=False, run_id="t", http=http)
    assert p.reports[0]["status"] == "failed" and "401" in p.reports[0]["message"]


def test_runner_portal_down():
    class Down:
        def post(self, path, body):
            return 502, {"error": "BAD_RESPONSE"}
    assert runner.run(Down(), armed_env=False, run_id="t") == 1


def test_runner_unconfigured_is_noop(monkeypatch):
    monkeypatch.delenv("PORTAL_URL", raising=False)
    assert runner.main() == 0


# ------------------------------------------------------------------ MCP client / verify
def meta_http(meta_overrides=None, mcp_status=401):
    meta = {"issuer": MCP + "/oauth", "authorization_endpoint": "https://business-api.tiktok.com/portal/mcp-tt4b-authorize",
            "token_endpoint": MCP + "/oauth/token", "registration_endpoint": MCP + "/oauth/register",
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"]}
    meta.update(meta_overrides or {})

    def http(method, url, data=None, headers=None, form=False):
        if url.endswith("/.well-known/oauth-protected-resource/open_mcp/tt-ads-mcp-flat"):
            return 200, {}, json.dumps({"resource": MCP, "authorization_servers": [MCP + "/oauth"],
                                        "scopes_supported": ["mcp:tt4b"]})
        if url == MCP + "/oauth/.well-known/oauth-authorization-server":
            return 200, {}, json.dumps(meta)
        if url == MCP:
            return mcp_status, {}, ""
        return 404, {}, ""
    return http


def test_discover_matches_tiktok_layout():
    m = mcp_client.discover(MCP, http=meta_http())
    assert m["registration_endpoint"].endswith("/oauth/register") and m["resource"] == MCP


def test_verify_probe_ok_and_detects_regressions():
    _, problems = verify.probe(MCP, http=meta_http())
    assert problems == []
    _, problems = verify.probe(MCP, http=meta_http({"registration_endpoint": None}))
    assert any("registration" in p for p in problems)
    _, problems = verify.probe(MCP, http=meta_http({"grant_types_supported": ["authorization_code"]}))
    assert any("refresh_token" in p for p in problems)
    _, problems = verify.probe(MCP, http=meta_http(mcp_status=200))
    assert any("401" in p for p in problems)


def test_verify_read_check_is_read_only():
    tk = FakeTikTok()
    s = mcp_client.McpSession(MCP, "AT", http=tk)
    s.initialize()
    msg = verify.read_check(s, {t["name"]: t for t in tk.tools()})
    assert msg.startswith("OK: tashafrh") and tk.writes() == []


def test_authorize_url_has_pkce_and_resource():
    url = mcp_client.authorize_url({"authorization_endpoint": "https://business-api.tiktok.com/portal/mcp-tt4b-authorize",
                                    "resource": MCP, "scopes": ["mcp:tt4b"]}, "cid", "https://p/cb", "st", "ch")
    assert "code_challenge_method=S256" in url and "resource=" in url and "scope=mcp%3Att4b" in url
