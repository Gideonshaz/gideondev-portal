"""Daily LIVE history: collector, runner step (backfill + refresh), portal endpoints, DB lock."""
from datetime import datetime, timezone

import psycopg
import pytest

from affiliate_scheduler import live_history, mcp_client, runner
from test_affiliate_scheduler import APPROVED, MCP, RUNNER_TOKEN, FakePortal, FakeTikTok, conn, device, env  # noqa: F401

NAZIFA = "1882182698757202"
NOW = datetime(2026, 11, 16, 15, 0, tzinfo=timezone.utc)      # 23:00 Malaysia time, 16 Nov


def session(tk):
    s = mcp_client.McpSession(MCP, "AT", http=tk)
    s.initialize()
    return s, s.list_tools()


def test_minutes():
    assert live_history.minutes("2h 1m") == 121
    assert live_history.minutes("0h 54m") == 54
    assert live_history.minutes("45m") == 45
    assert live_history.minutes("") is None and live_history.minutes(None) is None


def test_first_run_backfills_from_campaign_start():
    tk, p = FakeTikTok(stats_tools=True), FakePortal([])
    s, tools = session(tk)
    runner.report_history(p, s, tools, None, now=NOW)
    assert tk.writes() == []                                       # read only
    assert {c[0] for c in tk.calls} == {"campaign_gmv_max_info_get", "gmv_max_report_get"}
    h = {x["campaign_id"]: x["rows"] for x in p.history}
    rows = {r["day"]: r for r in h[APPROVED]}
    assert min(rows) == "2026-11-12" and max(rows) == "2026-11-16"   # every day since the start
    assert rows["2026-11-16"]["gmv"] == 168.2 and rows["2026-11-16"]["orders"] == 10
    assert rows["2026-11-16"]["live_views"] == 1087 and rows["2026-11-16"]["follows"] == 4
    assert rows["2026-11-16"]["sessions"] == 1 and rows["2026-11-16"]["live_minutes"] == 100   # still live
    assert rows["2026-11-15"]["cost"] == 20.0 and rows["2026-11-13"]["cost"] == 0
    assert rows["2026-11-12"]["sessions"] == 0                     # that LIVE had no ads


def test_later_runs_refresh_only_yesterday_and_today():
    tk, p = FakeTikTok(stats_tools=True), FakePortal([])
    p.coverage = {APPROVED: "2026-11-12", NAZIFA: "2026-11-12"}
    s, tools = session(tk)
    runner.report_history(p, s, tools, None, now=NOW)
    assert [r["day"] for r in p.history[0]["rows"]] == ["2026-11-15", "2026-11-16"]


def test_history_problems_never_break_the_run():
    tk, p = FakeTikTok(stats_tools=False), FakePortal([])
    s, tools = session(tk)
    runner.report_history(p, s, tools, None, now=NOW)                # tools missing: quietly skipped
    runner.report_history(p, None, None, "REAUTH", now=NOW)
    assert p.history == []


def test_history_endpoints(env, device):
    h = {"Authorization": f"Bearer {RUNNER_TOKEN}"}
    assert env.post("/api/scheduler/runner/history", json={}).status_code == 401
    assert env.get("/api/scheduler/v1/history").status_code == 401
    assert env.post("/api/scheduler/runner/history", headers=h,
                    json={"campaign_id": "1869666392557778", "rows": []}).status_code == 400
    assert env.post("/api/scheduler/runner/history-coverage", headers=h, json={}).json["campaigns"] == {
        APPROVED: None, NAZIFA: None}
    rows = [{"day": "2026-11-15", "cost": 20, "gmv": 100, "orders": 4, "live_views": 500, "views_10s": 100,
             "follows": 2, "live_minutes": 120, "sessions": 1},
            {"day": "2026-11-16", "cost": 10, "gmv": 70, "orders": 6, "live_views": None, "views_10s": None,
             "follows": None, "live_minutes": 60, "sessions": 1},
            {"day": "bad", "cost": 1}, {"day": "2026-11-14", "cost": -5}]
    r = env.post("/api/scheduler/runner/history", headers=h, json={"campaign_id": APPROVED, "rows": rows})
    assert r.json["saved"] == 2 and r.json["skipped"] == 2
    assert env.post("/api/scheduler/runner/history-coverage", headers=h, json={}).json["campaigns"][APPROVED] == "2026-11-15"
    # a later refresh without traffic keeps the views already saved
    env.post("/api/scheduler/runner/history", headers=h, json={"campaign_id": APPROVED, "rows": [
        dict(rows[0], cost=25, live_views=None, views_10s=None, follows=None)]})
    r = env.get("/api/scheduler/v1/history?from=2026-11-15&to=2026-11-16", headers=device).json
    c = next(x for x in r["campaigns"] if x["campaign_id"] == APPROVED)
    assert [d["day"] for d in c["days"]] == ["2026-11-16", "2026-11-15"]
    d15 = c["days"][1]
    assert d15["cost"] == 25 and d15["live_views"] == 500 and d15["view_10s_rate"] == 20.0 and d15["roi"] == 4.0
    t = c["totals"]
    assert t["cost"] == 35 and t["gmv"] == 170 and t["orders"] == 10 and t["roi"] == round(170 / 35, 2)
    assert t["cost_per_order"] == 3.5 and t["live_minutes"] == 180 and t["days_live"] == 2
    assert c["first_day"] == "2026-11-15"
    one = env.get(f"/api/scheduler/v1/history?from=2026-11-15&to=2026-11-16&campaign_id={NAZIFA}", headers=device).json
    assert [x["campaign_id"] for x in one["campaigns"]] == [NAZIFA] and one["campaigns"][0]["days"] == []
    for bad in ("from=2026-11-17&to=2026-11-16", "from=x", "from=2025-01-01&to=2026-11-16", "campaign_id=123"):
        assert env.get("/api/scheduler/v1/history?" + bad, headers=device).status_code == 400


def test_daily_table_refuses_other_campaigns(env):
    with conn() as c, pytest.raises(psycopg.errors.CheckViolation):
        c.execute("INSERT INTO sched_live_daily (campaign_id, day) VALUES ('1869666392557778', '2026-11-16')")
