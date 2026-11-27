"""Morning LIVE Performance Report: text format, per-LIVE collector, runner step, endpoints."""
from datetime import date, datetime, timezone

from affiliate_scheduler import live_history, mcp_client, morning_report, runner
from affiliate_scheduler.timing import MYT
from test_affiliate_scheduler import APPROVED, MCP, RUNNER_TOKEN, FakePortal, FakeTikTok, conn, device, env  # noqa: F401

NAZIFA = "1882182698757202"
FAIDI = "1882889601684577"
NOW = datetime(2026, 11, 16, 15, 0, tzinfo=timezone.utc)


def test_text_matches_the_template():
    s = {"started_at": datetime(2026, 11, 26, 13, 25, tzinfo=MYT), "minutes": 156, "ongoing": False,
         "cost": 91.86, "gmv": 764.74, "orders": 109}
    t = {"started_at": datetime(2026, 11, 26, 21, 30, tzinfo=MYT), "minutes": 120, "ongoing": False,
         "cost": 85.07, "gmv": 554.96, "orders": 72}
    text = morning_report.build(date(2026, 11, 26), [("tashafrh", t), ("faidisini", s)])
    assert text.split("\n\n📊")[0] == """📊 ViVid Hair | LIVE Performance Report

Affiliate: @faidisini
Date: 26 November 2026
LIVE Time: 1:25 PM - 4:01 PM
LIVE Duration: 2h 36m

Performance
* GMV: RM 764.74
* Orders: 109
* Ads Spend: RM 91.86
* ROI: 8.33
* AOV: RM 7.02

Source: GMV Max Dashboard"""
    assert "@tashafrh" in text and "LIVE Time: 9:30 PM - 11:30 PM" in text and "LIVE Duration: 2h\n" in text
    assert "* AOV: RM 7.71" in text and "* ROI: 6.52" in text      # rounded half up, not cut off


def test_text_edge_cases():
    assert morning_report.build(date(2026, 11, 26), []) == "No affiliate LIVE with GMV Max ads on 26 November 2026."
    s = {"started_at": datetime(2026, 11, 26, 9, 5, tzinfo=MYT), "minutes": 45, "ongoing": True,
         "cost": 0, "gmv": 0, "orders": 0}
    text = morning_report.build(date(2026, 11, 26), [("x", s)])
    assert "9:05 AM - LIVE now" in text and "45m (still live)" in text and "ROI: -" in text and "AOV: -" in text


def test_sessions_collector_reads_each_live():
    tk = FakeTikTok(stats_tools=True)
    s = mcp_client.McpSession(MCP, "AT", http=tk)
    s.initialize()
    out = live_history.sessions(s, APPROVED, "S1", date(2026, 11, 14), date(2026, 11, 16), NOW)
    assert tk.writes() == []
    assert out == [{"room_id": "R2", "started_at": "2026-11-16T13:19:42+00:00", "minutes": 100, "ongoing": True,
                    "cost": 11.59, "gmv": 168.2, "orders": 10}]       # R1 had no ads: left out


def test_runner_sends_sessions_backfill_then_three_days():
    tk, p = FakeTikTok(stats_tools=True), FakePortal([])
    s = mcp_client.McpSession(MCP, "AT", http=tk)
    s.initialize()
    runner.report_history(p, s, s.list_tools(), None, now=NOW)
    assert {x["campaign_id"] for x in p.sessions} == {APPROVED, NAZIFA, FAIDI}
    rooms = [c[1] for c in tk.calls if c[1].get("dimensions") == ["room_id"] and "gross_revenue" in c[1]["metrics"]]
    assert rooms[0]["start_date"] == "2026-11-12"                    # first time: since the campaign started
    tk, p = FakeTikTok(stats_tools=True), FakePortal([])
    p.session_cov = {APPROVED: 3, NAZIFA: 1, FAIDI: 1}
    s = mcp_client.McpSession(MCP, "AT", http=tk)
    s.initialize()
    runner.report_history(p, s, s.list_tools(), None, now=NOW)
    rooms = [c[1] for c in tk.calls if c[1].get("dimensions") == ["room_id"] and "gross_revenue" in c[1]["metrics"]]
    assert rooms[0]["start_date"] == "2026-11-14" and rooms[0]["end_date"] == "2026-11-16"


def test_sessions_and_morning_report_endpoints(env, device):
    h = {"Authorization": f"Bearer {RUNNER_TOKEN}"}
    assert env.post("/api/scheduler/runner/sessions", json={}).status_code == 401
    assert env.get("/api/scheduler/v1/morning-report").status_code == 401
    assert env.post("/api/scheduler/runner/sessions", headers=h,
                    json={"campaign_id": "1869666392557778", "sessions": []}).status_code == 400
    live = {"room_id": "R9", "started_at": "2026-11-26T05:25:00+00:00", "minutes": 156, "ongoing": False,
            "cost": 91.86, "gmv": 760.0, "orders": 108}
    r = env.post("/api/scheduler/runner/sessions", headers=h, json={"campaign_id": FAIDI, "sessions": [
        live, {"room_id": "bad", "started_at": "2026-11-26 05:25:00"}]})
    assert r.json["saved"] == 1 and r.json["skipped"] == 1
    env.post("/api/scheduler/runner/sessions", headers=h,                       # later run: late orders added
             json={"campaign_id": FAIDI, "sessions": [dict(live, gmv=764.74, orders=109)]})
    # another campaign can't take over that room
    env.post("/api/scheduler/runner/sessions", headers=h, json={"campaign_id": APPROVED, "sessions": [dict(live, gmv=1)]})
    late = {"room_id": "R10", "started_at": "2026-11-26T16:30:00+00:00", "minutes": 90, "ongoing": False,
            "cost": 10, "gmv": 50, "orders": 5}                                    # 12:30 AM Malaysia on the 27th
    env.post("/api/scheduler/runner/sessions", headers=h, json={"campaign_id": APPROVED, "sessions": [late]})
    cov = env.post("/api/scheduler/runner/history-coverage", headers=h, json={}).json["sessions"]
    assert cov[FAIDI] == 1 and cov[APPROVED] == 1
    r = env.get("/api/scheduler/v1/morning-report?date=2026-11-26", headers=device).json
    assert [x["campaign_name"] for x in r["lives"]] == ["faidisini"]
    assert "Affiliate: @faidisini" in r["text"] and "GMV: RM 764.74" in r["text"] and "Orders: 109" in r["text"]
    assert "LIVE Time: 1:25 PM - 4:01 PM" in r["text"]
    r = env.get("/api/scheduler/v1/morning-report?date=2026-11-27", headers=device).json
    assert "@tashafrh" in r["text"] and "12:30 AM - 2:00 AM" in r["text"]
    assert env.get("/api/scheduler/v1/morning-report?date=nope", headers=device).status_code == 400
