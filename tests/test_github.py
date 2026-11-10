import hashlib
import hmac
import json
import os

import pytest

import app as portal
import github_sync
from conftest import post


def rel(gid, tag, body="notes", pre=False, draft=False, assets=(("Setup.exe", 2048),), name=None):
    return {"id": gid, "tag_name": tag, "name": name or f"App {tag}", "body": body,
            "prerelease": pre, "draft": draft, "published_at": "2026-11-0%dT10:00:00Z" % (gid % 9 + 1),
            "html_url": f"https://github.com/o/r/releases/tag/{tag}",
            "assets": [{"name": n, "size": s} for n, s in assets]}


@pytest.fixture
def fake_github(monkeypatch):
    state = {"releases": [], "fail": None, "calls": 0}

    def fetch(repo, tok=None):
        state["calls"] += 1
        if state["fail"]:
            raise github_sync.GitHubError(state["fail"])
        return [r for r in state["releases"] if not r.get("draft")]
    monkeypatch.setattr(github_sync, "fetch_releases", fetch)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    return state


def gh_rows(slug="gatepasskiosk"):
    with portal.db() as conn:
        return conn.execute("""SELECT g.version, g.body, g.prerelease, g.removed_at IS NOT NULL, g.assets
                               FROM github_releases g JOIN projects p ON p.id=g.project_id
                               WHERE p.slug=%s ORDER BY g.gh_id""", (slug,)).fetchall()


def connect(admin, repo="Gideonshaz/GatePassKiosk-Windows", prefix="", slug="gatepasskiosk"):
    return post(admin, f"/projects/{slug}/github", github_repo=repo, github_tag_prefix=prefix)


def sync(admin, slug="gatepasskiosk"):
    return post(admin, f"/projects/{slug}/github/sync")


def test_connect_imports_history_and_resync_has_no_duplicates(admin, fake_github):
    fake_github["releases"] = [rel(1, "v1.0.0"), rel(2, "v1.0.1", pre=True), rel(3, "v1.0.2"),
                               rel(4, "v9.9.9", draft=True)]
    r = connect(admin)
    assert r.status_code == 302
    rows = gh_rows()
    assert [x[0] for x in rows] == ["1.0.0", "1.0.1", "1.0.2"]  # draft skipped, v stripped
    assert rows[1][2] is True and rows[0][4] == [{"name": "Setup.exe", "size": 2048}]
    for _ in range(3):
        sync(admin)
    assert len(gh_rows()) == 3
    page = admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    assert "GitHub release history (3)" in page and "Gideonshaz/GatePassKiosk-Windows" in page
    assert "3 releases · 0 new · 0 changed · 0 removed" in page


def test_new_edited_removed_and_restored_releases(admin, fake_github):
    fake_github["releases"] = [rel(1, "v1.0.0"), rel(2, "v1.0.1")]
    connect(admin)
    fake_github["releases"] = [rel(1, "v1.0.0", body="edited notes"), rel(3, "v1.0.2")]
    sync(admin)
    rows = {x[0]: x for x in gh_rows()}
    assert rows["1.0.0"][1] == "edited notes"
    assert rows["1.0.1"][3] is True            # removed on GitHub: kept, marked
    assert rows["1.0.2"][3] is False           # new release detected
    page = admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    assert "removed from GitHub" in page and "1 new · 1 changed · 1 removed" in page
    fake_github["releases"].append(rel(2, "v1.0.1"))
    sync(admin)
    assert {x[0]: x[3] for x in gh_rows()}["1.0.1"] is False  # came back


def test_api_failure_keeps_history_and_reports_error(admin, fake_github):
    fake_github["releases"] = [rel(1, "v1.0.0"), rel(2, "v1.0.1")]
    connect(admin)
    fake_github["fail"] = "GitHub rejected the token (401). It may be expired or wrong."
    r = sync(admin)
    assert r.status_code == 302
    assert [x[3] for x in gh_rows()] == [False, False]   # nothing marked removed
    page = admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    assert "sync failed" in page and "401" in page


def test_shared_repository_tag_prefix_mapping(admin, fake_github):
    post(admin, "/projects", name="Second App", slug="second-app")
    fake_github["releases"] = [rel(1, "kiosk-v1.0.0"), rel(2, "hr-v2.0.0"), rel(3, "kiosk-v1.1.0")]
    connect(admin, repo="Gideonshaz/shared", prefix="kiosk-")
    connect(admin, repo="Gideonshaz/shared", prefix="hr-", slug="second-app")
    assert [x[0] for x in gh_rows()] == ["1.0.0", "1.1.0"]
    assert [x[0] for x in gh_rows("second-app")] == ["2.0.0"]


def test_bad_repo_name_and_disconnect_keeps_history(admin, fake_github):
    fake_github["releases"] = [rel(1, "v1.0.0")]
    connect(admin, repo="not a repo")
    assert fake_github["calls"] == 0
    connect(admin, repo="https://github.com/Gideonshaz/GatePassKiosk-Windows.git")
    assert fake_github["calls"] == 1
    connect(admin, repo="")
    assert len(gh_rows()) == 1
    assert "Not connected" in admin.get("/projects/gatepasskiosk").get_data(as_text=True)


def test_missing_token_is_reported(admin, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    connect(admin)
    page = admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    assert "GitHub is not connected yet" in page and "sync failed" in page


def test_github_routes_need_login_and_csrf(client, fake_github):
    assert client.post("/projects/gatepasskiosk/github/sync").status_code == 302  # to login
    client.post("/login", data={"password": os.environ["ADMIN_PASSWORD"]})
    assert client.post("/projects/gatepasskiosk/github/sync").status_code == 403    # no csrf
    assert client.post("/projects/gatepasskiosk/github",
                       data={"github_repo": "a/b"}).status_code == 403


def test_private_github_data_never_reaches_public_endpoints(admin, fake_github):
    fake_github["releases"] = [rel(1, "v7.7.7", body="SECRET-NOTES")]
    connect(admin)
    post(admin, "/projects/gatepasskiosk/edit", name="Kiosk", description="", repo_url="", is_public="on")
    out = admin.get("/api/v1/projects").get_data(as_text=True)
    out += admin.get("/api/v1/projects/gatepasskiosk").get_data(as_text=True)
    out += admin.get("/api/v1/projects/gatepasskiosk/latest?current=1.0.0").get_data(as_text=True)
    assert "7.7.7" not in out and "SECRET-NOTES" not in out and "GatePassKiosk-Windows" not in out


def _signed(body, secret="whsec"):
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_webhook_verifies_signature_and_syncs(admin, fake_github, monkeypatch):
    fake_github["releases"] = [rel(1, "v1.0.0")]
    connect(admin)
    fake_github["releases"].append(rel(2, "v1.0.1"))
    body = json.dumps({"action": "published",
                       "repository": {"full_name": "gideonshaz/gatepasskiosk-windows"}}).encode()
    h = {"X-GitHub-Event": "release", "Content-Type": "application/json"}
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    assert admin.post("/api/github/webhook", data=body, headers=h).status_code == 503  # no secret
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "whsec")
    assert admin.post("/api/github/webhook", data=body,
                      headers={**h, "X-Hub-Signature-256": _signed(body, "wrong")}).status_code == 401
    assert len(gh_rows()) == 1
    r = admin.post("/api/github/webhook", data=body,
                   headers={**h, "X-Hub-Signature-256": _signed(body)})
    assert r.status_code == 200 and r.get_json()["synced"] == [{"project": "gatepasskiosk", "ok": True}]
    assert len(gh_rows()) == 2
    ping = b'{"zen":"hi"}'
    assert admin.post("/api/github/webhook", data=ping, headers={
        "X-GitHub-Event": "ping", "X-Hub-Signature-256": _signed(ping)}).status_code == 200


def test_licensing_unchanged_after_github_sync(admin, fake_github):
    from conftest import make_key
    from test_portal import verify
    fake_github["releases"] = [rel(1, "v1.0.0")]
    connect(admin)
    key = make_key(admin)
    assert verify(admin, key).get_json()["valid"] is True


def test_real_github_payloads_import(admin, fake_github):
    """Replays real release JSON captured from the repos, when available locally."""
    path = "/tmp/ghreal/HY-Enhance-Studio.json"
    if not os.path.exists(path):
        pytest.skip("no captured data")
    fake_github["releases"] = json.load(open(path))
    connect(admin, repo="Gideonshaz/HY-Enhance-Studio")
    versions = [x[0] for x in gh_rows()]
    assert "1.0.5" in versions and "0.7.2" in versions and len(versions) == len(fake_github["releases"])
    page = admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    assert "HYEnhanceStudio-v1.0.5-Setup.exe" in page


def test_large_webhook_payload_is_accepted_but_site_limit_stays(admin, fake_github, monkeypatch):
    fake_github["releases"] = [rel(1, "v1.0.0")]
    connect(admin)
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "whsec")
    body = json.dumps({"action": "edited", "repository": {"full_name": "Gideonshaz/GatePassKiosk-Windows"},
                       "release": {"body": "x" * 60000}}).encode()
    r = admin.post("/api/github/webhook", data=body, headers={
        "X-GitHub-Event": "release", "X-Hub-Signature-256": _signed(body), "Content-Type": "application/json"})
    assert r.status_code == 200
    big = admin.post("/login", data={"password": "x" * 60000})
    assert big.status_code == 413


def test_switching_repo_keeps_old_history_without_marking_it_removed(admin, fake_github):
    fake_github["releases"] = [rel(1, "v1.0.0"), rel(2, "v1.0.1")]
    connect(admin, repo="Gideonshaz/Old")
    fake_github["releases"] = [rel(9, "v0.0.1")]
    connect(admin, repo="Gideonshaz/New")
    rows = gh_rows()
    assert sorted((r[0], r[3]) for r in rows) == [("0.0.1", False), ("1.0.0", False), ("1.0.1", False)]
    page = admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    assert "GitHub release history (1)" in page and "removed from GitHub" not in page
