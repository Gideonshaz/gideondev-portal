import json

import pytest

import app as portal
import github_sync
from conftest import post

PKG = "HYEnhanceStudio"


def asset(aid, name, size=100, state="uploaded"):
    return {"id": aid, "name": name, "size": size, "state": state}


class FakeRepo:
    def __init__(self):
        self.releases = [{"id": 1, "tag_name": "v1.0.5", "name": "HY v1.0.5", "body": "old", "draft": False,
                          "prerelease": False, "published_at": "2026-11-08T11:45:31Z", "html_url": "u",
                          "assets": [asset(10, f"{PKG}-1.0.5-full.nupkg", 999)]}]
        self.feeds = {}
        self.calls = []
        self.fail_patch = False
        self.no_write = False

    def request(self, method, url, tok=None, payload=None):
        self.calls.append((method, url, payload))
        path = url.split("/repos/o/hy", 1)[-1]
        if method == "GET" and path.startswith("/releases?"):
            return [r for r in self.releases], ""
        if method == "POST" and path == "/releases":
            if self.no_write:
                raise github_sync.GitHubError("The GitHub app doesn't have write permission yet.")
            rel = {"id": 100 + len(self.releases), "tag_name": payload["tag_name"], "name": payload["name"],
                   "body": payload["body"], "draft": True, "prerelease": payload["prerelease"],
                   "published_at": None, "html_url": "u", "assets": []}
            self.releases.append(rel)
            return rel, ""
        rid = int(path.split("/releases/")[1]) if "/releases/" in path else None
        rel = next((r for r in self.releases if r["id"] == rid), None)
        if method == "GET" and rel:
            return rel, ""
        if method == "PATCH" and rel:
            if self.fail_patch:
                raise github_sync.GitHubError("GitHub error 502.")
            rel.update(draft=False, prerelease=payload["prerelease"], published_at="2026-11-10T09:00:00Z")
            return rel, ""
        if method == "DELETE" and rel:
            self.releases.remove(rel)
            return {}, ""
        raise AssertionError((method, url))

    def upload_all(self, version, feed_version=None, size=5000):
        rel = next(r for r in self.releases if r["draft"])
        rel["assets"] = [asset(200, "releases.win.json", 300), asset(201, "RELEASES", 87),
                         asset(202, "assets.win.json", 217), asset(203, f"{PKG}-{version}-full.nupkg", size),
                         asset(204, f"{PKG}-win-Setup.exe", 6000)]
        self.feeds[200] = json.dumps({"Assets": [{"PackageId": PKG, "Version": feed_version or version,
                                                  "Type": "Full", "Size": size,
                                                  "FileName": f"{PKG}-{feed_version or version}-full.nupkg"}]})
        return rel


@pytest.fixture
def gh(admin, monkeypatch):
    repo = FakeRepo()
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setattr(github_sync, "_request", repo.request)
    monkeypatch.setattr(github_sync, "download_small_asset", lambda r, aid, tok, limit=0: repo.feeds[aid])
    post(admin, "/projects/gatepasskiosk/github", github_repo="o/hy", github_tag_prefix="")
    return repo


def page(admin):
    return admin.get("/projects/gatepasskiosk").get_data(as_text=True)


def draft(admin, version="1.0.6", notes="New stuff", pre=False):
    data = dict(version=version, notes=notes)
    if pre:
        data["prerelease"] = "on"
    return post(admin, "/projects/gatepasskiosk/github/draft", **data)


def test_full_flow_draft_upload_verify_publish(admin, gh):
    draft(admin)
    created = gh.releases[-1]
    assert created["draft"] is True and created["tag_name"] == "v1.0.6" and created["body"] == "New stuff"
    html = page(admin)
    assert "Draft v1.0.6" in html and "waiting for files" in html
    assert f"Upload-ToDraft.ps1 -ReleaseId {created['id']}" in html
    # publishing before upload is refused and nothing is patched
    post(admin, "/projects/gatepasskiosk/github/draft/publish")
    assert not any(c[0] == "PATCH" for c in gh.calls) and created["draft"] is True
    gh.upload_all("1.0.6")
    post(admin, "/projects/gatepasskiosk/github/draft/check")
    assert "ready to publish" in page(admin)
    post(admin, "/projects/gatepasskiosk/github/draft/publish")
    patch = [c for c in gh.calls if c[0] == "PATCH"]
    assert len(patch) == 1 and patch[0][2] == {"draft": False, "prerelease": False, "make_latest": "true"}
    html = page(admin)
    assert "Create draft on GitHub" in html               # draft card gone
    with portal.db() as conn:
        assert ("1.0.6",) in conn.execute("SELECT version FROM github_releases").fetchall()
    # pressing publish again does nothing
    post(admin, "/projects/gatepasskiosk/github/draft/publish")
    assert len([c for c in gh.calls if c[0] == "PATCH"]) == 1


def test_wrong_or_unfinished_files_block_publishing(admin, gh):
    draft(admin)
    rel = gh.upload_all("1.0.6", feed_version="1.0.5")   # packed the wrong version
    post(admin, "/projects/gatepasskiosk/github/draft/publish")
    assert rel["draft"] is True and "does not match" in page(admin)
    gh.upload_all("1.0.6")
    rel["assets"][3]["state"] = "starter"                 # nupkg upload interrupted
    post(admin, "/projects/gatepasskiosk/github/draft/publish")
    assert rel["draft"] is True and "upload not finished" in page(admin)
    gh.upload_all("1.0.6")
    gh.feeds[200] = gh.feeds[200].replace('"Size": 5000', '"Size": 1')  # size mismatch
    post(admin, "/projects/gatepasskiosk/github/draft/publish")
    assert rel["draft"] is True


def test_version_rules_and_duplicates(admin, gh):
    for bad in ("1.0.5", "1.0.4", "abc"):
        draft(admin, version=bad)
    assert not any(r["draft"] for r in gh.releases)
    draft(admin, version="v1.0.6")
    assert sum(r["draft"] for r in gh.releases) == 1
    draft(admin, version="1.0.7")                         # only one draft at a time
    assert sum(r["draft"] for r in gh.releases) == 1
    with portal.db() as conn:
        conn.execute("UPDATE github_drafts SET status='discarded'")
    draft(admin, version="1.0.6")                         # tag already exists as a draft on GitHub
    assert sum(r["draft"] for r in gh.releases) == 1
    assert "already exists on GitHub as a draft" in page(admin)


def test_publish_failure_keeps_draft_and_retry_works(admin, gh):
    draft(admin)
    rel = gh.upload_all("1.0.6")
    gh.fail_patch = True
    post(admin, "/projects/gatepasskiosk/github/draft/publish")
    html = page(admin)
    assert rel["draft"] is True and "502" in html and "Draft v1.0.6" in html
    gh.fail_patch = False
    post(admin, "/projects/gatepasskiosk/github/draft/publish")
    assert rel["draft"] is False


def test_prerelease_is_not_marked_latest(admin, gh):
    draft(admin, pre=True)
    gh.upload_all("1.0.6")
    post(admin, "/projects/gatepasskiosk/github/draft/publish")
    patch = [c for c in gh.calls if c[0] == "PATCH"][0][2]
    assert patch == {"draft": False, "prerelease": True, "make_latest": "false"}


def test_discard_deletes_only_drafts(admin, gh):
    draft(admin)
    post(admin, "/projects/gatepasskiosk/github/draft/discard")
    assert not any(r["draft"] for r in gh.releases) and len(gh.releases) == 1
    assert [c for c in gh.calls if c[0] == "DELETE"][0][1].endswith("/releases/101")


def test_draft_published_by_old_script_is_detected(admin, gh):
    draft(admin)
    rel = gh.upload_all("1.0.6")
    rel.update(draft=False, published_at="2026-11-10T09:00:00Z")  # Resume-Release.ps1 published it
    post(admin, "/projects/gatepasskiosk/github/draft/check")
    html = page(admin)
    assert "already published on GitHub" in html and "Create draft on GitHub" in html
    assert not any(c[0] in ("PATCH", "DELETE") for c in gh.calls)


def test_missing_write_permission_is_explained(admin, gh):
    gh.no_write = True
    draft(admin)
    assert "write permission" in page(admin)


def test_draft_routes_need_login_and_csrf(client):
    for path in ("draft", "draft/check", "draft/publish", "draft/discard"):
        assert "/login" in client.post(f"/projects/gatepasskiosk/github/{path}").headers["Location"]
