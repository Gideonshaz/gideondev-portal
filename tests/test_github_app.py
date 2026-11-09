import base64
import hashlib
import hmac
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import app as portal
import github_sync
from conftest import post

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()).decode()


@pytest.fixture
def no_env(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    github_sync._cache.clear()


@pytest.fixture
def fake_api(monkeypatch):
    """Fake GitHub HTTP layer. Records calls; `broken` simulates an uninstalled app."""
    state = {"calls": [], "broken": False, "releases": [
        {"id": 11, "tag_name": "v1.0.5", "name": "HY v1.0.5", "body": "notes", "prerelease": False,
         "draft": False, "published_at": "2026-11-08T11:45:31Z", "html_url": "u",
         "assets": [{"name": "HYEnhanceStudio-win-Setup.exe", "size": 5}]}]}

    def request(method, url, tok=None, payload=None):
        state["calls"].append((method, url, tok))
        if url.endswith("/conversions"):
            return {"id": 4242, "slug": "gideondev-test", "html_url": "https://github.com/apps/gideondev-test",
                    "pem": PEM, "webhook_secret": "hooksecret"}, ""
        if "/access_tokens" in url:
            if state["broken"]:
                raise github_sync.GitHubError("Not found on GitHub (404).")
            return {"token": "ghs_installtoken", "expires_at": "2099-01-01T00:00:00Z"}, ""
        if url.endswith("/app/installations/777"):
            return {"id": 777}, ""
        if "/installation/repositories" in url:
            return {"repositories": [{"full_name": "Gideonshaz/HY-Enhance-Studio"}]}, ""
        if "/releases" in url:
            assert tok == "ghs_installtoken"
            return state["releases"], ""
        raise AssertionError(url)
    monkeypatch.setattr(github_sync, "_request", request)
    return state


def connect_app(admin):
    page = admin.get("/github")
    with admin.session_transaction() as s:
        state = s["gh_state"]
    r = admin.get(f"/github/app-created/finish?code=abc123&state={state}")
    assert r.status_code == 302 and r.headers["Location"] == "https://github.com/apps/gideondev-test/installations/new"
    r = admin.get("/github/installed/finish?installation_id=777")
    assert r.status_code == 302
    return page


def test_connect_page_posts_manifest_to_github_only_there(admin, no_env, fake_api):
    r = admin.get("/github")
    html = r.get_data(as_text=True)
    assert "form-action 'self' https://github.com" in r.headers["Content-Security-Policy"]
    assert 'action="https://github.com/settings/apps/new?state=' in html and "Connect GitHub" in html
    manifest = json.loads(html.split('name="manifest" value="')[1].split('"')[0].replace("&#34;", '"').replace("&amp;", "&"))
    assert manifest["default_permissions"] == {"contents": "read", "metadata": "read"}
    assert manifest["public"] is False and manifest["default_events"] == ["release"]
    assert manifest["hook_attributes"]["url"].endswith("/api/github/webhook")
    assert "github.com" not in admin.get("/").headers["Content-Security-Policy"]


def test_full_connect_flow_stores_key_encrypted_and_syncs(admin, no_env, fake_api):
    # cross-site redirect from GitHub arrives without the session: only a Finish link
    anon = portal.app.test_client()
    anon.environ_base["wsgi.url_scheme"] = "https"
    page = anon.get("/github/app-created?code=abc123&state=zzz").get_data(as_text=True)
    assert "Finish" in page and not any(c[1].endswith("/conversions") for c in fake_api["calls"])
    connect_app(admin)
    with portal.db() as conn:
        row = conn.execute("SELECT pem_enc, webhook_secret_enc, installation_id FROM github_app").fetchone()
    assert "PRIVATE KEY" not in row[0] and "hooksecret" not in row[1] and row[2] == 777
    html = admin.get("/github").get_data(as_text=True)
    assert "working" in html and "Gideonshaz/HY-Enhance-Studio" in html
    post(admin, "/projects/gatepasskiosk/github", github_repo="Gideonshaz/HY-Enhance-Studio",
         github_tag_prefix="")
    with portal.db() as conn:
        assert conn.execute("SELECT version FROM github_releases").fetchall() == [("1.0.5",)]
    # the token is cached: a second sync does not mint a new one
    post(admin, "/projects/gatepasskiosk/github/sync")
    assert sum("/access_tokens" in c[1] for c in fake_api["calls"]) == 1


def test_wrong_state_and_missing_login_are_rejected(client, admin, no_env, fake_api):
    admin.get("/github")
    r = admin.get("/github/app-created/finish?code=abc123&state=wrong")
    assert r.headers["Location"].endswith("/github")
    assert not any(c[1].endswith("/conversions") for c in fake_api["calls"])
    anon = portal.app.test_client()
    anon.environ_base["wsgi.url_scheme"] = "https"
    assert "/login" in anon.get("/github/app-created/finish?code=a&state=b").headers["Location"]
    assert "/login" in anon.get("/github/installed/finish?installation_id=777").headers["Location"]
    assert "/login" in anon.get("/github").headers["Location"]


def test_app_jwt_is_valid_rs256():
    tok = github_sync.app_jwt(4242, PEM)
    head, body, sig = tok.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)
    KEY.public_key().verify(base64.urlsafe_b64decode(pad(sig)), f"{head}.{body}".encode(),
                            padding.PKCS1v15(), hashes.SHA256())
    claims = json.loads(base64.urlsafe_b64decode(pad(body)))
    assert claims["iss"] == "4242" and claims["exp"] - claims["iat"] <= 600


def test_broken_connection_shows_reconnect_warning(admin, no_env, fake_api):
    connect_app(admin)
    post(admin, "/projects/gatepasskiosk/github", github_repo="Gideonshaz/HY-Enhance-Studio",
         github_tag_prefix="")
    github_sync._cache.clear()
    fake_api["broken"] = True
    post(admin, "/projects/gatepasskiosk/github/sync")
    page = admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    assert "sync failed" in page and "Reconnect GitHub" in page
    assert "check the GitHub connection" in page
    html = admin.get("/github").get_data(as_text=True)
    assert "not working" in html and "Reconnect GitHub" in html
    with portal.db() as conn:  # history kept
        assert conn.execute("SELECT count(*) FROM github_releases WHERE removed_at IS NULL").fetchone()[0] == 1


def test_webhook_uses_app_secret(admin, no_env, fake_api):
    connect_app(admin)
    post(admin, "/projects/gatepasskiosk/github", github_repo="Gideonshaz/HY-Enhance-Studio",
         github_tag_prefix="")
    body = json.dumps({"repository": {"full_name": "Gideonshaz/HY-Enhance-Studio"}}).encode()
    sig = "sha256=" + hmac.new(b"hooksecret", body, hashlib.sha256).hexdigest()
    r = admin.post("/api/github/webhook", data=body,
                   headers={"X-GitHub-Event": "release", "X-Hub-Signature-256": sig})
    assert r.status_code == 200 and r.get_json()["synced"][0]["ok"] is True
    bad = admin.post("/api/github/webhook", data=body,
                     headers={"X-GitHub-Event": "release", "X-Hub-Signature-256": "sha256=00"})
    assert bad.status_code == 401


def test_disconnect_needs_csrf_and_keeps_history(admin, no_env, fake_api):
    connect_app(admin)
    assert admin.post("/github/disconnect").status_code == 403
    post(admin, "/github/disconnect")
    with portal.db() as conn:
        assert conn.execute("SELECT count(*) FROM github_app").fetchone()[0] == 0
    assert "Not connected" in admin.get("/github").get_data(as_text=True)
