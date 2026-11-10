import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import app as portal
from conftest import DEVICE_A, DEVICE_B, DEVICE_C, legacy_schema, make_key, post

DB = os.environ["DATABASE_URL"]


def verify(c, key, project="gatepasskiosk", device=DEVICE_A, path="/api/v1/verify"):
    field = "product" if path == "/api/verify" else "project"
    return c.post(path, json={"key": key, field: project, "device_id": device})


# ------------------------------------------------------------------ migration
def test_legacy_database_is_upgraded_in_place(client):
    legacy_schema()
    key = "GP-" + "AB12" * 12
    now = datetime.now(timezone.utc)
    with psycopg.connect(DB) as conn:
        conn.execute("""INSERT INTO licenses (key_hash, key_ciphertext, product, months, duration,
                        activated_at, expires_at, device_id)
                        VALUES (%s,'x','GatePassKiosk',12,'1 year',%s,%s,%s)""",
                     (hashlib.sha256(key.encode()).hexdigest(), now, now + timedelta(days=300), DEVICE_A))
    # same call the deployed Windows clients make today
    r = verify(client, key, "GatePassKiosk", DEVICE_A, "/api/verify")
    assert r.get_json()["valid"] is True
    assert set(r.get_json()) == {"valid", "activated_at", "expires_at"}  # legacy shape
    r = verify(client, key, "GatePassKiosk", DEVICE_B, "/api/verify")
    assert r.get_json() == {"valid": False, "reason": "License belongs to another computer"}
    with psycopg.connect(DB) as conn:
        assert conn.execute("SELECT count(*) FROM activations").fetchone()[0] == 1
        assert conn.execute("SELECT project_id FROM licenses").fetchone()[0] is not None


def test_migration_is_idempotent(client):
    assert client.get("/health").get_json() == {"ok": True}
    portal.app.config["SCHEMA_READY"] = False  # simulate a second worker starting
    assert client.get("/login").status_code == 200
    portal.app.config["SCHEMA_READY"] = False
    assert client.get("/login").status_code == 200
    with psycopg.connect(DB) as conn:
        assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 6


# ------------------------------------------------------------------ licensing
def test_activation_and_device_limits(admin):
    key = make_key(admin)
    r = verify(admin, key).get_json()
    assert r["valid"] and r["devices_used"] == 1 and r["max_devices"] == 1
    assert verify(admin, key).get_json()["valid"]  # same device again
    r = verify(admin, key, device=DEVICE_B).get_json()
    assert r == {"valid": False, "reason": "License belongs to another computer"}

    key2 = make_key(admin, devices=2)
    assert verify(admin, key2, device=DEVICE_A).get_json()["valid"]
    assert verify(admin, key2, device=DEVICE_B).get_json()["valid"]
    r = verify(admin, key2, device=DEVICE_C).get_json()
    assert r == {"valid": False, "reason": "Device limit reached"}


def test_reset_devices_allows_new_computer_and_keeps_expiry(admin):
    key = make_key(admin)
    first = verify(admin, key).get_json()
    with psycopg.connect(DB) as conn:
        lid = conn.execute("SELECT id FROM licenses").fetchone()[0]
    assert post(admin, f"/licenses/{lid}/reset-devices").status_code == 302
    second = verify(admin, key, device=DEVICE_B).get_json()
    assert second["valid"] and second["expires_at"] == first["expires_at"]
    assert not verify(admin, key, device=DEVICE_A).get_json()["valid"]


def test_wrong_project_revoked_and_expired(admin):
    key = make_key(admin)
    assert verify(admin, key, project="gatepasssecurity").get_json()["reason"] == "Invalid product key"
    assert verify(admin, "GP-" + "0" * 48).get_json()["reason"] == "Invalid product key"
    assert verify(admin, key).get_json()["valid"]
    with psycopg.connect(DB) as conn:
        lid = conn.execute("SELECT id FROM licenses").fetchone()[0]
    post(admin, f"/licenses/{lid}/revoke")
    assert verify(admin, key).get_json() == {"valid": False, "reason": "License revoked"}

    key2 = make_key(admin)
    verify(admin, key2)
    with psycopg.connect(DB) as conn:
        conn.execute("UPDATE licenses SET expires_at = now() - interval '1 day' "
                     "WHERE id = (SELECT max(id) FROM licenses)")
    assert verify(admin, key2).get_json() == {"valid": False, "reason": "License expired"}


def test_malformed_requests_get_400(client):
    assert client.post("/api/v1/verify", json={}).status_code == 400
    assert client.post("/api/v1/verify", json={"key": "GP-1", "project": "x", "device_id": "y"}).status_code == 400
    assert client.post("/api/verify", data="not json").status_code == 400


def test_signed_token_verifies_offline(admin):
    key = make_key(admin)
    body = verify(admin, key).get_json()
    pub = admin.get("/api/v1/public-key").get_json()
    assert pub["algorithm"] == "Ed25519"
    payload_b64, sig_b64 = body["token"].split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)
    payload = base64.urlsafe_b64decode(pad(payload_b64))
    Ed25519PublicKey.from_public_bytes(base64.b64decode(pub["public_key"])).verify(
        base64.urlsafe_b64decode(pad(sig_b64)), payload)  # raises if invalid
    data = json.loads(payload)
    assert data["p"] == "gatepasskiosk" and data["d"] == DEVICE_A
    assert datetime.fromisoformat(body["offline_until"]) <= datetime.fromisoformat(data["exp"])


# ------------------------------------------------------------------ updates + public API
def add_release(c, slug, version, channel="stable", **extra):
    return post(c, f"/projects/{slug}/releases", version=version, channel=channel,
                download_url=f"https://example.com/{slug}-{version}.zip", **extra)


def test_update_check(admin):
    admin.get("/login")
    for v, ch, extra in [("1.0.0", "stable", {}), ("1.2.0", "stable", {"mandatory": "on"}),
                         ("1.10.0", "stable", {}), ("2.0.0", "beta", {})]:
        assert add_release(admin, "gatepasskiosk", v, ch, **extra).status_code == 302
    url = "/api/v1/projects/gatepasskiosk/latest"
    r = admin.get(url + "?current=1.2.0").get_json()
    assert r["update_available"] and r["latest"]["version"] == "1.10.0"  # 1.10 > 1.2 (numeric compare)
    assert r["mandatory"] is False  # only 1.2.0 is mandatory and the client already has it
    assert admin.get(url + "?current=1.0.0").get_json()["mandatory"] is True
    assert admin.get(url + "?current=1.10.0").get_json()["update_available"] is False
    assert admin.get(url + "?current=1.0.0&channel=beta").get_json()["latest"]["version"] == "2.0.0"
    assert admin.get(url + "?current=1.0.0").get_json()["latest"]["version"] == "1.10.0"  # no betas on stable
    assert admin.get(url + "?current=abc").status_code == 400
    assert admin.get("/api/v1/projects/nope/latest").status_code == 404


def test_withdrawn_release_is_never_offered(admin):
    add_release(admin, "gatepasskiosk", "1.0.0")
    add_release(admin, "gatepasskiosk", "1.1.0")
    with psycopg.connect(DB) as conn:
        rid = conn.execute("SELECT id FROM releases WHERE version='1.1.0'").fetchone()[0]
    post(admin, f"/releases/{rid}/yank")
    r = admin.get("/api/v1/projects/gatepasskiosk/latest?current=0.9").get_json()
    assert r["latest"]["version"] == "1.0.0"


def test_release_form_validation(admin):
    bad = post(admin, "/projects/gatepasskiosk/releases", version="1.0", channel="stable",
               download_url="http://insecure.example/app.zip")
    assert bad.status_code == 302
    bad = post(admin, "/projects/gatepasskiosk/releases", version="one", channel="stable",
               download_url="https://example.com/a.zip")
    assert bad.status_code == 302
    add_release(admin, "gatepasskiosk", "1.0.0")
    add_release(admin, "gatepasskiosk", "1.0.0")  # duplicate
    with psycopg.connect(DB) as conn:
        assert conn.execute("SELECT count(*) FROM releases").fetchone()[0] == 1


def test_public_api_only_shows_public_projects(admin):
    add_release(admin, "gatepasskiosk", "1.0.0")
    assert admin.get("/api/v1/projects").get_json() == {"projects": []}
    assert admin.get("/api/v1/projects/gatepasskiosk").status_code == 404
    post(admin, "/projects/gatepasskiosk/edit", name="GatePass Kiosk", description="Kiosk app",
         repo_url="", is_public="on")
    r = admin.get("/api/v1/projects", headers={"Origin": "https://gideonshaz.github.io"})
    assert r.get_json()["projects"][0]["latest"]["version"] == "1.0.0"
    assert r.headers["Access-Control-Allow-Origin"] == "https://gideonshaz.github.io"
    r = admin.get("/api/v1/projects", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in r.headers


# ------------------------------------------------------------------ admin security
def test_admin_pages_require_login_and_csrf(client):
    assert client.get("/").status_code == 302
    assert client.get("/projects/gatepasskiosk").status_code == 302
    assert client.post("/projects", data={"name": "x", "slug": "xx"}).status_code == 302
    client.post("/login", data={"password": os.environ["ADMIN_PASSWORD"]})
    assert client.post("/projects", data={"name": "x", "slug": "xx"}).status_code == 403  # no csrf


def test_login_is_throttled_per_ip(client):
    for _ in range(5):
        r = client.post("/login", data={"password": "wrong"}, environ_overrides={"REMOTE_ADDR": "9.9.9.9"})
        assert r.status_code == 401
    r = client.post("/login", data={"password": os.environ["ADMIN_PASSWORD"]},
                    environ_overrides={"REMOTE_ADDR": "9.9.9.9"})
    assert r.status_code == 429  # even the right password is blocked while throttled
    r = client.post("/login", data={"password": os.environ["ADMIN_PASSWORD"]},
                    environ_overrides={"REMOTE_ADDR": "8.8.8.8"})
    assert r.status_code == 302  # other addresses unaffected


def test_admin_pages_render(admin):
    key = make_key(admin)
    verify(admin, key)
    add_release(admin, "gatepasskiosk", "1.0.0", notes="First <b>release</b>")
    assert post(admin, "/projects", name="My New App", slug="my-new-app").status_code == 302
    page = admin.get("/projects/gatepasskiosk")
    assert page.status_code == 200 and key.encode() in page.data
    assert b"<b>release</b>" not in page.data  # notes are never echoed unescaped
    assert b"My New App" in admin.get("/").data
    assert admin.get("/projects/missing").status_code == 404
    assert "default-src 'self'" in page.headers["Content-Security-Policy"]


def test_keys_from_another_secret_do_not_crash_the_page(admin):
    with psycopg.connect(DB) as conn:
        pid = conn.execute("SELECT id FROM projects WHERE slug='gatepasskiosk'").fetchone()[0]
        conn.execute("""INSERT INTO licenses (key_hash, key_ciphertext, product, months, duration, project_id)
                        VALUES (%s, 'not-a-valid-token', 'GatePassKiosk', 12, '1 year', %s)""",
                     ("f" * 64, pid))
    page = admin.get("/projects/gatepasskiosk")
    assert page.status_code == 200 and "can't display this key" in page.get_data(as_text=True)


# ------------------------------------------------------- old server running alongside / after
def _old_server_insert(key, device=None, product="GatePassKiosk"):
    """Exactly what the OLD license server writes: no project_id, device in licenses.device_id."""
    now = datetime.now(timezone.utc)
    with psycopg.connect(DB) as conn:
        conn.execute("""INSERT INTO licenses (key_hash, key_ciphertext, product, months, duration,
                        activated_at, expires_at, device_id)
                        VALUES (%s,'x',%s,12,'1 year',%s,%s,%s)""",
                     (hashlib.sha256(key.encode()).hexdigest(), product,
                      now if device else None, now + timedelta(days=300) if device else None, device))


def test_key_created_by_old_server_after_migration_verifies(client):
    assert client.get("/health").status_code == 200  # new schema already in place
    key = "GP-" + "CD34" * 12
    _old_server_insert(key)  # old server creates a fresh, unactivated key afterwards
    r = verify(client, key, "GatePassKiosk", DEVICE_A, "/api/verify")
    assert r.get_json()["valid"] is True
    assert set(r.get_json()) == {"valid", "activated_at", "expires_at"}
    assert verify(client, key, "GatePassKiosk", DEVICE_B, "/api/verify").get_json()["valid"] is False


def test_device_bound_by_old_server_after_migration_is_respected(client):
    assert client.get("/health").status_code == 200
    key = "GP-" + "EF56" * 12
    _old_server_insert(key, device=DEVICE_A)  # old server activated it on computer A
    assert verify(client, key, "GatePassKiosk", DEVICE_A, "/api/verify").get_json()["valid"] is True
    r = verify(client, key, "GatePassKiosk", DEVICE_B, "/api/verify")
    assert r.get_json() == {"valid": False, "reason": "License belongs to another computer"}


def test_startup_sync_is_idempotent_and_respects_reset(admin):
    key = "GP-" + "AB90" * 12
    _old_server_insert(key, device=DEVICE_A)
    for _ in range(2):
        portal.app.config["SCHEMA_READY"] = False
        assert admin.get("/health").status_code == 200
    with psycopg.connect(DB) as conn:
        assert conn.execute("SELECT count(*) FROM activations").fetchone()[0] == 1
        lic = conn.execute("SELECT id FROM licenses").fetchone()[0]
    assert post(admin, f"/licenses/{lic}/reset-devices").status_code == 302
    portal.app.config["SCHEMA_READY"] = False  # restart after the reset must not resurrect device A
    assert admin.get("/health").status_code == 200
    with psycopg.connect(DB) as conn:
        assert conn.execute("SELECT count(*) FROM activations").fetchone()[0] == 0


# ------------------------------------------------------------------ robustness
def test_concurrent_activations_allow_exactly_one_computer(admin):
    import threading
    key = make_key(admin)
    results = []

    def go(device):
        c = portal.app.test_client()
        c.environ_base["wsgi.url_scheme"] = "https"
        results.append(verify(c, key, "gatepasskiosk", device, "/api/verify").get_json()["valid"])

    threads = [threading.Thread(target=go, args=(d,)) for d in (DEVICE_A, DEVICE_B, DEVICE_C) * 3]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count(True) == 3  # all calls from the one winning computer
    with psycopg.connect(DB) as conn:
        assert conn.execute("SELECT count(*) FROM activations").fetchone()[0] == 1


def test_database_failure_never_reports_a_valid_license(admin, monkeypatch):
    key = make_key(admin)
    assert verify(admin, key, "gatepasskiosk", DEVICE_A, "/api/verify").get_json()["valid"] is True

    def boom():
        raise psycopg.OperationalError("database unreachable")

    monkeypatch.setattr(portal, "db", boom)
    portal.app.config["PROPAGATE_EXCEPTIONS"] = False
    r = verify(admin, key, "gatepasskiosk", DEVICE_A, "/api/verify")
    assert r.status_code == 500
    assert not (r.get_json(silent=True) or {}).get("valid")


# ------------------------------------------------------------------ who a key belongs to
def _last_license_id():
    with psycopg.connect(DB) as conn:
        return conn.execute("SELECT id FROM licenses ORDER BY id DESC LIMIT 1").fetchone()[0]


def test_key_can_be_named_and_renamed(admin):
    r = post(admin, "/projects/gatepasskiosk/licenses", duration="1 year", max_devices="1",
             assigned_to="  Rahim   front desk ")
    assert r.status_code == 302
    page = admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    assert 'value="Rahim front desk"' in page  # spaces tidied
    lid = _last_license_id()
    assert post(admin, f"/licenses/{lid}/name", assigned_to="Siti").status_code == 302
    page = admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    assert 'value="Siti"' in page and "Rahim" not in page


def test_names_are_escaped_and_length_limited(admin):
    post(admin, "/projects/gatepasskiosk/licenses", duration="1 year", max_devices="1",
         assigned_to="<script>alert(1)</script>" + "x" * 200)
    page = admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    assert "<script>alert(1)" not in page
    with psycopg.connect(DB) as conn:
        assert len(conn.execute("SELECT assigned_to FROM licenses").fetchone()[0]) <= 80


def test_unnamed_keys_still_work_and_revoke_is_direct(admin):
    key = make_key(admin)  # no name given
    assert verify(admin, key, "gatepasskiosk", DEVICE_A, "/api/verify").get_json()["valid"] is True
    lid = _last_license_id()
    assert post(admin, f"/licenses/{lid}/revoke").status_code == 302
    assert verify(admin, key, "gatepasskiosk", DEVICE_A, "/api/verify").get_json()["valid"] is False


def test_naming_needs_login_and_csrf(client):
    assert client.post("/licenses/1/name", data={"assigned_to": "x"}).status_code in (302, 400, 401, 403)


def test_old_server_keys_still_work_with_the_new_column(client):
    assert client.get("/health").status_code == 200
    key = "GP-" + "9A8B" * 12
    _old_server_insert(key)  # the old server knows nothing about the name column
    assert verify(client, key, "GatePassKiosk", DEVICE_A, "/api/verify").get_json()["valid"] is True


def test_key_search_and_status_filter(admin):
    for n in ("Rahim", "Siti"):
        post(admin, "/projects/gatepasskiosk/licenses", duration="1 year", max_devices="1", assigned_to=n)
    page = admin.get("/projects/gatepasskiosk?q=rahim").get_data(as_text=True)
    assert 'value="Rahim"' in page and 'value="Siti"' not in page
    assert "No keys match." in admin.get("/projects/gatepasskiosk?status=revoked").get_data(as_text=True)
    assert admin.get("/projects/gatepasskiosk?status=bogus").status_code == 200


def test_view_switch_cookie_and_layout_links(admin):
    page = admin.get("/").get_data(as_text=True)
    assert 'media="(min-width: 960px)"' in page and "width=device-width" in page  # auto
    r = admin.get("/view?mode=desktop&next=/projects/gatepasskiosk")
    assert r.status_code == 302 and r.headers["Location"] == "/projects/gatepasskiosk"
    page = admin.get("/").get_data(as_text=True)
    assert "width=1100" in page and "desktop.css" in page and "min-width: 960px" not in page
    admin.get("/view?mode=mobile")
    page = admin.get("/").get_data(as_text=True)
    assert "desktop.css" not in page and "width=device-width" in page
    admin.get("/view?mode=auto")
    assert 'media="(min-width: 960px)"' in admin.get("/").get_data(as_text=True)


def test_view_switch_is_safe(client):
    for nxt in ("//evil.example", "https://evil.example", "/\\evil.example"):
        r = client.get("/view", query_string={"mode": "desktop", "next": nxt})
        assert r.headers["Location"] == "/"
    client.get("/view?mode=auto")
    client.get("/view?mode=bogus")
    assert 'media="(min-width: 960px)"' in client.get("/login").get_data(as_text=True)  # still auto


def test_project_page_section_order(admin):
    page = admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    assert page.index('id="releases"') < page.index('id="keys"') < page.index('id="details"')


def test_mobile_sections_are_collapsible_and_keep_order(admin):
    page = admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    assert page.count('<details class="msec" open>') == 4  # github, releases, keys, details
    assert "Existing keys (" in page and "Portal-managed releases (" in page
    assert page.index('id="releases"') < page.index('id="keys"') < page.index('id="details"')
    assert "app.js" in page
    filtered = admin.get("/projects/gatepasskiosk?q=x").get_data(as_text=True)
    assert "data-keep-open><summary>Existing keys" in filtered


def test_app_navigation_pages_and_project_tabs(admin):
    home = admin.get("/").get_data(as_text=True)
    for link in ('href="/"', 'href="/projects"', 'href="/activity"', 'class="bottomnav"'):
        assert link in home
    assert 'id="recent-releases"' in home and "See all activations" in home
    projects = admin.get("/projects").get_data(as_text=True)
    assert "gatepasskiosk" in projects and "Add a project" in projects
    assert "Activations (" in admin.get("/activity").get_data(as_text=True)
    page = admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    assert '<div class="tabpane active" data-tab="overview">' in page
    for tab in ("releases", "keys", "settings"):
        assert f'<div class="tabpane" data-tab="{tab}">' in page
    keys = admin.get("/projects/gatepasskiosk?tab=keys").get_data(as_text=True)
    assert '<div class="tabpane active" data-tab="keys">' in keys
    filtered = admin.get("/projects/gatepasskiosk?q=zz").get_data(as_text=True)
    assert '<div class="tabpane active" data-tab="keys">' in filtered
    assert '<div class="tabpane active" data-tab="overview">' in admin.get(
        "/projects/gatepasskiosk?tab=bogus").get_data(as_text=True)
    anon = portal.app.test_client()
    anon.environ_base["wsgi.url_scheme"] = "https"
    for path in ("/projects", "/activity"):
        assert "/login" in anon.get(path).headers["Location"]
    r = post(admin, "/projects", name="", slug="x")
    assert r.headers["Location"].endswith("/projects")
