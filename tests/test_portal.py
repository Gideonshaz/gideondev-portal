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
        assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 2


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
    assert page.status_code == 200 and b"unreadable" in page.data
