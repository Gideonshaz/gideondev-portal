import os

import pytest

import app as portal
from conftest import make_key, post, token


def project_id(slug):
    with portal.db() as conn:
        return conn.execute("SELECT id FROM projects WHERE slug=%s", (slug,)).fetchone()[0]


@pytest.fixture
def team(admin):
    """Owner creates 'ahmad' with access to GatePassKiosk + GatePassSecurity only.
    Returns a separate signed-in client for the team member."""
    post(admin, "/projects", name="Secret App", slug="secret-app")
    r = admin.post("/users", data={"csrf": token(admin), "username": "Ahmad", "password": "correct-horse-1",
                                   "project_ids": [str(project_id("gatepasskiosk")), str(project_id("gatepasssecurity"))]})
    assert r.status_code == 302
    c = portal.app.test_client()
    c.environ_base["wsgi.url_scheme"] = "https"
    r = c.post("/login", data={"username": "ahmad", "password": "correct-horse-1"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/team")
    return c


def test_team_member_sees_only_assigned_apps(team):
    home = team.get("/team").get_data(as_text=True)
    assert "GatePassKiosk" in home and "GatePassSecurity" in home
    assert "Secret App" not in home and "HR" not in home
    assert "0 keys" in home and "built-in" not in home
    assert team.get("/team/gatepasskiosk").status_code == 200
    assert team.get("/team/secret-app").status_code == 404
    assert team.get("/team/gatepasshrdashboard").status_code == 404


def test_team_member_can_generate_list_and_name_keys(team, admin):
    r = post(team, "/team/gatepasskiosk/licenses", duration="1 year", max_devices="2", assigned_to="Front gate")
    assert r.status_code == 302
    with portal.db() as conn:
        row = conn.execute("SELECT id, assigned_to, created_by, max_devices, project_id FROM licenses ORDER BY id DESC LIMIT 1").fetchone()
    assert row[1:4] == ("Front gate", "ahmad", 2) and row[4] == project_id("gatepasskiosk")
    page = team.get("/team/gatepasskiosk").get_data(as_text=True)
    assert "GP-" in page and 'value="Front gate"' in page
    post(team, f"/team/licenses/{row[0]}/name", assigned_to="Lobby")
    with portal.db() as conn:
        assert conn.execute("SELECT assigned_to FROM licenses WHERE id=%s", (row[0],)).fetchone()[0] == "Lobby"
    # the owner sees who made it
    assert "made by ahmad" in admin.get("/projects/gatepasskiosk").get_data(as_text=True)
    # search works
    assert "No keys match." in team.get("/team/gatepasskiosk?q=zzz").get_data(as_text=True)


def test_team_member_cannot_touch_other_apps(team, admin):
    other = make_key(admin, slug="gatepasshrdashboard")
    with portal.db() as conn:
        lid = conn.execute("SELECT id FROM licenses ORDER BY id DESC LIMIT 1").fetchone()[0]
        before = conn.execute("SELECT count(*) FROM licenses").fetchone()[0]
    assert post(team, "/team/gatepasshrdashboard/licenses", duration="1 year", max_devices="1").status_code == 404
    assert post(team, "/team/secret-app/licenses", duration="1 year", max_devices="1").status_code == 404
    assert post(team, f"/team/licenses/{lid}/name", assigned_to="hacked").status_code == 404
    with portal.db() as conn:
        assert conn.execute("SELECT count(*) FROM licenses").fetchone()[0] == before
        assert conn.execute("SELECT assigned_to FROM licenses WHERE id=%s", (lid,)).fetchone()[0] != "hacked"
    assert other not in team.get("/team/gatepasskiosk").get_data(as_text=True)


def test_team_member_is_kept_out_of_every_admin_page(team, admin):
    make_key(admin)
    with portal.db() as conn:
        lid = conn.execute("SELECT id FROM licenses ORDER BY id DESC LIMIT 1").fetchone()[0]
    for path in ("/", "/projects", "/activity", "/github", "/users", "/projects/gatepasskiosk",
                 "/projects/gatepasskiosk?tab=keys"):
        r = team.get(path)
        assert r.status_code == 302 and r.headers["Location"].endswith("/team"), path
    for path in (f"/licenses/{lid}/revoke", f"/licenses/{lid}/reset-devices", f"/licenses/{lid}/name",
                 "/projects/gatepasskiosk/licenses", "/projects/gatepasskiosk/releases",
                 "/projects/gatepasskiosk/edit", "/projects/gatepasskiosk/github/sync", "/users"):
        r = post(team, path, duration="1 year", max_devices="1", assigned_to="x", username="evil",
                 password="0123456789", name="x", version="9.9.9")
        assert r.status_code == 302 and r.headers["Location"].endswith("/team"), path
    with portal.db() as conn:
        assert conn.execute("SELECT revoked_at FROM licenses WHERE id=%s", (lid,)).fetchone()[0] is None
        assert conn.execute("SELECT count(*) FROM team_users").fetchone()[0] == 1
    page = team.get("/team/gatepasskiosk").get_data(as_text=True)
    for word in ("Revoke", "Reset devices", "Releases", "GitHub", "bottomnav"):
        assert word not in page


def test_team_routes_need_csrf_and_login(team):
    assert team.post("/team/gatepasskiosk/licenses", data={"duration": "1 year", "max_devices": "1"}).status_code == 403
    anon = portal.app.test_client()
    anon.environ_base["wsgi.url_scheme"] = "https"
    assert "/login" in anon.get("/team").headers["Location"]
    assert "/login" in anon.post("/team/gatepasskiosk/licenses").headers["Location"]


def test_disable_and_password_change_sign_out_immediately(team, admin):
    with portal.db() as conn:
        uid = conn.execute("SELECT id FROM team_users").fetchone()[0]
    post(admin, f"/users/{uid}/active", active="0")
    assert "/login" in team.get("/team").headers["Location"]
    r = team.post("/login", data={"username": "ahmad", "password": "correct-horse-1"})
    assert r.status_code == 401
    post(admin, f"/users/{uid}/active", active="1")
    assert team.post("/login", data={"username": "ahmad", "password": "correct-horse-1"}).status_code == 302
    post(admin, f"/users/{uid}/password", password="new-password-22")
    assert "/login" in team.get("/team").headers["Location"]
    assert team.post("/login", data={"username": "ahmad", "password": "correct-horse-1"}).status_code == 401
    assert team.post("/login", data={"username": "ahmad", "password": "new-password-22"}).status_code == 302


def test_access_can_be_changed(team, admin):
    with portal.db() as conn:
        uid = conn.execute("SELECT id FROM team_users").fetchone()[0]
    admin.post(f"/users/{uid}/projects", data={"csrf": token(admin), "project_ids": [str(project_id("gatepasshrdashboard"))]})
    assert team.get("/team/gatepasskiosk").status_code == 404
    assert team.get("/team/gatepasshrdashboard").status_code == 200


def test_owner_login_unchanged_and_bad_logins_rejected(client):
    assert client.post("/login", data={"username": "nobody", "password": os.environ["ADMIN_PASSWORD"]}).status_code == 401
    r = client.post("/login", data={"username": "", "password": os.environ["ADMIN_PASSWORD"]})
    assert r.status_code == 302 and r.headers["Location"].endswith("/")


def test_account_validation(admin):
    pid = str(project_id("gatepasskiosk"))
    for user, pw, ids in (("a", "long-enough-pw", [pid]), ("bob", "short", [pid]), ("bob", "long-enough-pw", []),
                          ("Bad Name!", "long-enough-pw", [pid])):
        admin.post("/users", data={"csrf": token(admin), "username": user, "password": pw, "project_ids": ids})
    admin.post("/users", data={"csrf": token(admin), "username": "bob", "password": "long-enough-pw", "project_ids": [pid]})
    admin.post("/users", data={"csrf": token(admin), "username": "BOB", "password": "long-enough-pw", "project_ids": [pid]})
    with portal.db() as conn:
        rows = conn.execute("SELECT username, password_hash FROM team_users").fetchall()
    assert [r[0] for r in rows] == ["bob"] and "long-enough-pw" not in rows[0][1]


def test_team_login_is_throttled(admin):
    c = portal.app.test_client()
    c.environ_base["wsgi.url_scheme"] = "https"
    codes = [c.post("/login", data={"username": "ahmad", "password": "wrong"}).status_code for _ in range(12)]
    assert codes[-1] == 429
