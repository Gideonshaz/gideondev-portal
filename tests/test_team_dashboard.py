import app as portal
from conftest import make_key, post
from test_team import team  # noqa: F401  (fixture)


def _activate(key_prefix_slug, device):
    """Attach a fake device to the newest key of the given app."""
    with portal.db() as conn:
        lid = conn.execute("""SELECT l.id FROM licenses l JOIN projects p ON p.id=l.project_id
                              WHERE p.slug=%s ORDER BY l.id DESC LIMIT 1""", (key_prefix_slug,)).fetchone()[0]
        conn.execute("INSERT INTO activations (license_id, device_id) VALUES (%s, %s)", (lid, device))
    return lid


def test_dashboard_shows_all_apps_but_devices_only_for_assigned(team, admin):
    make_key(admin, slug="gatepasskiosk")
    lid = _activate("gatepasskiosk", "KIOSK-DEVICE-AAAA")
    with portal.db() as conn:
        conn.execute("UPDATE licenses SET assigned_to='Front gate' WHERE id=%s", (lid,))
    make_key(admin, slug="gatepasshrdashboard")
    _activate("gatepasshrdashboard", "HR-SECRET-DEVICE")

    r = team.get("/team/dashboard")
    assert r.status_code == 200
    page = r.get_data(as_text=True)
    # every app is listed, including ones he is not assigned to
    for name in ("GatePassKiosk", "GatePassSecurity", "Secret App"):
        assert name in page
    # his devices are visible, with key name
    assert "KIOSK-DEVICE-A" in page and "Front gate" in page
    # devices of apps he does not own are not
    assert "HR-SECRET" not in page
    # and no license key text leaks at all
    assert "GP-" not in page


def test_dashboard_is_read_only(team):
    page = team.get("/team/dashboard").get_data(as_text=True)
    assert "<form" not in page.split("<main>", 1)[1]
    for word in ("Revoke", "Reset devices", "GitHub", "Settings", "bottomnav", "/users"):
        assert word not in page
    # both tabs present
    assert 'href="/team"' in page and 'href="/team/dashboard"' in page


def test_dashboard_needs_team_login(client, admin):
    r = client.get("/team/dashboard")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    # the owner is sent to his own dashboard, not the team one
    r = admin.get("/team/dashboard")
    assert r.status_code in (302, 403)


def test_disabled_member_loses_dashboard(team, admin):
    with portal.db() as conn:
        uid = conn.execute("SELECT id FROM team_users WHERE username='ahmad'").fetchone()[0]
    post(admin, f"/users/{uid}/active", active="0")
    r = team.get("/team/dashboard")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
