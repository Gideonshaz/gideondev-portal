import base64
import os
import sys

from cryptography.fernet import Fernet

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DATABASE_URL", "postgresql://postgres@127.0.0.1:5433/portal_test")
os.environ.setdefault("SESSION_SECRET", "x" * 40)
os.environ.setdefault("ADMIN_PASSWORD", "correct horse battery")
os.environ.setdefault("KEY_ENCRYPTION_SECRET", Fernet.generate_key().decode())
os.environ.setdefault("SIGNING_PRIVATE_KEY", base64.b64encode(os.urandom(32)).decode())

import psycopg
import pytest

import app as portal
from migrations import MIGRATIONS

DEVICE_A = "A" * 24
DEVICE_B = "B" * 24
DEVICE_C = "C" * 24


@pytest.fixture
def fresh():
    with psycopg.connect(os.environ["DATABASE_URL"], autocommit=True) as c:
        c.execute("DROP SCHEMA public CASCADE")
        c.execute("CREATE SCHEMA public")
    portal.app.config["SCHEMA_READY"] = False


@pytest.fixture
def client(fresh):
    c = portal.app.test_client()
    c.environ_base["wsgi.url_scheme"] = "https"
    return c


@pytest.fixture
def admin(client):
    r = client.post("/login", data={"password": os.environ["ADMIN_PASSWORD"]})
    assert r.status_code == 302
    return client


def token(c):
    with c.session_transaction() as s:
        return s["csrf"]


def post(c, url, **data):
    data["csrf"] = token(c)
    return c.post(url, data=data)


def make_key(c, slug="gatepasskiosk", duration="1 year", devices=1):
    """Generate a key through the admin UI and return its plaintext."""
    r = post(c, f"/projects/{slug}/licenses", duration=duration, max_devices=str(devices))
    assert r.status_code == 302
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        ct = conn.execute("SELECT key_ciphertext FROM licenses ORDER BY id DESC LIMIT 1").fetchone()[0]
    return portal.fernet.decrypt(ct.encode()).decode()


def legacy_schema():
    with psycopg.connect(os.environ["DATABASE_URL"], autocommit=True) as c:
        c.execute(MIGRATIONS[0][1])
