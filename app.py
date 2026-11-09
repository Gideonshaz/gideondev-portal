"""GideonDev Portal: licensing, activation and update server for all projects.

Public API (used by your apps and portfolio site)
  POST /api/verify                       legacy endpoint, same behaviour as the old license server
  POST /api/v1/verify                    {key, project, device_id} -> activation + signed offline token
  GET  /api/v1/public-key                Ed25519 public key for verifying tokens offline
  GET  /api/v1/projects                  public projects + latest stable release
  GET  /api/v1/projects/<slug>           public project detail + release history
  GET  /api/v1/projects/<slug>/latest    update check: ?current=1.0.2&channel=stable
Admin site: /login, /, /projects/<slug>
"""
import base64
import calendar
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import psycopg
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix

from migrations import MIGRATIONS

DURATIONS = {"3 months": 3, "6 months": 6, "12 months": 12,
             "1 year": 12, "2 years": 24, "3 years": 36}
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,48}$")
VERSION_RE = re.compile(r"^\d+(\.\d+){0,3}([-+][0-9A-Za-z.-]{1,32})?$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW_MIN = 15

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = os.environ["SESSION_SECRET"]
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Strict", MAX_CONTENT_LENGTH=16384)
fernet = Fernet(os.environ["KEY_ENCRYPTION_SECRET"].encode())
CORS_ORIGINS = [o.strip() for o in os.environ.get(
    "CORS_ORIGINS", "https://gideonshaz.github.io").split(",") if o.strip()]
OFFLINE_GRACE_DAYS = int(os.environ.get("OFFLINE_GRACE_DAYS", "7"))

_signing_key = None
if os.environ.get("SIGNING_PRIVATE_KEY"):
    _signing_key = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(os.environ["SIGNING_PRIVATE_KEY"]))


# ---------------------------------------------------------------- database
def db():
    return psycopg.connect(os.environ["DATABASE_URL"], autocommit=False)


def sync_legacy(conn, digest=None):
    """Adopt rows written by the OLD license server (no project_id, device kept in
    licenses.device_id). Idempotent and additive, so it is safe to run any time, which keeps
    a rollback to the old server and a later switch forward lossless."""
    extra, args = (" AND key_hash=%s", (digest,)) if digest else ("", ())
    conn.execute("""UPDATE licenses SET project_id = p.id FROM projects p
                    WHERE licenses.project_id IS NULL AND p.slug = lower(licenses.product)"""
                 + extra.replace("key_hash", "licenses.key_hash"), args)
    conn.execute("""INSERT INTO activations (license_id, device_id, first_seen, last_seen)
                    SELECT id, device_id, COALESCE(activated_at, now()), COALESCE(activated_at, now())
                    FROM licenses WHERE device_id IS NOT NULL""" + extra + """
                    ON CONFLICT (license_id, device_id) DO NOTHING""", args)


def migrate():
    with db() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(727401)")  # safe with many workers
        conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
                          name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())""")
        done = {r[0] for r in conn.execute("SELECT name FROM schema_migrations")}
        for name, sql in MIGRATIONS:
            if name not in done:
                conn.execute(sql)
                conn.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (name,))
        sync_legacy(conn)


@app.before_request
def ensure_schema():
    if not app.config.get("SCHEMA_READY"):
        migrate()
        app.config["SCHEMA_READY"] = True


# ---------------------------------------------------------------- helpers
def add_months(d, n):
    y = d.year + (d.month - 1 + n) // 12
    m = (d.month - 1 + n) % 12 + 1
    return d.replace(year=y, month=m, day=min(d.day, calendar.monthrange(y, m)[1]))


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def vkey(version):
    nums = [int(x) for x in re.findall(r"\d+", version.split("-")[0].split("+")[0])][:4]
    return tuple(nums + [0] * (4 - len(nums)))


def admin_only(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


def csrf():
    token = session.get("csrf")
    if not token or not hmac.compare_digest(token, request.form.get("csrf", "")):
        abort(403)


@app.context_processor
def inject():
    side = []
    if session.get("admin") and request.endpoint not in (None, "static"):
        try:
            with db() as conn:
                side = [dict(slug=r[0], name=r[1])
                        for r in conn.execute("SELECT slug, name FROM projects ORDER BY name").fetchall()]
        except Exception:
            side = []
    return {"csrf": session.get("csrf", ""), "side_projects": side}


@app.after_request
def headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'")
    origin = request.headers.get("Origin")
    if (request.method in ("GET", "OPTIONS") and request.path.startswith("/api/v1/")
            and origin in CORS_ORIGINS):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    return response


def show_key(ciphertext):
    """Decrypt a stored key for display; None if it was encrypted with another secret."""
    try:
        return fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        return None


@app.get("/health")
def health():
    return {"ok": True}


def get_project(conn, slug):
    row = conn.execute("""SELECT id, slug, name, description, repo_url, is_public
                          FROM projects WHERE slug=%s""", (slug,)).fetchone()
    if not row:
        abort(404)
    return dict(id=row[0], slug=row[1], name=row[2], description=row[3],
                repo_url=row[4], is_public=row[5])


def release_dict(r):
    return dict(version=r[0], channel=r[1], download_url=r[2], sha256=r[3], size_bytes=r[4],
                notes=r[5], mandatory=r[6], released_at=r[7].isoformat())


def releases_for(conn, project_id, channel=None, include_yanked=False):
    sql = """SELECT version, channel, download_url, sha256, size_bytes, notes, mandatory,
                    created_at, yanked, id FROM releases WHERE project_id=%s"""
    params = [project_id]
    if channel:
        sql += " AND channel=%s"
        params.append(channel)
    if not include_yanked:
        sql += " AND NOT yanked"
    rows = conn.execute(sql, params).fetchall()
    return sorted(rows, key=lambda r: vkey(r[0]), reverse=True)


# ---------------------------------------------------------------- license logic
def sign_token(slug, device, expires, now):
    if not _signing_key:
        return None, None
    offline_until = min(expires, now + timedelta(days=OFFLINE_GRACE_DAYS))
    payload = {"v": 1, "p": slug, "d": device, "iat": now.isoformat(),
               "exp": expires.isoformat(), "offline_until": offline_until.isoformat()}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return b64u(raw) + "." + b64u(_signing_key.sign(raw)), offline_until


def run_verify(key, slug, device):
    """Shared by the legacy and v1 endpoints. Returns (result dict, token, offline_until)."""
    digest = hashlib.sha256(key.encode()).hexdigest()
    with db() as conn:
        sync_legacy(conn, digest)  # picks up a key the old server created or bound meanwhile
        row = conn.execute("""SELECT l.id, p.slug, l.months, l.activated_at, l.expires_at,
                                     l.revoked_at, l.max_devices
                              FROM licenses l JOIN projects p ON p.id = l.project_id
                              WHERE l.key_hash=%s FOR UPDATE OF l""", (digest,)).fetchone()
        if not row or row[1] != slug:
            return dict(valid=False, reason="Invalid product key"), None, None
        lic_id, _, months, activation, expiry, revoked, max_devices = row
        if revoked:
            return dict(valid=False, reason="License revoked"), None, None
        now = datetime.now(timezone.utc)
        if expiry and expiry <= now:
            return dict(valid=False, reason="License expired"), None, None
        devices = [r[0] for r in conn.execute(
            "SELECT device_id FROM activations WHERE license_id=%s", (lic_id,))]
        if device in devices:
            conn.execute("UPDATE activations SET last_seen=now() WHERE license_id=%s AND device_id=%s",
                         (lic_id, device))
        else:
            if len(devices) >= max_devices:
                reason = ("License belongs to another computer" if max_devices == 1
                          else "Device limit reached")
                return dict(valid=False, reason=reason), None, None
            conn.execute("INSERT INTO activations (license_id, device_id) VALUES (%s,%s)",
                         (lic_id, device))
            devices.append(device)
        if not activation:
            activation = now
            expiry = add_months(now, months)
            conn.execute("""UPDATE licenses SET activated_at=%s, expires_at=%s, device_id=%s
                            WHERE id=%s""", (activation, expiry, devices[0], lic_id))
    token, offline_until = sign_token(slug, device, expiry, now)
    result = dict(valid=True, activated_at=activation.isoformat(), expires_at=expiry.isoformat(),
                  devices_used=len(devices), max_devices=max_devices)
    return result, token, offline_until


def parse_verify_body(slug_field):
    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip().upper()
    slug = str(data.get(slug_field, "")).strip().lower()
    device = str(data.get("device_id", "")).strip()
    if (not key.startswith("GP-") or len(key) != 51 or not SLUG_RE.match(slug)
            or len(device) < 16 or len(device) > 128):
        return None
    return key, slug, device


@app.post("/api/verify")
def verify_legacy():
    parsed = parse_verify_body("product")
    if not parsed:
        return jsonify(valid=False, reason="Invalid license details"), 400
    result, _, _ = run_verify(*parsed)
    if result["valid"]:  # keep the exact legacy response shape
        result = dict(valid=True, activated_at=result["activated_at"],
                      expires_at=result["expires_at"])
    return jsonify(result)


@app.post("/api/v1/verify")
def verify_v1():
    parsed = parse_verify_body("project")
    if not parsed:
        return jsonify(valid=False, reason="Invalid license details"), 400
    result, token, offline_until = run_verify(*parsed)
    if result["valid"] and token:
        result["token"] = token
        result["offline_until"] = offline_until.isoformat()
    return jsonify(result)


@app.get("/api/v1/public-key")
def public_key():
    if not _signing_key:
        return jsonify(error="Token signing is not configured"), 404
    raw = _signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return jsonify(algorithm="Ed25519", public_key=base64.b64encode(raw).decode())


# ---------------------------------------------------------------- public project / update API
@app.get("/api/v1/projects")
def api_projects():
    out = []
    with db() as conn:
        rows = conn.execute("""SELECT id, slug, name, description, repo_url FROM projects
                               WHERE is_public ORDER BY name""").fetchall()
        for pid, slug, name, desc, repo in rows:
            rel = releases_for(conn, pid, "stable")
            out.append(dict(slug=slug, name=name, description=desc, repo_url=repo,
                            latest=release_dict(rel[0]) if rel else None))
    return jsonify(projects=out)


@app.get("/api/v1/projects/<slug>")
def api_project(slug):
    with db() as conn:
        p = get_project(conn, slug)
        if not p["is_public"]:
            abort(404)
        rels = [release_dict(r) for r in releases_for(conn, p["id"])]
    return jsonify(slug=p["slug"], name=p["name"], description=p["description"],
                   repo_url=p["repo_url"], releases=rels)


@app.get("/api/v1/projects/<slug>/latest")
def api_latest(slug):
    channel = request.args.get("channel", "stable")
    current = request.args.get("current", "")
    if channel not in ("stable", "beta") or (current and not VERSION_RE.match(current)):
        return jsonify(error="Invalid channel or version"), 400
    with db() as conn:
        p = get_project(conn, slug)
        # beta users also get stable releases; stable users never get betas
        rels = releases_for(conn, p["id"], None if channel == "beta" else "stable")
    if not rels:
        return jsonify(update_available=False, current=current or None)
    latest = release_dict(rels[0])
    newer = (not current) or vkey(latest["version"]) > vkey(current)
    body = dict(update_available=bool(newer), current=current or None, latest=latest)
    if newer and current:
        # mandatory if any release newer than `current` is flagged mandatory
        body["mandatory"] = any(r[6] and vkey(r[0]) > vkey(current) for r in rels)
    return jsonify(body)


# ---------------------------------------------------------------- admin: auth
def login_throttled(conn, ip):
    conn.execute("DELETE FROM login_attempts WHERE at < now() - interval '1 day'")
    n = conn.execute("""SELECT count(*) FROM login_attempts
                        WHERE ip=%s AND at > now() - make_interval(mins => %s)""",
                     (ip, LOGIN_WINDOW_MIN)).fetchone()[0]
    return n >= LOGIN_MAX_FAILS


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        with db() as conn:
            if login_throttled(conn, ip):
                return render_template("login.html",
                                       error="Too many attempts. Try again in 15 minutes."), 429
            if hmac.compare_digest(request.form.get("password", ""), os.environ["ADMIN_PASSWORD"]):
                conn.execute("DELETE FROM login_attempts WHERE ip=%s", (ip,))
                session.clear()
                session["admin"] = True
                session["csrf"] = secrets.token_urlsafe(32)
                return redirect(url_for("dashboard"))
            conn.execute("INSERT INTO login_attempts (ip) VALUES (%s)", (ip,))
        return render_template("login.html", error="Incorrect password."), 401
    return render_template("login.html", error=None)


@app.post("/logout")
@admin_only
def logout():
    csrf()
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- admin: dashboard & projects
@app.get("/")
@admin_only
def dashboard():
    with db() as conn:
        rows = conn.execute("""
            SELECT p.slug, p.name, p.is_public,
                   (SELECT count(*) FROM releases r WHERE r.project_id=p.id AND NOT r.yanked),
                   (SELECT count(*) FROM licenses l WHERE l.project_id=p.id AND l.revoked_at IS NULL),
                   (SELECT count(*) FROM activations a JOIN licenses l ON l.id=a.license_id
                     WHERE l.project_id=p.id)
            FROM projects p ORDER BY p.name""").fetchall()
        recent_rel = conn.execute("""
            SELECT p.name, r.version, r.channel, r.created_at FROM releases r
            JOIN projects p ON p.id=r.project_id WHERE NOT r.yanked
            ORDER BY r.created_at DESC LIMIT 5""").fetchall()
        recent_act = conn.execute("""
            SELECT p.name, a.device_id, a.last_seen FROM activations a
            JOIN licenses l ON l.id=a.license_id JOIN projects p ON p.id=l.project_id
            ORDER BY a.last_seen DESC LIMIT 5""").fetchall()
    projects = [dict(slug=r[0], name=r[1], is_public=r[2], releases=r[3], licenses=r[4],
                     devices=r[5]) for r in rows]
    totals = dict(projects=len(projects), key_count=sum(p["licenses"] for p in projects),
                  devices=sum(p["devices"] for p in projects),
                  releases=sum(p["releases"] for p in projects))
    return render_template("dashboard.html", projects=projects, totals=totals,
                           recent_rel=recent_rel, recent_act=recent_act)


@app.post("/projects")
@admin_only
def project_create():
    csrf()
    slug = request.form.get("slug", "").strip().lower()
    name = request.form.get("name", "").strip()
    if not SLUG_RE.match(slug) or not name or len(name) > 80:
        flash("Slug must be 2-49 characters: lowercase letters, numbers, dashes. Name is required.")
        return redirect(url_for("dashboard"))
    try:
        with db() as conn:
            conn.execute("INSERT INTO projects (slug, name) VALUES (%s,%s)", (slug, name))
    except psycopg.errors.UniqueViolation:
        flash("That slug already exists.")
        return redirect(url_for("dashboard"))
    return redirect(url_for("project_page", slug=slug))


@app.get("/projects/<slug>")
@admin_only
def project_page(slug):
    with db() as conn:
        p = get_project(conn, slug)
        rels = releases_for(conn, p["id"], include_yanked=True)
        lic_rows = conn.execute("""
            SELECT id, key_ciphertext, duration, max_devices, activated_at, expires_at, revoked_at,
                   assigned_to
            FROM licenses WHERE project_id=%s ORDER BY id DESC""", (p["id"],)).fetchall()
        devices = {}
        for lid, dev, seen in conn.execute("""
                SELECT a.license_id, a.device_id, a.last_seen FROM activations a
                JOIN licenses l ON l.id=a.license_id WHERE l.project_id=%s""", (p["id"],)):
            devices.setdefault(lid, []).append(dict(id=dev[:10] + "…", seen=seen))
    now = datetime.now(timezone.utc)
    licenses = []
    for r in lic_rows:
        exp = r[5]
        if r[6]:
            status = "revoked"
        elif exp is None:
            status = "unused"
        elif exp < now:
            status = "expired"
        else:
            status = "active"
        left = ""
        if status == "active":
            days = (exp - now).days
            left = f"{days} days left" if days < 60 else f"{days // 30} months left"
        licenses.append(dict(id=r[0], key=show_key(r[1]), duration=r[2],
                             max_devices=r[3], activated_at=r[4], expires_at=exp, revoked_at=r[6],
                             assigned_to=r[7], status=status, left=left,
                             devices=devices.get(r[0], [])))
    stats = dict(total=len(licenses),
                 active=sum(1 for l in licenses if l["status"] == "active"),
                 unused=sum(1 for l in licenses if l["status"] == "unused"),
                 devices=sum(len(l["devices"]) for l in licenses))
    q = request.args.get("q", "").strip().lower()[:80]
    status_filter = request.args.get("status", "")
    if status_filter not in ("active", "unused", "expired", "revoked"):
        status_filter = ""
    if status_filter:
        licenses = [l for l in licenses if l["status"] == status_filter]
    if q:
        licenses = [l for l in licenses
                    if q in (l["assigned_to"] or "").lower() or q in (l["key"] or "").lower()]
    releases = [dict(id=r[9], version=r[0], channel=r[1], download_url=r[2], notes=r[5],
                     mandatory=r[6], yanked=r[8], created_at=r[7]) for r in rels]
    latest = next((r for r in releases if not r["yanked"]), None)
    return render_template("project.html", p=p, releases=releases, licenses=licenses,
                           durations=DURATIONS, stats=stats, latest=latest, q=q,
                           status_filter=status_filter)


@app.post("/projects/<slug>/edit")
@admin_only
def project_edit(slug):
    csrf()
    name = request.form.get("name", "").strip()
    if not name or len(name) > 80:
        abort(400)
    with db() as conn:
        p = get_project(conn, slug)
        conn.execute("""UPDATE projects SET name=%s, description=%s, repo_url=%s, is_public=%s
                        WHERE id=%s""",
                     (name, request.form.get("description", "").strip()[:500],
                      request.form.get("repo_url", "").strip()[:200],
                      request.form.get("is_public") == "on", p["id"]))
        # keep the legacy column readable by the old app
        conn.execute("UPDATE licenses SET product=%s WHERE project_id=%s", (name, p["id"]))
    flash("Project saved.")
    return redirect(url_for("project_page", slug=slug))


@app.post("/projects/<slug>/releases")
@admin_only
def release_add(slug):
    csrf()
    version = request.form.get("version", "").strip().lstrip("vV")
    url = request.form.get("download_url", "").strip()
    sha = request.form.get("sha256", "").strip().lower()
    channel = request.form.get("channel", "stable")
    if (not VERSION_RE.match(version) or not url.startswith("https://") or len(url) > 500
            or (sha and not SHA_RE.match(sha)) or channel not in ("stable", "beta")):
        flash("Check the form: version like 1.2.0, an https:// download link, "
              "optional 64-character SHA-256.")
        return redirect(url_for("project_page", slug=slug))
    try:
        with db() as conn:
            p = get_project(conn, slug)
            conn.execute("""INSERT INTO releases (project_id, version, channel, download_url, sha256,
                                                  notes, mandatory)
                            VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                         (p["id"], version, channel, url, sha,
                          request.form.get("notes", "").strip()[:2000],
                          request.form.get("mandatory") == "on"))
    except psycopg.errors.UniqueViolation:
        flash("That version already exists for this project.")
        return redirect(url_for("project_page", slug=slug))
    flash("Release published.")
    return redirect(url_for("project_page", slug=slug))


@app.post("/releases/<int:release_id>/yank")
@admin_only
def release_yank(release_id):
    csrf()
    with db() as conn:
        row = conn.execute("""UPDATE releases SET yanked = NOT yanked WHERE id=%s
                              RETURNING (SELECT slug FROM projects WHERE id=project_id)""",
                           (release_id,)).fetchone()
    if not row:
        abort(404)
    return redirect(url_for("project_page", slug=row[0]))


@app.post("/projects/<slug>/licenses")
@admin_only
def license_generate(slug):
    csrf()
    duration = request.form.get("duration")
    try:
        max_devices = int(request.form.get("max_devices", "1"))
    except ValueError:
        abort(400)
    if duration not in DURATIONS or not 1 <= max_devices <= 50:
        abort(400)
    key = "GP-" + secrets.token_hex(24).upper()
    assigned_to = clean_label(request.form.get("assigned_to"), 80)
    with db() as conn:
        p = get_project(conn, slug)
        conn.execute("""INSERT INTO licenses (key_hash, key_ciphertext, product, months, duration,
                                              project_id, max_devices, assigned_to)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                     (hashlib.sha256(key.encode()).hexdigest(), fernet.encrypt(key.encode()).decode(),
                      p["name"], DURATIONS[duration], duration, p["id"], max_devices,
                      assigned_to))
    flash("Key generated.")
    return redirect(url_for("project_page", slug=slug))


def clean_label(value, limit):
    """Names and notes are plain text. Collapse whitespace and cap the length."""
    return " ".join(str(value or "").split())[:limit]


@app.post("/licenses/<int:license_id>/name")
@admin_only
def license_name(license_id):
    csrf()
    with db() as conn:
        row = conn.execute("""SELECT p.slug FROM licenses l JOIN projects p ON p.id=l.project_id
                              WHERE l.id=%s""", (license_id,)).fetchone()
        if not row:
            abort(404)
        conn.execute("UPDATE licenses SET assigned_to=%s WHERE id=%s",
                     (clean_label(request.form.get("assigned_to"), 80), license_id))
    flash("Name saved.")
    return redirect(url_for("project_page", slug=row[0]))


def _license_action(license_id, sql_list):
    with db() as conn:
        row = conn.execute("""SELECT p.slug FROM licenses l JOIN projects p ON p.id=l.project_id
                              WHERE l.id=%s""", (license_id,)).fetchone()
        if not row:
            abort(404)
        for sql in sql_list:
            conn.execute(sql, (license_id,))
    return redirect(url_for("project_page", slug=row[0]))


@app.post("/licenses/<int:license_id>/revoke")
@admin_only
def license_revoke(license_id):
    csrf()
    return _license_action(license_id, [
        "UPDATE licenses SET revoked_at=now() WHERE id=%s AND revoked_at IS NULL"])


@app.post("/licenses/<int:license_id>/reset-devices")
@admin_only
def license_reset(license_id):
    csrf()
    return _license_action(license_id, [
        "DELETE FROM activations WHERE license_id=%s",
        "UPDATE licenses SET device_id=NULL WHERE id=%s"])


if __name__ == "__main__":
    app.run()
