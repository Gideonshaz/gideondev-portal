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
import github_sync
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

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
            if session.get("staff_id"):
                return redirect(url_for("team_home"))
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


DUMMY_HASH = generate_password_hash("not-a-real-password")  # equalises timing for unknown users
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,40}$")


def current_staff():
    """The signed-in team member, re-checked on every request (disable/reset takes effect at once)."""
    sid = session.get("staff_id")
    if not sid:
        return None
    with db() as conn:
        r = conn.execute("""SELECT id, username, project_ids, active, session_version
                            FROM team_users WHERE id=%s""", (sid,)).fetchone()
    if not r or not r[3] or r[4] != session.get("staff_ver"):
        session.clear()
        return None
    return dict(id=r[0], username=r[1], project_ids=list(r[2] or []))


def staff_only(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user = current_staff()
        if not user:
            return redirect(url_for("login"))
        g.staff = user
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
    view = request.cookies.get("view")
    if view not in ("desktop", "mobile"):
        view = "auto"
    return {"csrf": session.get("csrf", ""), "side_projects": side, "view": view}


@app.get("/view")
def set_view():
    """Remember a layout choice (display preference only): auto, desktop or mobile."""
    mode = request.args.get("mode", "")
    nxt = request.args.get("next", "/")
    if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt or len(nxt) > 300:
        nxt = "/"
    resp = redirect(nxt)
    if mode == "auto":
        resp.delete_cookie("view", path="/")
    elif mode in ("desktop", "mobile"):
        resp.set_cookie("view", mode, max_age=60 * 60 * 24 * 365, path="/",
                        samesite="Lax", secure=request.is_secure)
    return resp


@app.after_request
def headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    form_action = "'self' https://github.com" if getattr(request, "github_form", False) else "'self'"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; style-src 'self'; form-action {form_action}; frame-ancestors 'none'")
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
    row = conn.execute("""SELECT id, slug, name, description, repo_url, is_public, github_repo,
                                 github_tag_prefix, gh_last_sync_at, gh_sync_ok, gh_sync_message
                          FROM projects WHERE slug=%s""", (slug,)).fetchone()
    if not row:
        abort(404)
    return dict(id=row[0], slug=row[1], name=row[2], description=row[3],
                repo_url=row[4], is_public=row[5], github_repo=row[6], github_tag_prefix=row[7],
                gh_last_sync_at=row[8], gh_sync_ok=row[9], gh_sync_message=row[10])


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
            username = request.form.get("username", "").strip().lower()[:40]
            if username:
                row = conn.execute("""SELECT id, password_hash, active, session_version
                                      FROM team_users WHERE username=%s""", (username,)).fetchone()
                ok = check_password_hash(row[1] if row else DUMMY_HASH, request.form.get("password", ""))
                if row and ok and row[2]:
                    conn.execute("DELETE FROM login_attempts WHERE ip=%s", (ip,))
                    conn.execute("UPDATE team_users SET last_login_at=now() WHERE id=%s", (row[0],))
                    session.clear()
                    session["staff_id"], session["staff_ver"] = row[0], row[3]
                    session["csrf"] = secrets.token_urlsafe(32)
                    return redirect(url_for("team_home"))
                conn.execute("INSERT INTO login_attempts (ip) VALUES (%s)", (ip,))
                return render_template("login.html", error="Incorrect username or password."), 401
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
def logout():
    if not (session.get("admin") or session.get("staff_id")):
        return redirect(url_for("login"))
    csrf()
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- admin: dashboard & projects
def _overview(conn, limit):
    rows = conn.execute("""
        SELECT p.slug, p.name, p.is_public,
               (SELECT count(*) FROM releases r WHERE r.project_id=p.id AND NOT r.yanked)
               + (SELECT count(*) FROM github_releases g WHERE g.project_id=p.id
                  AND g.removed_at IS NULL AND lower(g.repo)=lower(p.github_repo)),
               (SELECT count(*) FROM licenses l WHERE l.project_id=p.id AND l.revoked_at IS NULL),
               (SELECT count(*) FROM activations a JOIN licenses l ON l.id=a.license_id
                 WHERE l.project_id=p.id)
        FROM projects p ORDER BY p.name""").fetchall()
    recent_rel = conn.execute("""
        SELECT name, version, channel, at, slug FROM (
          SELECT p.name, r.version, r.channel, r.created_at AS at, p.slug FROM releases r
          JOIN projects p ON p.id=r.project_id WHERE NOT r.yanked
          UNION ALL
          SELECT p.name, g.version, CASE WHEN g.prerelease THEN 'prerelease' ELSE 'stable' END,
                 coalesce(g.published_at, g.first_seen_at), p.slug FROM github_releases g
          JOIN projects p ON p.id=g.project_id
          WHERE g.removed_at IS NULL AND lower(g.repo)=lower(p.github_repo)
        ) x ORDER BY at DESC LIMIT %s""", (limit,)).fetchall()
    recent_act = conn.execute("""
        SELECT p.name, a.device_id, a.last_seen, l.assigned_to, p.slug FROM activations a
        JOIN licenses l ON l.id=a.license_id JOIN projects p ON p.id=l.project_id
        ORDER BY a.last_seen DESC LIMIT %s""", (limit,)).fetchall()
    projects = [dict(slug=r[0], name=r[1], is_public=r[2], releases=r[3], licenses=r[4],
                     devices=r[5]) for r in rows]
    totals = dict(projects=len(projects), key_count=sum(p["licenses"] for p in projects),
                  devices=sum(p["devices"] for p in projects),
                  releases=sum(p["releases"] for p in projects))
    return dict(projects=projects, totals=totals, recent_rel=recent_rel, recent_act=recent_act)


@app.get("/")
@admin_only
def dashboard():
    with db() as conn:
        data = _overview(conn, 5)
    return render_template("dashboard.html", nav="home", **data)


@app.get("/projects")
@admin_only
def projects_list():
    with db() as conn:
        data = _overview(conn, 1)
    return render_template("projects.html", nav="projects", **data)


@app.get("/activity")
@admin_only
def activity():
    with db() as conn:
        data = _overview(conn, 300)
    return render_template("activity.html", nav="activity", **data)


@app.post("/projects")
@admin_only
def project_create():
    csrf()
    slug = request.form.get("slug", "").strip().lower()
    name = request.form.get("name", "").strip()
    if not SLUG_RE.match(slug) or not name or len(name) > 80:
        flash("Slug must be 2-49 characters: lowercase letters, numbers, dashes. Name is required.")
        return redirect(url_for("projects_list"))
    try:
        with db() as conn:
            conn.execute("INSERT INTO projects (slug, name) VALUES (%s,%s)", (slug, name))
    except psycopg.errors.UniqueViolation:
        flash("That slug already exists.")
        return redirect(url_for("projects_list"))
    return redirect(url_for("project_page", slug=slug))


@app.get("/projects/<slug>")
@admin_only
def project_page(slug):
    with db() as conn:
        p = get_project(conn, slug)
        rels = releases_for(conn, p["id"], include_yanked=True)
        lic_rows = conn.execute("""
            SELECT id, key_ciphertext, duration, max_devices, activated_at, expires_at, revoked_at,
                   assigned_to, created_by
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
                             assigned_to=r[7], created_by=r[8], status=status, left=left,
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
    gh = []
    with db() as conn:
        for g in conn.execute("""SELECT tag, name, version, body, prerelease, published_at,
                                        html_url, assets, removed_at
                                 FROM github_releases WHERE project_id=%s
                                 AND lower(repo)=lower(%s)""", (p["id"], p["github_repo"])):
            gh.append(dict(tag=g[0], name=g[1], version=g[2], body=g[3], prerelease=g[4],
                           published_at=g[5], html_url=g[6], assets=g[7] or [],
                           removed_at=g[8]))
    gh.sort(key=lambda g: (vkey(g["version"]), g["published_at"] or now), reverse=True)
    live = [g for g in gh if not g["removed_at"]]
    gh_latest = next((g for g in live if not g["prerelease"]), None)
    gh_pre = next((g for g in live if g["prerelease"]), None)
    if gh_pre and gh_latest and vkey(gh_pre["version"]) <= vkey(gh_latest["version"]):
        gh_pre = None  # only show a prerelease that is newer than the latest stable
    portal_versions = {r["version"] for r in releases}
    with db() as conn:
        gh_connected = bool(github_sync.env_token()) or bool(github_sync.load_app(conn, fernet))
        gh_draft = _draft_row(conn, p["id"]) if p["github_repo"] else None
    return render_template("project.html", p=p, releases=releases, licenses=licenses,
                           durations=DURATIONS, stats=stats, latest=latest, q=q,
                           status_filter=status_filter, gh=gh, gh_latest=gh_latest,
                           gh_pre=gh_pre, portal_versions=portal_versions,
                           gh_connected=gh_connected, gh_draft=gh_draft, nav="projects",
                           tab=request.args.get("tab") if request.args.get("tab") in
                           ("overview", "releases", "keys", "settings")
                           else ("keys" if (q or status_filter) else "overview"),
                           draft_ready=bool(gh_draft and gh_draft["checks"]
                                            and all(c[1] for c in gh_draft["checks"])))


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


# ---------------------------------------------------------------- team members (limited access)
def _key_rows(conn, project_id, q=""):
    now = datetime.now(timezone.utc)
    rows = conn.execute("""
        SELECT l.id, l.key_ciphertext, l.duration, l.max_devices, l.expires_at, l.revoked_at,
               l.assigned_to, l.created_by,
               (SELECT count(*) FROM activations a WHERE a.license_id=l.id)
        FROM licenses l WHERE l.project_id=%s ORDER BY l.id DESC""", (project_id,)).fetchall()
    out = []
    for r in rows:
        status = ("revoked" if r[5] else "unused" if r[4] is None
                  else "expired" if r[4] < now else "active")
        item = dict(id=r[0], key=show_key(r[1]), duration=r[2], max_devices=r[3], expires_at=r[4],
                    status=status, assigned_to=r[6], created_by=r[7], devices=r[8])
        if q and q not in (item["assigned_to"] or "").lower() and q not in (item["key"] or "").lower():
            continue
        out.append(item)
    return out


def _team_project(slug):
    with db() as conn:
        p = get_project(conn, slug)
    if p["id"] not in g.staff["project_ids"]:
        abort(404)
    return p


@app.get("/team")
@staff_only
def team_home():
    with db() as conn:
        rows = conn.execute("""SELECT p.slug, p.name,
               (SELECT count(*) FROM licenses l WHERE l.project_id=p.id AND l.revoked_at IS NULL)
               FROM projects p WHERE p.id = ANY(%s) ORDER BY p.name""",
                            (g.staff["project_ids"],)).fetchall()
    return render_template("team.html", staff=g.staff,
                           projects=[dict(slug=r[0], name=r[1], key_count=r[2]) for r in rows])


@app.get("/team/dashboard")
@staff_only
def team_dashboard():
    """Read-only overview for team members: every app and its releases, but license counts and
    device lists only for the apps assigned to this member."""
    mine = g.staff["project_ids"]
    with db() as conn:
        data = _overview(conn, 8)
        ids = {r[1]: r[0] for r in conn.execute("SELECT id, slug FROM projects")}
        dev_rows = conn.execute("""
            SELECT p.name, p.slug, l.assigned_to, a.device_id, a.last_seen
            FROM activations a JOIN licenses l ON l.id=a.license_id
            JOIN projects p ON p.id=l.project_id
            WHERE p.id = ANY(%s) ORDER BY a.last_seen DESC LIMIT 300""", (mine,)).fetchall()
    projects = [dict(slug=p["slug"], name=p["name"], releases=p["releases"],
                     mine=ids.get(p["slug"]) in mine,
                     licenses=p["licenses"] if ids.get(p["slug"]) in mine else None,
                     devices=p["devices"] if ids.get(p["slug"]) in mine else None)
                for p in data["projects"]]
    totals = dict(projects=len(projects), releases=sum(p["releases"] for p in projects),
                  mine=sum(1 for p in projects if p["mine"]),
                  devices=sum(p["devices"] or 0 for p in projects))
    return render_template("team_dashboard.html", staff=g.staff, projects=projects,
                           totals=totals, recent_rel=data["recent_rel"],
                           devices=[dict(app=r[0], slug=r[1], name=r[2], device=r[3][:14], seen=r[4])
                                    for r in dev_rows])


@app.get("/team/<slug>")
@staff_only
def team_project(slug):
    p = _team_project(slug)
    q = request.args.get("q", "").strip().lower()[:80]
    with db() as conn:
        keys = _key_rows(conn, p["id"], q)
    return render_template("team_project.html", staff=g.staff, p=p, keys=keys, q=q,
                           durations=DURATIONS)


@app.post("/team/<slug>/licenses")
@staff_only
def team_generate(slug):
    csrf()
    _team_project(slug)
    _generate_key(slug, g.staff["username"], g.staff["project_ids"])
    return redirect(url_for("team_project", slug=slug))


@app.post("/team/licenses/<int:license_id>/name")
@staff_only
def team_key_name(license_id):
    csrf()
    with db() as conn:
        row = conn.execute("""SELECT p.slug, p.id FROM licenses l JOIN projects p ON p.id=l.project_id
                              WHERE l.id=%s""", (license_id,)).fetchone()
        if not row or row[1] not in g.staff["project_ids"]:
            abort(404)
        conn.execute("UPDATE licenses SET assigned_to=%s WHERE id=%s",
                     (clean_label(request.form.get("assigned_to"), 80), license_id))
    flash("Name saved.")
    return redirect(url_for("team_project", slug=row[0]))


# ---------------------------------------------------------------- owner: manage team accounts
@app.get("/users")
@admin_only
def users_page():
    with db() as conn:
        projects = conn.execute("SELECT id, name FROM projects ORDER BY name").fetchall()
        users = conn.execute("""SELECT id, username, project_ids, active, created_at, last_login_at
                                FROM team_users ORDER BY username""").fetchall()
    names = {r[0]: r[1] for r in projects}
    return render_template("users.html", nav="projects", projects=projects, names=names,
                           users=[dict(id=u[0], username=u[1], project_ids=list(u[2] or []),
                                       active=u[3], created_at=u[4], last_login_at=u[5])
                                  for u in users])


def _picked_projects(conn):
    valid = {r[0] for r in conn.execute("SELECT id FROM projects")}
    picked = []
    for v in request.form.getlist("project_ids"):
        if v.isdigit() and int(v) in valid:
            picked.append(int(v))
    return sorted(set(picked))


@app.post("/users")
@admin_only
def users_create():
    csrf()
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    if not USERNAME_RE.match(username):
        flash("Username: 3-40 characters, lowercase letters, numbers, dot, dash or underscore.")
        return redirect(url_for("users_page"))
    if len(password) < 10:
        flash("Password must be at least 10 characters.")
        return redirect(url_for("users_page"))
    with db() as conn:
        ids = _picked_projects(conn)
        if not ids:
            flash("Pick at least one project.")
            return redirect(url_for("users_page"))
        try:
            conn.execute("""INSERT INTO team_users (username, password_hash, project_ids)
                            VALUES (%s,%s,%s)""", (username, generate_password_hash(password), ids))
        except psycopg.errors.UniqueViolation:
            flash("That username already exists.")
            return redirect(url_for("users_page"))
    flash(f"Account {username} created. Share the username and password with them privately.")
    return redirect(url_for("users_page"))


@app.post("/users/<int:user_id>/projects")
@admin_only
def users_projects(user_id):
    csrf()
    with db() as conn:
        ids = _picked_projects(conn)
        conn.execute("UPDATE team_users SET project_ids=%s WHERE id=%s", (ids, user_id))
    flash("Access updated.")
    return redirect(url_for("users_page"))


@app.post("/users/<int:user_id>/active")
@admin_only
def users_active(user_id):
    csrf()
    active = request.form.get("active") == "1"
    with db() as conn:
        conn.execute("""UPDATE team_users SET active=%s, session_version=session_version+1
                        WHERE id=%s""", (active, user_id))
    flash("Account enabled." if active else "Account disabled. They are signed out now.")
    return redirect(url_for("users_page"))


@app.post("/users/<int:user_id>/password")
@admin_only
def users_password(user_id):
    csrf()
    password = request.form.get("password", "")
    if len(password) < 10:
        flash("Password must be at least 10 characters.")
        return redirect(url_for("users_page"))
    with db() as conn:
        conn.execute("""UPDATE team_users SET password_hash=%s, session_version=session_version+1
                        WHERE id=%s""", (generate_password_hash(password), user_id))
    flash("Password changed. They are signed out and must use the new password.")
    return redirect(url_for("users_page"))


@app.post("/projects/<slug>/github")
@admin_only
def project_github(slug):
    """Connect or disconnect a GitHub repository (admin only). Imported history is kept."""
    csrf()
    repo = request.form.get("github_repo", "").strip().removeprefix("https://github.com/")
    repo = repo.removesuffix(".git").strip("/")
    prefix = request.form.get("github_tag_prefix", "").strip()[:40]
    if repo and not github_sync.REPO_RE.match(repo):
        flash("Repository must look like owner/name, e.g. Gideonshaz/HY-Enhance-Studio.")
        return redirect(url_for("project_page", slug=slug) + "#github")
    with db() as conn:
        p = get_project(conn, slug)
        conn.execute("UPDATE projects SET github_repo=%s, github_tag_prefix=%s WHERE id=%s",
                     (repo, prefix, p["id"]))
        if repo:
            p.update(github_repo=repo, github_tag_prefix=prefix)
            ok, msg = github_sync.sync_project(conn, p, fernet)
    flash(("Connected and synced: " if ok else "Saved, but sync failed: ") + msg if repo
          else "GitHub repository disconnected. Imported history was kept.")
    return redirect(url_for("project_page", slug=slug) + "#github")


# ---------------------------------------------------------------- GitHub connection (one-time)
def _github_status(conn):
    """(app or None, repos list, error text). Never raises."""
    app_row = github_sync.load_app(conn, fernet)
    if not app_row:
        return None, [], ""
    try:
        return app_row, github_sync.installation_repos(github_sync.installation_token(app_row)), ""
    except github_sync.GitHubError as e:
        return app_row, [], str(e)


@app.get("/github")
@admin_only
def github_page():
    with db() as conn:
        app_row, repos, error = _github_status(conn)
    base = request.host_url.rstrip("/")
    host = request.host.split(".")[0][:24]
    manifest = {
        "name": f"GideonDev {host}"[:34],
        "url": base,
        "hook_attributes": {"url": base + url_for("github_webhook"), "active": True},
        "redirect_url": base + url_for("github_app_created"),
        "setup_url": base + url_for("github_installed"),
        "setup_on_update": True,
        "public": False,
        "default_permissions": {"contents": "write", "metadata": "read"},
        "default_events": ["release"],
    }
    session["gh_state"] = secrets.token_urlsafe(24)
    request.github_form = True
    return render_template("github.html", app_row=app_row, repos=repos, error=error,
                           env_token=bool(github_sync.env_token()),
                           manifest=json.dumps(manifest), state=session["gh_state"])


@app.get("/github/app-created")
def github_app_created():
    """GitHub redirects here after the app is created. The session cookie is SameSite=Strict,
    so it is not sent on this cross-site redirect: show a same-site 'Finish' link instead."""
    code = request.args.get("code", "")[:100]
    state = request.args.get("state", "")[:100]
    return render_template("github_continue.html", step="created",
                           href=url_for("github_app_created_finish", code=code, state=state))


@app.get("/github/app-created/finish")
@admin_only
def github_app_created_finish():
    state = request.args.get("state", "")
    if not session.get("gh_state") or not hmac.compare_digest(session["gh_state"], state):
        flash("That GitHub link expired. Please click Connect GitHub again.")
        return redirect(url_for("github_page"))
    session.pop("gh_state", None)
    try:
        data = github_sync.convert_manifest(request.args.get("code", ""))
    except github_sync.GitHubError as e:
        flash(f"Could not finish creating the GitHub app: {e}")
        return redirect(url_for("github_page"))
    with db() as conn:
        conn.execute("DELETE FROM github_app")
        conn.execute("""INSERT INTO github_app (id, app_id, slug, html_url, pem_enc, webhook_secret_enc)
                        VALUES (1, %s, %s, %s, %s, %s)""",
                     (int(data["id"]), data["slug"], data.get("html_url", ""),
                      fernet.encrypt(data["pem"].encode()).decode(),
                      fernet.encrypt((data.get("webhook_secret") or "").encode()).decode()))
    github_sync._cache.clear()
    return redirect(f"https://github.com/apps/{data['slug']}/installations/new")


@app.get("/github/installed")
def github_installed():
    iid = request.args.get("installation_id", "")
    return render_template("github_continue.html", step="installed",
                           href=url_for("github_installed_finish", installation_id=iid[:20]))


@app.get("/github/installed/finish")
@admin_only
def github_installed_finish():
    iid = request.args.get("installation_id", "")
    if not iid.isdigit():
        flash("GitHub did not send an installation id. Install the app again.")
        return redirect(url_for("github_page"))
    with db() as conn:
        app_row = github_sync.load_app(conn, fernet)
        if not app_row or app_row["broken"]:
            flash("No GitHub app found. Click Connect GitHub first.")
            return redirect(url_for("github_page"))
        try:
            iid = github_sync.check_installation(app_row, iid)  # must belong to our app
        except github_sync.GitHubError as e:
            flash(f"Could not confirm the installation: {e}")
            return redirect(url_for("github_page"))
        conn.execute("UPDATE github_app SET installation_id=%s WHERE id=1", (iid,))
    github_sync._cache.clear()
    flash("GitHub connected. Now open each project and pick its repository.")
    return redirect(url_for("github_page"))


@app.post("/github/disconnect")
@admin_only
def github_disconnect():
    csrf()
    with db() as conn:
        conn.execute("DELETE FROM github_app")
    github_sync._cache.clear()
    flash("Disconnected from the portal. Also delete the app on GitHub (Settings › Developer "
          "settings › GitHub Apps) if you no longer need it. Imported history was kept.")
    return redirect(url_for("github_page"))


# ---------------------------------------------------------------- Method B: publish via draft
def _draft_row(conn, project_id):
    r = conn.execute("""SELECT id, gh_id, tag, version, prerelease, package_id, checks, last_error,
                               created_at FROM github_drafts
                        WHERE project_id=%s AND status='draft' ORDER BY id DESC LIMIT 1""",
                     (project_id,)).fetchone()
    return None if not r else dict(id=r[0], gh_id=r[1], tag=r[2], version=r[3], prerelease=r[4],
                                   package_id=r[5], checks=r[6] or [], last_error=r[7],
                                   created_at=r[8])


@app.post("/projects/<slug>/github/draft")
@admin_only
def github_draft_create(slug):
    csrf()
    version = request.form.get("version", "").strip().lstrip("vV")
    notes = request.form.get("notes", "").strip()[:20000]
    prerelease = request.form.get("prerelease") == "on"
    back = redirect(url_for("project_page", slug=slug) + "#newrelease")
    if not VERSION_RE.match(version):
        flash("Version must look like 1.0.6 (or 1.0.6-beta).")
        return back
    with db() as conn:
        p = get_project(conn, slug)
        if not p["github_repo"]:
            abort(400)
        if _draft_row(conn, p["id"]):
            flash("There is already a draft for this app. Publish or discard it first.")
            return back
        try:
            tok = github_sync.current_token(conn, fernet)
            existing = github_sync.all_releases_including_drafts(p["github_repo"], tok)
            tag = f"{p['github_tag_prefix']}v{version}"
            clash = next((r for r in existing if r.get("tag_name") == tag), None)
            if clash:
                flash(f"{tag} already exists on GitHub{' as a draft' if clash.get('draft') else ''}. "
                      "Nothing was created.")
                return back
            newest = max((vkey(github_sync.version_from_tag(r.get("tag_name", ""), p["github_tag_prefix"]))
                          for r in existing if not r.get("draft")), default=None)
            if newest and vkey(version) <= newest:
                flash(f"Version {version} is not newer than the latest release on GitHub. "
                      "Velopack only updates to higher versions.")
                return back
            pkg = github_sync.package_id([r for r in existing if not r.get("draft")])
            if not pkg:
                flash("Couldn't find the Velopack package name from earlier releases.")
                return back
            rel = github_sync.create_draft(p["github_repo"], tok, tag, f"{p['name']} v{version}",
                                           notes, prerelease)
        except github_sync.GitHubError as e:
            flash(f"Draft not created: {e}")
            return back
        conn.execute("""INSERT INTO github_drafts (project_id, gh_id, tag, version, prerelease,
                        package_id) VALUES (%s,%s,%s,%s,%s,%s)""",
                     (p["id"], int(rel["id"]), tag, version, prerelease, pkg))
    flash(f"Draft {tag} created on GitHub (hidden from the app updaters). Upload the files next.")
    return back


def _check_draft(conn, p, d):
    tok = github_sync.current_token(conn, fernet)
    rel = github_sync.get_release(p["github_repo"], d["gh_id"], tok)
    if not rel.get("draft"):
        return rel, None
    checks = github_sync.verify_draft(p["github_repo"], rel, d["package_id"], d["version"], tok)
    conn.execute("""UPDATE github_drafts SET checks=%s::jsonb, last_error='', updated_at=now()
                    WHERE id=%s""", (json.dumps(checks), d["id"]))
    return rel, checks


@app.post("/projects/<slug>/github/draft/check")
@admin_only
def github_draft_check(slug):
    csrf()
    with db() as conn:
        p = get_project(conn, slug)
        d = _draft_row(conn, p["id"])
        if not d:
            return redirect(url_for("project_page", slug=slug))
        try:
            rel, checks = _check_draft(conn, p, d)
            if checks is None:
                github_sync.sync_project(conn, p, fernet)
                flash(f"{d['tag']} was already published on GitHub; synced.")
            else:
                ok = all(c[1] for c in checks)
                flash("All files verified. Ready to publish." if ok else
                      "Some files are still missing or unfinished.")
        except github_sync.GitHubError as e:
            conn.execute("UPDATE github_drafts SET last_error=%s WHERE id=%s", (str(e), d["id"]))
            flash(f"Check failed: {e}")
    return redirect(url_for("project_page", slug=slug) + "#newrelease")


@app.post("/projects/<slug>/github/draft/publish")
@admin_only
def github_draft_publish(slug):
    csrf()
    with db() as conn:
        p = get_project(conn, slug)
        conn.execute("SELECT pg_advisory_xact_lock(727402, %s)", (p["id"],))  # no double publish
        d = _draft_row(conn, p["id"])
        if not d:
            flash("Nothing to publish.")
            return redirect(url_for("project_page", slug=slug))
        try:
            rel, checks = _check_draft(conn, p, d)   # always re-verify right before publishing
            if checks is not None:
                if not all(c[1] for c in checks):
                    flash("Not published: some required files are missing or don't match.")
                    return redirect(url_for("project_page", slug=slug) + "#newrelease")
                github_sync.publish_draft(p["github_repo"], d["gh_id"],
                                          github_sync.current_token(conn, fernet), d["prerelease"])
            conn.execute("UPDATE github_drafts SET status='published', updated_at=now() WHERE id=%s",
                         (d["id"],))
            github_sync.sync_project(conn, p, fernet)
        except github_sync.GitHubError as e:
            conn.execute("UPDATE github_drafts SET last_error=%s WHERE id=%s", (str(e), d["id"]))
            flash(f"Not published: {e} It is still a draft — you can safely try again.")
            return redirect(url_for("project_page", slug=slug) + "#newrelease")
    flash(f"Published {d['tag']}. Installed apps will see it at their next update check.")
    return redirect(url_for("project_page", slug=slug) + "#github")


@app.post("/projects/<slug>/github/draft/discard")
@admin_only
def github_draft_discard(slug):
    csrf()
    with db() as conn:
        p = get_project(conn, slug)
        d = _draft_row(conn, p["id"])
        if d:
            try:
                tok = github_sync.current_token(conn, fernet)
                rel = github_sync.get_release(p["github_repo"], d["gh_id"], tok)
                if not rel.get("draft"):
                    flash("It is already published on GitHub, so it was not deleted.")
                    conn.execute("UPDATE github_drafts SET status='published' WHERE id=%s", (d["id"],))
                    return redirect(url_for("project_page", slug=slug) + "#github")
                github_sync.delete_draft(p["github_repo"], d["gh_id"], tok)
            except github_sync.GitHubError as e:
                if "404" not in str(e):
                    flash(f"Could not discard: {e}")
                    return redirect(url_for("project_page", slug=slug) + "#newrelease")
            conn.execute("UPDATE github_drafts SET status='discarded', updated_at=now() WHERE id=%s",
                         (d["id"],))
            flash(f"Draft {d['tag']} discarded.")
    return redirect(url_for("project_page", slug=slug) + "#newrelease")


@app.post("/projects/<slug>/github/sync")
@admin_only
def project_github_sync(slug):
    csrf()
    with db() as conn:
        p = get_project(conn, slug)
        ok, msg = github_sync.sync_project(conn, p, fernet)
    flash(("Sync complete: " if ok else "Sync failed: ") + msg)
    return redirect(url_for("project_page", slug=slug) + "#github")


@app.post("/api/github/webhook")
def github_webhook():
    """GitHub release webhook. Verified with GITHUB_WEBHOOK_SECRET; re-syncs linked projects."""
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    if not secret:
        with db() as conn:
            app_row = github_sync.load_app(conn, fernet)
        secret = app_row["webhook_secret"] if app_row else ""
    if not secret:
        return jsonify(error="webhook disabled"), 503
    request.max_content_length = 5_000_000  # release payloads exceed the 16 KB site-wide limit
    body = request.get_data(cache=False)
    if len(body) > 5_000_000 or not github_sync.webhook_signature_ok(
            secret, body, request.headers.get("X-Hub-Signature-256", "")):
        return jsonify(error="bad signature"), 401
    event = request.headers.get("X-GitHub-Event", "")
    if event == "ping":
        return jsonify(ok=True)
    if event != "release":
        return jsonify(ok=True, ignored=event)
    try:
        repo = json.loads(body)["repository"]["full_name"]
    except (ValueError, KeyError, TypeError):
        return jsonify(error="bad payload"), 400
    synced = []
    with db() as conn:
        slugs = [r[0] for r in conn.execute(
            "SELECT slug FROM projects WHERE lower(github_repo)=lower(%s)", (repo,))]
        for slug in slugs:
            ok, _ = github_sync.sync_project(conn, get_project(conn, slug), fernet)
            synced.append(dict(project=slug, ok=ok))
    return jsonify(ok=True, synced=synced)


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


def _generate_key(slug, created_by, project_ids=None):
    """Create one license key. Returns the project dict. project_ids limits team members."""
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
        if project_ids is not None and p["id"] not in project_ids:
            abort(404)
        conn.execute("""INSERT INTO licenses (key_hash, key_ciphertext, product, months, duration,
                                              project_id, max_devices, assigned_to, created_by)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                     (hashlib.sha256(key.encode()).hexdigest(), fernet.encrypt(key.encode()).decode(),
                      p["name"], DURATIONS[duration], duration, p["id"], max_devices,
                      assigned_to, created_by))
    flash("Key generated.")
    return p


@app.post("/projects/<slug>/licenses")
@admin_only
def license_generate(slug):
    csrf()
    _generate_key(slug, "owner")
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


# Affiliate LIVE GMV Max scheduler: separate module, own tables and URLs.
from affiliate_scheduler import portal as affiliate_scheduler_portal  # noqa: E402
affiliate_scheduler_portal.init_app(app, db, fernet, csrf)


if __name__ == "__main__":
    app.run()
