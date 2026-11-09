"""Read-only GitHub release sync for the admin side of the portal.

GitHub is the source of truth for GitHub-managed releases. Imported releases live in their
own table (github_releases) so the public update API, the public pages and the licensing code
never read them. Nothing here writes to GitHub.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

API = "https://api.github.com"
REPO_RE = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")


class GitHubError(Exception):
    """A failure the admin should see, worded for a human."""


def env_token():
    return os.environ.get("GITHUB_TOKEN", "").strip()


# ---------------------------------------------------------------- GitHub App credentials
# Created once through the manifest flow; the private key never expires and is stored
# encrypted (Fernet) in the database. Short-lived installation tokens are minted from it.
_cache = {}


def load_app(conn, fernet):
    row = conn.execute("""SELECT app_id, slug, html_url, pem_enc, webhook_secret_enc,
                                 installation_id FROM github_app WHERE id=1""").fetchone()
    if not row:
        return None
    try:
        pem = fernet.decrypt(row[3].encode()).decode()
        secret = fernet.decrypt(row[4].encode()).decode()
    except Exception:
        return dict(app_id=row[0], slug=row[1], html_url=row[2], pem=None,
                    webhook_secret="", installation_id=row[5], broken=True)
    return dict(app_id=row[0], slug=row[1], html_url=row[2], pem=pem, webhook_secret=secret,
                installation_id=row[5], broken=False)


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def app_jwt(app_id, pem):
    now = int(time.time())
    head = b64u(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = b64u(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}).encode())
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    sig = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64u(sig)}"


def installation_token(app):
    """Short-lived (1 h) token for the installation, cached until 5 min before expiry."""
    if app.get("broken") or not app.get("pem"):
        raise GitHubError("Stored GitHub connection can't be read (server key changed). "
                          "Reconnect GitHub.")
    if not app.get("installation_id"):
        raise GitHubError("GitHub app created but not installed on any repository yet. "
                          "Finish connecting GitHub.")
    key = (app["app_id"], app["installation_id"])
    hit = _cache.get(key)
    if hit and hit[1] > time.time() + 300:
        return hit[0]
    try:
        data, _ = _request("POST", f"{API}/app/installations/{app['installation_id']}/access_tokens",
                           app_jwt(app["app_id"], app["pem"]))
    except GitHubError as e:
        _cache.pop(key, None)
        raise GitHubError("GitHub connection is broken (the app may have been uninstalled or "
                          f"deleted): {e} Reconnect GitHub.")
    exp = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")).timestamp()
    _cache[key] = (data["token"], exp)
    return data["token"]


def current_token(conn, fernet):
    """The token used for syncing: GITHUB_TOKEN if set, otherwise the connected GitHub App."""
    if env_token():
        return env_token()
    app = load_app(conn, fernet)
    if not app:
        raise GitHubError("GitHub is not connected yet. Open GitHub connection and click "
                          "Connect GitHub.")
    return installation_token(app)


def _request(method, url, tok=None, payload=None):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "gideondev-portal"}
    if tok:
        headers["Authorization"] = "Bearer " + tok
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode()
            return (json.loads(raw) if raw else {}), resp.headers.get("Link", "")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise GitHubError("GitHub rejected the token (401). It may be expired or wrong.")
        if e.code == 404:
            raise GitHubError("Not found on GitHub (404). Check the repository name, and that "
                              "the GideonDev GitHub app is installed on it.")
        if e.code in (403, 429):
            if e.headers.get("X-RateLimit-Remaining") == "0":
                raise GitHubError("GitHub rate limit reached. Try again later.")
            detail = ""
            try:
                detail = json.loads(e.read().decode()).get("message", "")
            except Exception:
                pass
            if "not accessible by integration" in detail.lower():
                raise GitHubError("The GitHub app doesn't have write permission yet. Approve "
                                  "'Contents: Read and write' (see GitHub connection page).")
            raise GitHubError(f"GitHub refused the request ({e.code}). The connection may "
                              "lack access to this repository.")
        try:
            detail = json.loads(e.read().decode()).get("message", "")
        except Exception:
            detail = ""
        if e.code == 422:
            raise GitHubError(f"GitHub rejected it (422): {detail or 'invalid request'}.")
        raise GitHubError(f"GitHub error {e.code}{': ' + detail if detail else ''}.")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise GitHubError(f"Could not reach GitHub: {getattr(e, 'reason', e)}")
    except ValueError:
        raise GitHubError("GitHub sent a response the portal could not read.")


def _get(url, tok):
    return _request("GET", url, tok)


def installation_repos(tok):
    data, _ = _get(f"{API}/installation/repositories?per_page=100", tok)
    return sorted(r["full_name"] for r in data.get("repositories", []))


def convert_manifest(code):
    """Exchange the one-time manifest code for the new app's credentials."""
    if not re.match(r"^[A-Za-z0-9_-]{1,100}$", code or ""):
        raise GitHubError("Invalid code from GitHub.")
    data, _ = _request("POST", f"{API}/app-manifests/{code}/conversions")
    return data


def check_installation(app, installation_id):
    data, _ = _get(f"{API}/app/installations/{int(installation_id)}",
                   app_jwt(app["app_id"], app["pem"]))
    return int(data["id"])


def fetch_releases(repo, tok):
    """All published (non-draft) releases of owner/repo. Raises GitHubError."""
    out, url, pages = [], f"{API}/repos/{repo}/releases?per_page=100", 0
    while url and pages < 20:
        data, link = _get(url, tok)
        if not isinstance(data, list):
            raise GitHubError("GitHub sent an unexpected response.")
        out.extend(data)
        pages += 1
        m = re.search(r'<([^>]+)>;\s*rel="next"', link or "")
        url = m.group(1) if m else None
    return [r for r in out if not r.get("draft")]


def version_from_tag(tag, prefix=""):
    v = tag[len(prefix):] if prefix and tag.startswith(prefix) else tag
    m = re.match(r"^[vV]\.?(?=\d)", v)
    return v[m.end():] if m else v


def _ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def apply_releases(conn, project_id, repo, prefix, releases, now=None):
    """Upsert by GitHub release id; mark releases gone from GitHub as removed (never delete).
    Only call with a COMPLETE successful fetch. Returns counts."""
    now = now or datetime.now(timezone.utc)
    if prefix:
        releases = [r for r in releases if (r.get("tag_name") or "").startswith(prefix)]
    seen, added, updated = [], 0, 0
    for r in releases:
        gid = int(r["id"])
        seen.append(gid)
        tag = r.get("tag_name") or ""
        assets = [dict(name=a.get("name", ""), size=int(a.get("size") or 0))
                  for a in (r.get("assets") or [])]
        row = (tag, r.get("name") or "", version_from_tag(tag, prefix), r.get("body") or "",
               bool(r.get("prerelease")), _ts(r.get("published_at")),
               r.get("html_url") or "", json.dumps(assets))
        old = conn.execute("""SELECT tag, name, version, body, prerelease, published_at, html_url,
                                     assets::text, removed_at
                              FROM github_releases WHERE project_id=%s AND gh_id=%s""",
                           (project_id, gid)).fetchone()
        if old is None:
            conn.execute("""INSERT INTO github_releases
                (project_id, gh_id, repo, tag, name, version, body, prerelease, published_at,
                 html_url, assets, first_seen_at, last_synced_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)""",
                         (project_id, gid, repo) + row + (now, now))
            added += 1
        else:
            changed = (tuple(old[:7]) != row[:7] or json.loads(old[7]) != assets
                       or old[8] is not None)
            conn.execute("""UPDATE github_releases SET repo=%s, tag=%s, name=%s, version=%s, body=%s,
                            prerelease=%s, published_at=%s, html_url=%s, assets=%s::jsonb,
                            removed_at=NULL, last_synced_at=%s
                            WHERE project_id=%s AND gh_id=%s""",
                         (repo,) + row + (now, project_id, gid))
            updated += int(changed)
    removed = conn.execute("""UPDATE github_releases SET removed_at=%s
                              WHERE project_id=%s AND removed_at IS NULL
                              AND NOT (gh_id = ANY(%s))""", (now, project_id, seen)).rowcount
    return dict(total=len(seen), added=added, updated=updated, removed=removed)


def sync_project(conn, project, fernet=None, fetch=None):
    """Sync one project. Records status on the project row. Never raises GitHubError."""
    now = datetime.now(timezone.utc)
    repo, prefix = project["github_repo"], project["github_tag_prefix"]
    try:
        if not repo:
            raise GitHubError("No repository connected.")
        releases = fetch(repo) if fetch else fetch_releases(repo, current_token(conn, fernet))
        counts = apply_releases(conn, project["id"], repo, prefix, releases, now)
        published = [int(r["id"]) for r in releases if not r.get("draft")]
        conn.execute("""UPDATE github_drafts SET status='published', updated_at=%s
                        WHERE project_id=%s AND status='draft' AND gh_id = ANY(%s)""",
                     (now, project["id"], published))
        msg = (f"{counts['total']} releases · {counts['added']} new · {counts['updated']} "
               f"changed · {counts['removed']} removed on GitHub")
        conn.execute("""UPDATE projects SET gh_last_sync_at=%s, gh_sync_ok=true, gh_sync_message=%s
                        WHERE id=%s""", (now, msg, project["id"]))
        return True, msg
    except GitHubError as e:
        conn.execute("""UPDATE projects SET gh_last_sync_at=%s, gh_sync_ok=false, gh_sync_message=%s
                        WHERE id=%s""", (now, str(e), project["id"]))
        return False, str(e)


def webhook_signature_ok(secret, body, header):
    if not secret or not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


# ---------------------------------------------------------------- Method B: draft → verify → publish
class _NoAuthRedirect(urllib.request.HTTPRedirectHandler):
    """Asset downloads redirect to signed storage URLs that reject an Authorization header."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.headers.pop("Authorization", None)
            new.unredirected_hdrs.pop("Authorization", None)
        return new


def download_small_asset(repo, asset_id, tok, limit=200_000):
    req = urllib.request.Request(f"{API}/repos/{repo}/releases/assets/{int(asset_id)}", headers={
        "Accept": "application/octet-stream", "User-Agent": "gideondev-portal",
        "Authorization": "Bearer " + tok})
    try:
        with urllib.request.build_opener(_NoAuthRedirect).open(req, timeout=20) as resp:
            return resp.read(limit + 1)[:limit].decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise GitHubError(f"Could not download a release file to check it: {e}")


def all_releases_including_drafts(repo, tok):
    out, url, pages = [], f"{API}/repos/{repo}/releases?per_page=100", 0
    while url and pages < 20:
        data, link = _get(url, tok)
        out.extend(data)
        pages += 1
        m = re.search(r'<([^>]+)>;\s*rel="next"', link or "")
        url = m.group(1) if m else None
    return out


def package_id(releases):
    """Velopack package id learned from earlier releases' full nupkg names (newest first)."""
    for r in releases:
        for a in r.get("assets") or []:
            m = re.match(r"^(.+?)-\d[\w.+-]*-full\.nupkg$", a.get("name", ""))
            if m:
                return m.group(1)
    return None


def required_files(pkg, version):
    return ["releases.win.json", "RELEASES", "assets.win.json",
            f"{pkg}-{version}-full.nupkg", f"{pkg}-win-Setup.exe"]


def create_draft(repo, tok, tag, name, notes, prerelease):
    data, _ = _request("POST", f"{API}/repos/{repo}/releases", tok, {
        "tag_name": tag, "name": name, "body": notes, "draft": True, "prerelease": prerelease})
    return data


def get_release(repo, rid, tok):
    data, _ = _get(f"{API}/repos/{repo}/releases/{int(rid)}", tok)
    return data


def verify_draft(repo, release, pkg, version, tok, download=None):
    """Return a list of (file, ok, detail). All ok → safe to publish for the Velopack updater."""
    assets = {a["name"]: a for a in release.get("assets") or []}
    checks = []
    for name in required_files(pkg, version):
        a = assets.get(name)
        if not a:
            checks.append((name, False, "missing"))
        elif a.get("state") != "uploaded" or not a.get("size"):
            checks.append((name, False, "upload not finished"))
        else:
            checks.append((name, True, f"{a['size']:,} bytes"))
    feed = assets.get("releases.win.json")
    if feed and feed.get("state") == "uploaded":
        text = (download or download_small_asset)(repo, feed["id"], tok)
        nupkg = f"{pkg}-{version}-full.nupkg"
        try:
            entries = json.loads(text).get("Assets", [])
            pkg_size = (assets.get(nupkg) or {}).get("size")
            ok = any(e.get("Version") == version and e.get("FileName") == nupkg
                     and e.get("Size") == pkg_size for e in entries)
        except (ValueError, AttributeError):
            ok = False
        checks.append(("feed lists this version", ok,
                       "releases.win.json lists " + nupkg if ok else
                       f"releases.win.json does not match {nupkg} (wrong version or unfinished upload)"))
    return checks


def publish_draft(repo, rid, tok, prerelease):
    data, _ = _request("PATCH", f"{API}/repos/{repo}/releases/{int(rid)}", tok, {
        "draft": False, "prerelease": prerelease, "make_latest": "false" if prerelease else "true"})
    return data


def delete_draft(repo, rid, tok):
    _request("DELETE", f"{API}/repos/{repo}/releases/{int(rid)}", tok)
