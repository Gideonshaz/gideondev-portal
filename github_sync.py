"""Read-only GitHub release sync for the admin side of the portal.

GitHub is the source of truth for GitHub-managed releases. Imported releases live in their
own table (github_releases) so the public update API, the public pages and the licensing code
never read them. Nothing here writes to GitHub.
"""
import hashlib
import hmac
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = "https://api.github.com"
REPO_RE = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")


class GitHubError(Exception):
    """A failure the admin should see, worded for a human."""


def token():
    return os.environ.get("GITHUB_TOKEN", "").strip()


def _get(url):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "gideondev-portal",
        "Authorization": "Bearer " + token(),
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode()), resp.headers.get("Link", "")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise GitHubError("GitHub rejected the token (401). It may be expired or wrong.")
        if e.code == 404:
            raise GitHubError("Repository not found (404). Check the name, and that the token "
                              "has access to this repository.")
        if e.code in (403, 429):
            if e.headers.get("X-RateLimit-Remaining") == "0":
                raise GitHubError("GitHub rate limit reached. Try again later.")
            raise GitHubError(f"GitHub refused the request ({e.code}). The token may lack "
                              "Contents: Read permission for this repository.")
        raise GitHubError(f"GitHub error {e.code}.")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise GitHubError(f"Could not reach GitHub: {getattr(e, 'reason', e)}")
    except ValueError:
        raise GitHubError("GitHub sent a response the portal could not read.")


def fetch_releases(repo):
    """All published (non-draft) releases of owner/repo. Raises GitHubError."""
    if not token():
        raise GitHubError("GitHub is not connected yet: GITHUB_TOKEN is not set on the server.")
    out, url, pages = [], f"{API}/repos/{repo}/releases?per_page=100", 0
    while url and pages < 20:
        data, link = _get(url)
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


def sync_project(conn, project, fetch=None):
    """Sync one project. Records status on the project row. Never raises GitHubError."""
    now = datetime.now(timezone.utc)
    repo, prefix = project["github_repo"], project["github_tag_prefix"]
    try:
        if not repo:
            raise GitHubError("No repository connected.")
        releases = (fetch or fetch_releases)(repo)
        counts = apply_releases(conn, project["id"], repo, prefix, releases, now)
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
