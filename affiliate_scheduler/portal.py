"""Portal side of the Affiliate LIVE GMV Max scheduler (Flask blueprint).

Separate from licensing/releases: own tables (sched_*), own URL prefixes
(/scheduler, /api/scheduler/...), own auth (device tokens for the Android app, one
shared runner token for GitHub Actions). The portal never calls the TikTok MCP server:
it only runs the OAuth hand-off and stores/refreshes tokens. All MCP calls, including the
read-only verification, happen in GitHub Actions.
"""
import hashlib
import json
import hmac
import os
import secrets
from datetime import date, datetime, timedelta, timezone

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

from affiliate_scheduler import mcp_client, timing
from affiliate_scheduler.safety import ADVERTISER_ID, APPROVED_AFFILIATES, PROTECTED_IDS

bp = Blueprint("scheduler", __name__)
MAX_ATTEMPTS = 3
STALE_CLAIM = timedelta(minutes=10)
AUTH_LIFETIME = timedelta(days=30)
TERMINAL = ("succeeded", "dry_run", "rejected", "missed", "skipped_overlap")
_deps = {}


def init_app(app, db, fernet, csrf):
    _deps.update(db=db, fernet=fernet, csrf=csrf)
    app.register_blueprint(bp)


def db():
    return _deps["db"]()


def enc(text):
    return _deps["fernet"].encrypt(text.encode()).decode() if text else ""


def dec(text):
    return _deps["fernet"].decrypt(text.encode()).decode() if text else ""


def now_utc():
    return datetime.now(timezone.utc)


def mcp_url():
    return os.environ.get("TIKTOK_MCP_URL", mcp_client.DEFAULT_MCP_URL)


def err(code, message, status):
    return jsonify(error=code, message=message), status


# ------------------------------------------------------------------ auth helpers
def _admin(fn):
    from functools import wraps
    from flask import session

    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapped


def _bearer():
    h = request.headers.get("Authorization", "")
    return h[7:].strip() if h.startswith("Bearer ") else ""


def device_api(fn):
    from functools import wraps

    @wraps(fn)
    def wrapped(*a, **kw):
        tok = _bearer()
        if len(tok) < 20:
            return err("UNAUTHORIZED", "Missing or invalid device token", 401)
        digest = hashlib.sha256(tok.encode()).hexdigest()
        with db() as conn:
            row = conn.execute("""UPDATE sched_devices SET last_seen=now()
                                  WHERE token_hash=%s AND revoked_at IS NULL RETURNING id""",
                               (digest,)).fetchone()
        if not row:
            return err("UNAUTHORIZED", "Device token not recognised or revoked", 401)
        return fn(*a, **kw)
    return wrapped


def runner_api(fn):
    from functools import wraps

    @wraps(fn)
    def wrapped(*a, **kw):
        expected = os.environ.get("SCHEDULER_RUNNER_TOKEN", "")
        if len(expected) < 32:
            return err("NOT_CONFIGURED", "SCHEDULER_RUNNER_TOKEN is not set on the portal", 503)
        if not hmac.compare_digest(_bearer().encode(), expected.encode()):
            return err("UNAUTHORIZED", "Bad runner token", 401)
        return fn(*a, **kw)
    return wrapped


# ------------------------------------------------------------------ TikTok token store
class ReauthRequired(Exception):
    pass


def auth_row(conn, lock=False):
    return conn.execute("""SELECT mcp_url, client_id, client_secret_enc, token_endpoint, resource,
                                  access_token_enc, access_expires_at, refresh_token_enc,
                                  authorized_at, last_refresh_at, needs_reauth, last_error,
                                  verified_at, verify_result
                           FROM sched_tiktok_auth WHERE id=1""" + (" FOR UPDATE" if lock else "")
                        ).fetchone()


def _store_tokens(conn, tok, now):
    expires = now + timedelta(seconds=int(tok.get("expires_in") or 3600))
    conn.execute("""UPDATE sched_tiktok_auth SET access_token_enc=%s, access_expires_at=%s,
                       refresh_token_enc=COALESCE(NULLIF(%s,''), refresh_token_enc),
                       last_refresh_at=%s, needs_reauth=false, last_error='' WHERE id=1""",
                 (enc(tok["access_token"]), expires, enc(tok.get("refresh_token", "")), now))
    return expires


def get_access_token(http=None):
    """Valid access token, refreshing if needed. Raises ReauthRequired."""
    http = http or mcp_client._http
    failure = None
    with db() as conn:
        row = auth_row(conn, lock=True)  # serialises refreshes (refresh tokens may rotate)
        if not row:
            raise ReauthRequired("TikTok is not connected yet")
        (url, client_id, secret_enc, token_ep, resource, at_enc, at_exp, rt_enc,
         authorized_at, *_rest) = row
        needs_reauth = row[10]
        now = now_utc()
        if needs_reauth:
            raise ReauthRequired(row[11] or "TikTok authorization must be renewed")
        if at_exp and at_exp - now > timedelta(minutes=5):
            return dec(at_enc), url, at_exp
        if not rt_enc:
            failure = "Access token expired and TikTok gave no refresh token"
        else:
            try:
                tok = mcp_client.refresh(token_ep, client_id, dec(rt_enc), resource,
                                         dec(secret_enc) or None, http=http)
                expires = _store_tokens(conn, tok, now)
                return tok["access_token"], url, expires
            except mcp_client.AuthError as e:
                failure = f"Refresh rejected: {e}"
            except mcp_client.McpError as e:
                conn.execute("UPDATE sched_tiktok_auth SET last_error=%s WHERE id=1", (str(e)[:500],))
                raise
        conn.execute("UPDATE sched_tiktok_auth SET needs_reauth=true, last_error=%s WHERE id=1",
                     (failure,))
    raise ReauthRequired(failure)


def auth_summary(conn):
    row = auth_row(conn)
    if not row:
        return {"connected": False, "state": "NOT_CONNECTED"}
    authorized_at = row[8]
    expires = authorized_at + AUTH_LIFETIME
    state = "NEEDS_REAUTH" if row[10] else ("EXPIRING_SOON" if expires - now_utc() < timedelta(days=5)
                                            else "CONNECTED")
    return {"connected": not row[10], "state": state, "authorized_at": iso(authorized_at),
            "reauthorize_by": iso(expires), "last_error": row[11],
            "verified_at": iso(row[12]), "verify_result": row[13]}


# ------------------------------------------------------------------ serialisation
def iso(dt):
    if dt is None:
        return None
    return dt.astimezone(timing.MYT).isoformat(timespec="seconds")


SCHED_COLS = """id, advertiser_id, campaign_id, campaign_name, schedule_type, live_date, weekdays,
                live_start, live_end, lead_minutes, timezone, active, label, last_execution_at,
                last_result, effective_from, created_at, updated_at, deleted_at"""
SCHED_KEYS = [c.strip() for c in SCHED_COLS.replace("\n", "").split(",")]


def sched_dict(row):
    d = dict(zip(SCHED_KEYS, row))
    return d


def sched_json(d):
    return {
        "id": d["id"], "campaign_id": d["campaign_id"], "campaign_name": d["campaign_name"],
        "advertiser_id": d["advertiser_id"], "schedule_type": d["schedule_type"],
        "live_date": d["live_date"].isoformat() if d["live_date"] else None,
        "weekdays": list(d["weekdays"] or []),
        "live_start": d["live_start"].strftime("%H:%M"), "live_end": d["live_end"].strftime("%H:%M"),
        "lead_minutes": d["lead_minutes"], "timezone": d["timezone"], "active": d["active"],
        "label": d["label"], "last_execution_at": iso(d["last_execution_at"]),
        "last_result": d["last_result"], "created_at": iso(d["created_at"]),
        "updated_at": iso(d["updated_at"]), "next_operations": next_ops(d),
    }


def next_ops(d, now=None):
    now = now or now_utc()
    if not d["active"] or d["deleted_at"]:
        return []
    out = []
    for op in timing.operations(d, now):
        if timing.classify(op, now) != "missed":
            out.append({"operation": op.operation, "due_at": iso(op.due_at), "operation_id": op.operation_id})
    return out[:4]


def exec_json(r):
    keys = ["id", "operation_id", "schedule_id", "campaign_id", "operation", "due_at", "status",
            "mode", "attempts", "message", "run_id", "claimed_at", "finished_at"]
    d = dict(zip(keys, r))
    for k in ("due_at", "claimed_at", "finished_at"):
        d[k] = iso(d[k])
    return d


# ------------------------------------------------------------------ validation
def validate(payload, now=None):
    now = now or now_utc()
    if not isinstance(payload, dict):
        raise ValueError("Body must be a JSON object")
    cid = str(payload.get("campaign_id", ""))
    if cid in PROTECTED_IDS:
        raise ValueError("That campaign is protected and can never be scheduled")
    if cid not in APPROVED_AFFILIATES:
        raise ValueError("Campaign is not approved for scheduling")
    stype = payload.get("schedule_type")
    if stype not in ("once", "weekly"):
        raise ValueError("schedule_type must be 'once' or 'weekly'")
    try:
        start = timing.parse_hhmm(payload.get("live_start", ""))
        end = timing.parse_hhmm(payload.get("live_end", ""))
    except (ValueError, TypeError):
        raise ValueError("live_start and live_end must be HH:MM (Malaysia time)")
    if start == end:
        raise ValueError("LIVE start and end cannot be the same time")
    lead = payload.get("lead_minutes", 10)
    if not isinstance(lead, int) or isinstance(lead, bool) or not 0 <= lead <= 120:
        raise ValueError("lead_minutes must be a whole number from 0 to 120")
    live_date, weekdays = None, []
    if stype == "once":
        try:
            live_date = date.fromisoformat(str(payload.get("live_date", "")))
        except ValueError:
            raise ValueError("live_date must be YYYY-MM-DD")
        _, end_at = timing.window(live_date, start, end, lead)
        if end_at <= now:
            raise ValueError("That LIVE window has already ended (Malaysia time)")
    else:
        weekdays = payload.get("weekdays")
        if (not isinstance(weekdays, list) or not weekdays or
                not all(isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 6 for x in weekdays)):
            raise ValueError("weekdays must be a non-empty list of 0 (Mon) .. 6 (Sun)")
        weekdays = sorted(set(weekdays))
    label = str(payload.get("label", ""))[:80]
    active = payload.get("active", True)
    if not isinstance(active, bool):
        raise ValueError("active must be true or false")
    return {"campaign_id": cid, "campaign_name": APPROVED_AFFILIATES[cid],
            "advertiser_id": ADVERTISER_ID, "schedule_type": stype, "live_date": live_date,
            "weekdays": weekdays, "live_start": start, "live_end": end, "lead_minutes": lead,
            "label": label, "active": active}


# ------------------------------------------------------------------ Android API
@bp.get("/api/scheduler/v1/status")
@device_api
def api_status():
    with db() as conn:
        live = conn.execute("SELECT live_enabled FROM sched_settings WHERE id=1").fetchone()[0]
        last = conn.execute("""SELECT max(finished_at) FROM sched_executions""").fetchone()[0]
        auth = auth_summary(conn)
    return jsonify(server_time=iso(now_utc()), timezone="Asia/Kuala_Lumpur",
                   live_enabled=live, mode="LIVE" if live else "DRY_RUN",
                   tiktok=auth, last_runner_activity=iso(last))


@bp.post("/api/scheduler/v1/live")
@device_api
def api_live():
    """App switch for the portal's live mode. Turning LIVE on needs the typed confirmation;
    going back to dry run never does. The GitHub variable SCHEDULER_LIVE_ARMED stays the
    master switch: with it off, nothing is switched whatever this says."""
    b = request.get_json(silent=True) or {}
    want = b.get("live")
    if not isinstance(want, bool):
        return err("INVALID", "live must be true or false", 400)
    if want and b.get("confirm") != "ENABLE LIVE":
        return err("CONFIRM_REQUIRED", "Type ENABLE LIVE to arm real campaign changes", 400)
    with db() as conn:
        conn.execute("UPDATE sched_settings SET live_enabled=%s, updated_at=now() WHERE id=1", (want,))
    return jsonify(live_enabled=want, mode="LIVE" if want else "DRY_RUN")


@bp.get("/api/scheduler/v1/campaigns")
@device_api
def api_campaigns():
    return jsonify(campaigns=[{"campaign_id": cid, "campaign_name": name, "advertiser_id": ADVERTISER_ID,
                               "type": "LIVE_GMV_MAX"} for cid, name in APPROVED_AFFILIATES.items()])


@bp.get("/api/scheduler/v1/schedules")
@device_api
def api_schedules():
    with db() as conn:
        rows = conn.execute(f"SELECT {SCHED_COLS} FROM sched_schedules WHERE deleted_at IS NULL "
                            "ORDER BY active DESC, id DESC").fetchall()
    return jsonify(schedules=[sched_json(sched_dict(r)) for r in rows])


def _get_sched(conn, sid):
    row = conn.execute(f"SELECT {SCHED_COLS} FROM sched_schedules WHERE id=%s AND deleted_at IS NULL",
                       (sid,)).fetchone()
    return sched_dict(row) if row else None


@bp.post("/api/scheduler/v1/schedules")
@device_api
def api_create():
    try:
        v = validate(request.get_json(silent=True))
    except ValueError as e:
        return err("INVALID", str(e), 400)
    with db() as conn:
        sid = conn.execute("""INSERT INTO sched_schedules (advertiser_id, campaign_id, campaign_name,
                schedule_type, live_date, weekdays, live_start, live_end, lead_minutes, label, active)
                VALUES (%(advertiser_id)s, %(campaign_id)s, %(campaign_name)s, %(schedule_type)s,
                        %(live_date)s, %(weekdays)s, %(live_start)s, %(live_end)s, %(lead_minutes)s,
                        %(label)s, %(active)s) RETURNING id""", v).fetchone()[0]
        d = _get_sched(conn, sid)
    return jsonify(schedule=sched_json(d)), 201


@bp.put("/api/scheduler/v1/schedules/<int:sid>")
@device_api
def api_update(sid):
    try:
        v = validate(request.get_json(silent=True))
    except ValueError as e:
        return err("INVALID", str(e), 400)
    v["id"] = sid
    with db() as conn:
        row = conn.execute("""UPDATE sched_schedules SET schedule_type=%(schedule_type)s,
                live_date=%(live_date)s, weekdays=%(weekdays)s, live_start=%(live_start)s,
                live_end=%(live_end)s, lead_minutes=%(lead_minutes)s, label=%(label)s,
                active=%(active)s, effective_from=now(), updated_at=now()
                WHERE id=%(id)s AND deleted_at IS NULL RETURNING id""", v).fetchone()
        if not row:
            return err("NOT_FOUND", "Schedule not found", 404)
        d = _get_sched(conn, sid)
    return jsonify(schedule=sched_json(d))


@bp.post("/api/scheduler/v1/schedules/<int:sid>/active")
@device_api
def api_active(sid):
    body = request.get_json(silent=True) or {}
    if not isinstance(body.get("active"), bool):
        return err("INVALID", "active must be true or false", 400)
    with db() as conn:
        row = conn.execute("""UPDATE sched_schedules SET active=%s, updated_at=now(),
                              effective_from = CASE WHEN %s THEN now() ELSE effective_from END
                              WHERE id=%s AND deleted_at IS NULL RETURNING id""",
                           (body["active"], body["active"], sid)).fetchone()
        if not row:
            return err("NOT_FOUND", "Schedule not found", 404)
        d = _get_sched(conn, sid)
    return jsonify(schedule=sched_json(d))


@bp.delete("/api/scheduler/v1/schedules/<int:sid>")
@device_api
def api_delete(sid):
    with db() as conn:
        row = conn.execute("""UPDATE sched_schedules SET deleted_at=now(), active=false, updated_at=now()
                              WHERE id=%s AND deleted_at IS NULL RETURNING id""", (sid,)).fetchone()
    if not row:
        return err("NOT_FOUND", "Schedule not found", 404)
    return jsonify(deleted=sid)


@bp.get("/api/scheduler/v1/executions")
@device_api
def api_executions():
    limit = max(1, min(request.args.get("limit", 50, type=int), 200))
    sid = request.args.get("schedule_id", type=int)
    with db() as conn:
        sql = """SELECT id, operation_id, schedule_id, campaign_id, operation, due_at, status, mode,
                        attempts, message, run_id, claimed_at, finished_at FROM sched_executions"""
        rows = conn.execute(sql + (" WHERE schedule_id=%s" if sid else "") + " ORDER BY id DESC LIMIT %s",
                            ((sid, limit) if sid else (limit,))).fetchall()
    return jsonify(executions=[exec_json(r) for r in rows])


# ------------------------------------------------------------------ runner API
def _record_missed(conn, op, campaign_id):
    conn.execute("""INSERT INTO sched_executions (operation_id, schedule_id, campaign_id, operation,
                       due_at, status, message, finished_at)
                    VALUES (%s,%s,%s,%s,%s,'missed',%s, now()) ON CONFLICT (operation_id) DO NOTHING""",
                 (op.operation_id, op.schedule_id, campaign_id, op.operation, op.due_at,
                  "Runner did not reach this operation inside its window; not executed late"))


def claim_due(conn, now, run_id):
    conn.execute("SELECT pg_advisory_xact_lock(727402)")  # one claimer at a time
    rows = conn.execute(f"""SELECT {SCHED_COLS} FROM sched_schedules
                            WHERE (active AND deleted_at IS NULL)
                               OR updated_at > now() - interval '3 days'""").fetchall()
    scheds = [sched_dict(r) for r in rows]
    status_of = {r[0]: r[1:] for r in conn.execute(
        """SELECT operation_id, status, attempts, claimed_at FROM sched_executions
           WHERE created_at > now() - interval '4 days'""")}
    ops_all = []
    for s in scheds:
        live_sched = s["active"] and not s["deleted_at"]
        for op in timing.operations(s, now):
            if not live_sched:
                # Switched off or deleted: only finish a window that was actually opened.
                enable_id = op.operation_id.rsplit("-", 1)[0] + "-ENABLE"
                if op.operation != "DISABLE" or (status_of.get(enable_id) or ("",))[0] not in ("succeeded", "dry_run"):
                    continue
            ops_all.append((s, op, live_sched))
    claimed = []
    for s, op, live_sched in ops_all:
        state = timing.classify(op, now)
        existing = status_of.get(op.operation_id)
        if state == "pending":
            continue
        if state == "missed":
            if not existing:
                _record_missed(conn, op, s["campaign_id"])
            continue
        if op.operation == "DISABLE":
            overlap = any(o.operation == "ENABLE" and o.operation_id.rsplit("-", 1)[0] != op.operation_id.rsplit("-", 1)[0]
                          and ls and timing.window_open(o, now) for _s, o, ls in ops_all)
            if overlap and not existing:
                conn.execute("""INSERT INTO sched_executions (operation_id, schedule_id, campaign_id, operation,
                                   due_at, status, message, finished_at, run_id)
                                VALUES (%s,%s,%s,'DISABLE',%s,'skipped_overlap',%s, now(), %s)
                                ON CONFLICT (operation_id) DO NOTHING""",
                             (op.operation_id, op.schedule_id, s["campaign_id"], op.due_at,
                              "Another schedule's LIVE window is open; left campaign on", run_id))
                continue
        token = secrets.token_urlsafe(16)
        if not existing:
            row = conn.execute("""INSERT INTO sched_executions (operation_id, schedule_id, campaign_id,
                                     operation, due_at, status, attempts, claim_token, claimed_at, run_id)
                                  VALUES (%s,%s,%s,%s,%s,'claimed',1,%s,%s,%s)
                                  ON CONFLICT (operation_id) DO NOTHING RETURNING attempts""",
                               (op.operation_id, op.schedule_id, s["campaign_id"], op.operation,
                                op.due_at, token, now, run_id)).fetchone()
        else:
            status, attempts, claimed_at = existing
            retry = status == "failed" or (status == "claimed" and claimed_at and now - claimed_at > STALE_CLAIM)
            if status in TERMINAL or not retry or attempts >= MAX_ATTEMPTS:
                continue
            row = conn.execute("""UPDATE sched_executions SET status='claimed', attempts=attempts+1,
                                     claim_token=%s, claimed_at=%s, run_id=%s
                                  WHERE operation_id=%s AND status IN ('failed','claimed')
                                  RETURNING attempts""", (token, now, run_id, op.operation_id)).fetchone()
        if row:
            claimed.append({"operation_id": op.operation_id, "claim_token": token,
                            "schedule_id": op.schedule_id, "campaign_id": s["campaign_id"],
                            "advertiser_id": s["advertiser_id"], "campaign_name": s["campaign_name"],
                            "operation": op.operation, "due_at": op.due_at.isoformat(),
                            "attempt": row[0]})
    # ENABLE before DISABLE never matters for one campaign, but run oldest first.
    claimed.sort(key=lambda c: c["due_at"])
    return claimed


@bp.post("/api/scheduler/runner/claim")
@runner_api
def runner_claim():
    body = request.get_json(silent=True) or {}
    run_id = str(body.get("run_id", ""))[:80]
    with db() as conn:
        live = conn.execute("SELECT live_enabled FROM sched_settings WHERE id=1").fetchone()[0]
        ops = claim_due(conn, now_utc(), run_id)
    return jsonify(live_enabled=live, server_time=now_utc().isoformat(), operations=ops)


@bp.post("/api/scheduler/runner/report")
@runner_api
def runner_report():
    b = request.get_json(silent=True) or {}
    status = b.get("status")
    if status not in ("succeeded", "dry_run", "failed", "rejected"):
        return err("INVALID", "bad status", 400)
    message = str(b.get("message", ""))[:1000]
    mode = "LIVE" if b.get("mode") == "LIVE" else "DRY_RUN"
    with db() as conn:
        row = conn.execute("""UPDATE sched_executions SET status=%s, message=%s, mode=%s, finished_at=now()
                              WHERE operation_id=%s AND claim_token=%s AND status='claimed'
                              RETURNING schedule_id, operation""",
                           (status, message, mode, str(b.get("operation_id", "")),
                            str(b.get("claim_token", "")))).fetchone()
        if not row:
            return err("NOT_CLAIMED", "No matching claimed operation", 409)
        conn.execute("UPDATE sched_schedules SET last_execution_at=now(), last_result=%s WHERE id=%s",
                     (f"{row[1]} {status}: {message}"[:300], row[0]))
    return jsonify(ok=True)


STAT_KEYS = ("date", "campaign_status", "budget", "roas_bid", "cost", "gmv", "roi", "orders", "is_live")
LIVE_KEYS = ("room_id", "status", "started_at", "duration", "views", "cost", "gmv", "roi", "orders")


def _clean_stats(s):
    if not isinstance(s, dict):
        return None
    out = {k: s.get(k) for k in STAT_KEYS if k in s}
    live = s.get("live")
    out["live"] = {k: live.get(k) for k in LIVE_KEYS if k in live} if isinstance(live, dict) else None
    for k, v in list(out.items()):
        if isinstance(v, str):
            out[k] = v[:60]
    return out


@bp.post("/api/scheduler/runner/stats")
@runner_api
def runner_stats():
    """Latest read-only LIVE stats from the scheduler run (GitHub). Never changes a schedule."""
    b = request.get_json(silent=True) or {}
    cid = str(b.get("campaign_id", ""))
    if cid not in APPROVED_AFFILIATES:
        return err("INVALID", "Not an approved campaign", 400)
    stats = _clean_stats(b.get("stats"))
    error = str(b.get("error") or "")[:300]
    with db() as conn:
        if stats is not None:
            conn.execute("""INSERT INTO sched_live_stats (campaign_id, stats, error, fetched_at, ok_at)
                            VALUES (%s, %s, '', now(), now())
                            ON CONFLICT (campaign_id) DO UPDATE SET stats=EXCLUDED.stats, error='',
                              fetched_at=now(), ok_at=now()""", (cid, json.dumps(stats)))
        else:
            conn.execute("""INSERT INTO sched_live_stats (campaign_id, error, fetched_at) VALUES (%s, %s, now())
                            ON CONFLICT (campaign_id) DO UPDATE SET error=EXCLUDED.error, fetched_at=now()""",
                         (cid, error or "No stats"))
    return jsonify(ok=True)


@bp.get("/api/scheduler/v1/stats")
@device_api
def api_stats():
    """Latest LIVE stats for the app. Keeps the last good figures when a read fails."""
    with db() as conn:
        rows = conn.execute("SELECT campaign_id, stats, error, fetched_at, ok_at FROM sched_live_stats").fetchall()
    found = {r[0]: r for r in rows}
    out = []
    for cid, name in APPROVED_AFFILIATES.items():
        r = found.get(cid)
        stats = r[1] if r else None
        if isinstance(stats, str):
            stats = json.loads(stats)
        out.append({"campaign_id": cid, "campaign_name": name, "stats": stats,
                    "error": r[2] if r else "", "fetched_at": iso(r[3]) if r else None,
                    "updated_at": iso(r[4]) if r else None})
    return jsonify(server_time=iso(now_utc()), campaigns=out)


# ------------------------------------------------------------------ daily history
HIST_INT = ("orders", "live_minutes", "sessions")
HIST_OPT = ("live_views", "views_10s", "follows")


def _hist_row(r):
    """One validated day row from the runner, or None."""
    if not isinstance(r, dict):
        return None
    try:
        day = date.fromisoformat(str(r.get("day", ""))[:10])
        out = {"day": day, "cost": round(float(r.get("cost") or 0), 2), "gmv": round(float(r.get("gmv") or 0), 2)}
        for k in HIST_INT:
            out[k] = max(0, int(r.get(k) or 0))
        for k in HIST_OPT:
            out[k] = None if r.get(k) is None else max(0, int(r[k]))
    except (TypeError, ValueError):
        return None
    if not (0 <= out["cost"] < 10_000_000 and 0 <= out["gmv"] < 10_000_000):
        return None
    return out


@bp.post("/api/scheduler/runner/history-coverage")
@runner_api
def runner_history_coverage():
    """Earliest stored day per campaign, so the runner knows whether to fill in the past."""
    with db() as conn:
        rows = conn.execute("SELECT campaign_id, min(day) FROM sched_live_daily GROUP BY campaign_id").fetchall()
    found = {r[0]: r[1].isoformat() for r in rows}
    return jsonify(campaigns={cid: found.get(cid) for cid in APPROVED_AFFILIATES})


@bp.post("/api/scheduler/runner/history")
@runner_api
def runner_history():
    """Daily figures from the scheduler run (read-only TikTok data). Upserts by campaign + day."""
    b = request.get_json(silent=True) or {}
    cid = str(b.get("campaign_id", ""))
    if cid not in APPROVED_AFFILIATES:
        return err("INVALID", "Not an approved campaign", 400)
    raw = b.get("rows")
    if not isinstance(raw, list) or len(raw) > 400:
        return err("INVALID", "rows must be a list (max 400)", 400)
    rows = [x for x in (_hist_row(r) for r in raw) if x]
    with db() as conn:
        for r in rows:
            conn.execute("""INSERT INTO sched_live_daily (campaign_id, day, cost, gmv, orders, live_views, views_10s,
                                follows, live_minutes, sessions, updated_at)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, now())
                            ON CONFLICT (campaign_id, day) DO UPDATE SET cost=EXCLUDED.cost, gmv=EXCLUDED.gmv,
                              orders=EXCLUDED.orders,
                              live_views=COALESCE(EXCLUDED.live_views, sched_live_daily.live_views),
                              views_10s=COALESCE(EXCLUDED.views_10s, sched_live_daily.views_10s),
                              follows=COALESCE(EXCLUDED.follows, sched_live_daily.follows),
                              live_minutes=EXCLUDED.live_minutes, sessions=EXCLUDED.sessions, updated_at=now()""",
                         (cid, r["day"], r["cost"], r["gmv"], r["orders"], r["live_views"], r["views_10s"],
                          r["follows"], r["live_minutes"], r["sessions"]))
    return jsonify(ok=True, saved=len(rows), skipped=len(raw) - len(rows))


def _totals(days):
    t = {"cost": 0.0, "gmv": 0.0, "orders": 0, "live_views": 0, "views_10s": 0, "follows": 0,
         "live_minutes": 0, "sessions": 0, "days": len(days), "days_live": 0}
    for d in days:
        for k in ("cost", "gmv"):
            t[k] += d[k]
        for k in ("orders", "live_minutes", "sessions"):
            t[k] += d[k]
        for k in HIST_OPT:
            t[k] += d[k] or 0
        t["days_live"] += 1 if d["sessions"] or d["cost"] > 0 else 0
    t["cost"], t["gmv"] = round(t["cost"], 2), round(t["gmv"], 2)
    t["roi"] = round(t["gmv"] / t["cost"], 2) if t["cost"] else 0
    t["cost_per_order"] = round(t["cost"] / t["orders"], 2) if t["orders"] else 0
    t["view_10s_rate"] = round(100 * t["views_10s"] / t["live_views"], 1) if t["live_views"] else 0
    return t


@bp.get("/api/scheduler/v1/history")
@device_api
def api_history():
    """Daily figures for a date range (Malaysia days, inclusive). Default: last 7 days.
    ?from=YYYY-MM-DD&to=YYYY-MM-DD&campaign_id=... (campaign_id optional)."""
    today = now_utc().astimezone(timing.MYT).date()
    try:
        end = date.fromisoformat(request.args.get("to") or today.isoformat())
        start = date.fromisoformat(request.args.get("from") or (end - timedelta(days=6)).isoformat())
    except ValueError:
        return err("INVALID", "Dates must be YYYY-MM-DD", 400)
    if start > end or (end - start).days > 366:
        return err("INVALID", "Range must be 1 to 367 days", 400)
    want = request.args.get("campaign_id")
    if want and want not in APPROVED_AFFILIATES:
        return err("INVALID", "Not an approved campaign", 400)
    with db() as conn:
        rows = conn.execute("""SELECT campaign_id, day, cost, gmv, orders, live_views, views_10s, follows,
                                      live_minutes, sessions, updated_at FROM sched_live_daily
                               WHERE day BETWEEN %s AND %s ORDER BY day DESC""", (start, end)).fetchall()
        first = dict(conn.execute("SELECT campaign_id, min(day) FROM sched_live_daily GROUP BY campaign_id").fetchall())
    out = []
    for cid, name in APPROVED_AFFILIATES.items():
        if want and cid != want:
            continue
        days = []
        for r in rows:
            if r[0] != cid:
                continue
            cost, gmv, orders = float(r[2]), float(r[3]), r[4]
            days.append({"day": r[1].isoformat(), "cost": cost, "gmv": gmv, "orders": orders,
                         "roi": round(gmv / cost, 2) if cost else 0,
                         "cost_per_order": round(cost / orders, 2) if orders else 0,
                         "live_views": r[5], "views_10s": r[6], "follows": r[7],
                         "view_10s_rate": round(100 * r[6] / r[5], 1) if r[5] and r[6] is not None else None,
                         "live_minutes": r[8], "sessions": r[9], "updated_at": iso(r[10])})
        out.append({"campaign_id": cid, "campaign_name": name, "totals": _totals(days), "days": days,
                    "first_day": first[cid].isoformat() if first.get(cid) else None})
    return jsonify(server_time=iso(now_utc()), today=today.isoformat(), **{"from": start.isoformat()},
                   to=end.isoformat(), campaigns=out)


@bp.post("/api/scheduler/runner/tiktok-token")
@runner_api
def runner_token():
    try:
        token, url, expires = get_access_token()
    except ReauthRequired as e:
        return err("TIKTOK_REAUTH_REQUIRED", str(e), 503)
    except mcp_client.McpError as e:
        return err("TIKTOK_UNAVAILABLE", str(e), 502)
    return jsonify(access_token=token, mcp_url=url, expires_at=expires.isoformat())


@bp.post("/api/scheduler/runner/verify-result")
@runner_api
def runner_verify_result():
    """The manual 'verify' GitHub workflow reports its read-only check here. The portal itself
    never calls the TikTok MCP server."""
    b = request.get_json(silent=True) or {}
    result = str(b.get("result", ""))[:500]
    if not result:
        return err("INVALID", "result required", 400)
    with db() as conn:
        row = conn.execute("UPDATE sched_tiktok_auth SET verified_at=now(), verify_result=%s WHERE id=1 "
                           "RETURNING id", (result,)).fetchone()
    if not row:
        return err("NOT_CONNECTED", "TikTok is not connected", 409)
    return jsonify(ok=True)


# ------------------------------------------------------------------ admin pages
def _page(**extra):
    with db() as conn:
        auth = auth_summary(conn)
        live = conn.execute("SELECT live_enabled FROM sched_settings WHERE id=1").fetchone()[0]
        devices = conn.execute("""SELECT id, name, created_at, last_seen, revoked_at FROM sched_devices
                                  ORDER BY id DESC""").fetchall()
        scheds = [sched_json(sched_dict(r)) for r in conn.execute(
            f"SELECT {SCHED_COLS} FROM sched_schedules WHERE deleted_at IS NULL ORDER BY id DESC")]
        execs = [exec_json(r) for r in conn.execute(
            """SELECT id, operation_id, schedule_id, campaign_id, operation, due_at, status, mode,
                      attempts, message, run_id, claimed_at, finished_at
               FROM sched_executions ORDER BY id DESC LIMIT 30""")]
    runner_ready = len(os.environ.get("SCHEDULER_RUNNER_TOKEN", "")) >= 32
    return render_template("scheduler.html", auth=auth, live=live, devices=devices, scheds=scheds,
                           execs=execs, runner_ready=runner_ready, mcp_url=mcp_url(),
                           approved=APPROVED_AFFILIATES, advertiser=ADVERTISER_ID, **extra)


@bp.get("/scheduler")
@_admin
def page():
    return _page()


@bp.post("/scheduler/tiktok/connect")
@_admin
def tiktok_connect():
    _deps["csrf"]()
    redirect_uri = url_for("scheduler.tiktok_callback", _external=True, _scheme="https")
    try:
        meta = mcp_client.discover(mcp_url())
        reg = mcp_client.register_client(meta, redirect_uri)
    except mcp_client.McpError as e:
        flash(f"Could not start TikTok authorization: {e}")
        return redirect(url_for("scheduler.page"))
    verifier, challenge = mcp_client.pkce_pair()
    state = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute("DELETE FROM sched_oauth_pending WHERE created_at < now() - interval '15 minutes'")
        conn.execute("""INSERT INTO sched_oauth_pending (state, verifier_enc, client_id, client_secret_enc,
                           redirect_uri, token_endpoint, resource, mcp_url)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                     (state, enc(verifier), reg["client_id"], enc(reg.get("client_secret", "")),
                      redirect_uri, meta["token_endpoint"], meta["resource"], mcp_url()))
    url = mcp_client.authorize_url(meta, reg["client_id"], redirect_uri, state, challenge)
    return _page(authorize_url=url)


@bp.get("/scheduler/tiktok/callback")
def tiktok_callback():
    """TikTok redirects here. The session cookie is SameSite=Strict and is not sent on this
    cross-site redirect, so show a same-site Finish link (like the GitHub flow)."""
    code = request.args.get("code", "")[:2000]
    state = request.args.get("state", "")[:100]
    error = request.args.get("error", "")[:100]
    return render_template("scheduler_continue.html", error=error,
                           href=url_for("scheduler.tiktok_finish", code=code, state=state))


@bp.get("/scheduler/tiktok/finish")
@_admin
def tiktok_finish():
    state, code = request.args.get("state", ""), request.args.get("code", "")
    with db() as conn:
        p = conn.execute("""DELETE FROM sched_oauth_pending WHERE state=%s
                            AND created_at > now() - interval '15 minutes'
                            RETURNING verifier_enc, client_id, client_secret_enc, redirect_uri,
                                      token_endpoint, resource, mcp_url""", (state,)).fetchone()
    if not p or not code:
        flash("That TikTok link expired or was already used. Click Connect TikTok again.")
        return redirect(url_for("scheduler.page"))
    verifier, client_id, secret_enc, redirect_uri, token_ep, resource, url = p
    try:
        tok = mcp_client.exchange_code(token_ep, client_id, code, redirect_uri, dec(verifier),
                                       resource, dec(secret_enc) or None)
    except mcp_client.McpError as e:
        flash(f"TikTok did not complete authorization: {e}")
        return redirect(url_for("scheduler.page"))
    now = now_utc()
    with db() as conn:
        conn.execute("DELETE FROM sched_tiktok_auth")
        conn.execute("""INSERT INTO sched_tiktok_auth (id, mcp_url, client_id, client_secret_enc,
                           token_endpoint, resource, access_token_enc, authorized_at)
                        VALUES (1,%s,%s,%s,%s,%s,'',%s)""",
                     (url, client_id, secret_enc, token_ep, resource, now))
        _store_tokens(conn, tok, now)
    flash("TikTok authorized. Now run the Verify workflow in GitHub Actions to confirm read access.")
    return redirect(url_for("scheduler.page"))


@bp.post("/scheduler/live")
@_admin
def set_live():
    _deps["csrf"]()
    want = request.form.get("live") == "on"
    if want and request.form.get("confirm", "") != "ENABLE LIVE":
        flash("Type ENABLE LIVE to arm real campaign changes.")
        return redirect(url_for("scheduler.page"))
    with db() as conn:
        conn.execute("UPDATE sched_settings SET live_enabled=%s, updated_at=now() WHERE id=1", (want,))
    flash("Live campaign changes ARMED on the portal." if want else "Back to dry run.")
    return redirect(url_for("scheduler.page"))


@bp.post("/scheduler/devices")
@_admin
def device_create():
    _deps["csrf"]()
    name = (request.form.get("name") or "Android").strip()[:60]
    token = "gds_" + secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute("INSERT INTO sched_devices (name, token_hash) VALUES (%s,%s)",
                     (name, hashlib.sha256(token.encode()).hexdigest()))
    return _page(new_device_token=token, new_device_name=name)


@bp.post("/scheduler/devices/<int:did>/revoke")
@_admin
def device_revoke(did):
    _deps["csrf"]()
    with db() as conn:
        conn.execute("UPDATE sched_devices SET revoked_at=now() WHERE id=%s AND revoked_at IS NULL", (did,))
    return redirect(url_for("scheduler.page"))
