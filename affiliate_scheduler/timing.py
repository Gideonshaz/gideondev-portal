"""Malaysia-time schedule maths. Pure functions, no I/O, so they are easy to test.

A schedule describes LIVE windows in Asia/Kuala_Lumpur (UTC+8, no DST). Each window
("occurrence") produces two operations:

  ENABLE   valid from (live_start - lead) until live_end
  DISABLE  valid from live_end until live_end + DISABLE_GRACE

Outside its validity an operation is "missed" and is never executed late, except
that DISABLE keeps a generous grace because turning a campaign off late is the
safe direction (it stops spend). A late ENABLE after the LIVE has ended would
spend money for nothing, so it is never run.

GitHub Actions cron is best effort (often 5-15 min late), so nothing here
promises exact-minute execution.
"""
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

MYT = ZoneInfo("Asia/Kuala_Lumpur")
DISABLE_GRACE = timedelta(hours=6)
LOOKBACK_DAYS = 2


@dataclass(frozen=True)
class Op:
    operation_id: str
    schedule_id: int
    occurrence: date
    operation: str          # ENABLE | DISABLE
    due_at: datetime        # UTC
    valid_until: datetime   # UTC
    window_start: datetime  # UTC, enable time
    window_end: datetime    # UTC, live end


def parse_hhmm(value):
    if isinstance(value, time):
        return value.replace(second=0, microsecond=0)
    h, m = str(value).split(":")[:2]
    return time(int(h), int(m))


def window(occ: date, live_start: time, live_end: time, lead_minutes: int):
    start = datetime.combine(occ, live_start, MYT)
    end = datetime.combine(occ, live_end, MYT)
    if end <= start:            # e.g. 22:00 -> 00:30 runs past midnight
        end += timedelta(days=1)
    enable = start - timedelta(minutes=lead_minutes)
    return enable.astimezone(timezone.utc), end.astimezone(timezone.utc)


def occurrence_dates(sched, now_utc):
    """Dates (MYT) whose window could be relevant around now."""
    today = now_utc.astimezone(MYT).date()
    if sched["schedule_type"] == "once":
        d = sched["live_date"]
        return [d] if today - timedelta(days=LOOKBACK_DAYS) <= d <= today + timedelta(days=1) else []
    days = set(sched["weekdays"] or [])
    out = []
    for i in range(-LOOKBACK_DAYS, 2):
        d = today + timedelta(days=i)
        if d.weekday() in days:
            out.append(d)
    return out


def operations(sched, now_utc):
    """All ENABLE/DISABLE ops for occurrences near now. Occurrences that had already
    ended before the schedule was created (or last edited) are ignored."""
    ops = []
    since = sched.get("effective_from")
    for occ in occurrence_dates(sched, now_utc):
        enable_at, end_at = window(occ, parse_hhmm(sched["live_start"]),
                                   parse_hhmm(sched["live_end"]), int(sched["lead_minutes"]))
        if since and end_at <= since:
            continue
        base = f"s{sched['id']}-{occ.isoformat()}"
        ops.append(Op(f"{base}-ENABLE", sched["id"], occ, "ENABLE", enable_at, end_at, enable_at, end_at))
        ops.append(Op(f"{base}-DISABLE", sched["id"], occ, "DISABLE", end_at,
                      end_at + DISABLE_GRACE, enable_at, end_at))
    return ops


def classify(op: Op, now_utc):
    if now_utc < op.due_at:
        return "pending"
    if now_utc >= op.valid_until:
        return "missed"
    return "due"


def window_open(op: Op, now_utc):
    return op.window_start <= now_utc < op.window_end
