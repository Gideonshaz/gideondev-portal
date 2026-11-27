"""Text of the daily 'LIVE Performance Report' Gideon sends his boss, built from the per-LIVE
figures the scheduler run collects (GMV Max dashboard numbers). One block per LIVE, in the
order they started, ready to copy into WhatsApp."""
from decimal import ROUND_HALF_UP, Decimal

from affiliate_scheduler import timing


def money(x):
    return str(Decimal(str(x)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def ratio(a, b):
    return money(Decimal(str(a)) / Decimal(str(b))) if b else "-"


def clock(dt):
    return dt.astimezone(timing.MYT).strftime("%I:%M %p").lstrip("0")


def duration(mins):
    h, m = divmod(int(mins), 60)
    if h and m:
        return f"{h}h {m}m"
    return f"{h}h" if h else f"{m}m"


def long_date(d):
    return f"{d.day} {d.strftime('%B %Y')}"


def block(name, s):
    from datetime import timedelta
    start = s["started_at"]
    end = "LIVE now" if s["ongoing"] else clock(start + timedelta(minutes=s["minutes"]))
    return "\n".join([
        "📊 ViVid Hair | LIVE Performance Report",
        "",
        f"Affiliate: @{name}",
        f"Date: {long_date(start.astimezone(timing.MYT).date())}",
        f"LIVE Time: {clock(start)} - {end}",
        f"LIVE Duration: {duration(s['minutes'])}" + (" (still live)" if s["ongoing"] else ""),
        "",
        "Performance",
        f"* GMV: RM {money(s['gmv'])}",
        f"* Orders: {s['orders']}",
        f"* Ads Spend: RM {money(s['cost'])}",
        f"* ROI: {ratio(s['gmv'], s['cost'])}",
        f"* AOV: RM {ratio(s['gmv'], s['orders'])}" if s["orders"] else "* AOV: -",
        "",
        "Source: GMV Max Dashboard",
    ])


def build(day, sessions):
    """sessions: [(campaign_name, {started_at: datetime, minutes, ongoing, cost, gmv, orders})]"""
    if not sessions:
        return f"No affiliate LIVE with GMV Max ads on {long_date(day)}."
    ordered = sorted(sessions, key=lambda x: x[1]["started_at"])
    return "\n\n".join(block(n, s) for n, s in ordered)
