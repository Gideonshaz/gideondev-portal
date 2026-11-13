"""GitHub Actions scheduler entrypoint.

DRY RUN ONLY until independent TikTok Ads OAuth and an authenticated
server-side schedule store are implemented and verified. Never execute
a campaign status update from this file in its current form.
"""
import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from affiliate_scheduler.safety import (
    ADVERTISER_ID, APPROVED_AFFILIATES, PROTECTED_IDS,
)

def main():
    now = datetime.now(timezone.utc).astimezone(ZoneInfo("Asia/Kuala_Lumpur"))
    print(json.dumps({
        "time_malaysia": now.isoformat(timespec="seconds"),
        "mode": "DRY_RUN",
        "automation_armed": False,
        "advertiser_id": ADVERTISER_ID,
        "approved_affiliate_count": len(APPROVED_AFFILIATES),
        "protected_campaign_count": len(PROTECTED_IDS),
        "status": "No schedule storage or TikTok Ads OAuth configured. No campaigns touched."
    }))

if __name__ == "__main__":
    main()
