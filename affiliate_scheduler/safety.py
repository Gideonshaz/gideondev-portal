"""Affiliate LIVE GMV Max safety gate. No campaign writes are performed here.

Fail closed: the client cannot add eligible IDs. Server-side approval is required.
This module is intentionally separate from the existing licensing endpoints.
"""
from dataclasses import dataclass

ADVERTISER_ID = "7657848009081946119"
PROTECTED_IDS = frozenset({
    "1869666392557778",  # ViVid HAIR Malaysia
    "1869665454413026",  # ViVid HAIR MY
    "1869665286717649",  # ViVid HAIR
})
APPROVED_AFFILIATES = {"1881634554090609": "tashafrh"}

@dataclass(frozen=True)
class Campaign:
    advertiser_id: str
    campaign_id: str
    name: str
    promotion_type: str

def authorize_campaign(campaign: Campaign, operation: str) -> None:
    """Raises ValueError unless exact server-approved campaign and type match."""
    if operation not in ("ENABLE", "DISABLE"):
        raise ValueError("Unsupported operation")
    if campaign.campaign_id in PROTECTED_IDS:
        raise ValueError("Protected ViVid campaign")
    if campaign.advertiser_id != ADVERTISER_ID:
        raise ValueError("Wrong advertiser")
    if campaign.promotion_type != "LIVE_GMV_MAX":
        raise ValueError("Not a LIVE GMV Max campaign")
    expected = APPROVED_AFFILIATES.get(campaign.campaign_id)
    if expected is None or campaign.name != expected:
        raise ValueError("Campaign is not explicitly approved")

def verify_live_campaign(fetch_campaign, campaign_id: str, operation: str) -> Campaign:
    """Fetch fresh authoritative campaign details before every write."""
    if campaign_id in PROTECTED_IDS or campaign_id not in APPROVED_AFFILIATES:
        raise ValueError("Campaign ID is blocked")
    campaign = fetch_campaign(ADVERTISER_ID, campaign_id)
    if not isinstance(campaign, Campaign):
        raise ValueError("Campaign lookup failed")
    authorize_campaign(campaign, operation)
    return campaign
