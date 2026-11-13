import unittest
from affiliate_scheduler.safety import (
    Campaign, authorize_campaign, verify_live_campaign, PROTECTED_IDS,
    ADVERTISER_ID,
)

class CampaignSafetyTests(unittest.TestCase):
    def test_approved_affiliate(self):
        authorize_campaign(Campaign(ADVERTISER_ID, "1881634554090609", "tashafrh", "LIVE_GMV_MAX"), "ENABLE")
        authorize_campaign(Campaign(ADVERTISER_ID, "1881634554090609", "tashafrh", "LIVE_GMV_MAX"), "DISABLE")

    def test_protected_never_allowed(self):
        for campaign_id in PROTECTED_IDS:
            for operation in ("ENABLE", "DISABLE"):
                with self.subTest(campaign_id=campaign_id, operation=operation):
                    with self.assertRaises(ValueError):
                        authorize_campaign(Campaign(ADVERTISER_ID, campaign_id, "tashafrh", "LIVE_GMV_MAX"), operation)

    def test_wrong_account_type_name_and_id(self):
        cases = [
            Campaign("other", "1881634554090609", "tashafrh", "LIVE_GMV_MAX"),
            Campaign(ADVERTISER_ID, "1881634554090609", "tashafrh", "PRODUCT_GMV_MAX"),
            Campaign(ADVERTISER_ID, "1881634554090609", "ViVid HAIR", "LIVE_GMV_MAX"),
            Campaign(ADVERTISER_ID, "123456", "tashafrh", "LIVE_GMV_MAX"),
        ]
        for campaign in cases:
            with self.subTest(campaign=campaign):
                with self.assertRaises(ValueError):
                    authorize_campaign(campaign, "DISABLE")

    def test_unknown_operation(self):
        with self.assertRaises(ValueError):
            authorize_campaign(Campaign(ADVERTISER_ID, "1881634554090609", "tashafrh", "LIVE_GMV_MAX"), "DELETE")

    def test_protected_never_fetched(self):
        for campaign_id in PROTECTED_IDS:
            with self.assertRaises(ValueError):
                verify_live_campaign(lambda *args: self.fail("Should not fetch protected campaign"), campaign_id, "DISABLE")

    def test_lookup_must_match(self):
        with self.assertRaises(ValueError):
            verify_live_campaign(lambda advertiser, campaign: Campaign(advertiser, campaign, "ViVid HAIR", "LIVE_GMV_MAX"), "1881634554090609", "DISABLE")

if __name__ == "__main__":
    unittest.main()
