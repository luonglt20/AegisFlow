import os
import unittest

import server


class ResolveTargetUrlTests(unittest.TestCase):
    def setUp(self):
        self.original_allowlist = os.environ.get("AEGIS_ALLOWED_DAST_TARGETS")
        if "AEGIS_ALLOWED_DAST_TARGETS" in os.environ:
            del os.environ["AEGIS_ALLOWED_DAST_TARGETS"]

    def tearDown(self):
        if self.original_allowlist is None:
            os.environ.pop("AEGIS_ALLOWED_DAST_TARGETS", None)
        else:
            os.environ["AEGIS_ALLOWED_DAST_TARGETS"] = self.original_allowlist

    def test_uses_inferred_demo_target_when_request_is_empty(self):
        self.assertEqual(
            server.resolve_target_url("./real-apps/juice-shop", ""),
            "http://juice-shop:3000",
        )

    def test_rejects_unapproved_target_url(self):
        with self.assertRaises(ValueError):
            server.resolve_target_url("./real-apps/juice-shop", "http://169.254.169.254")

    def test_accepts_explicitly_allowlisted_target_url(self):
        os.environ["AEGIS_ALLOWED_DAST_TARGETS"] = "https://demo.example.com"
        self.assertEqual(
            server.resolve_target_url("./workspace/custom-app", "https://demo.example.com"),
            "https://demo.example.com",
        )


if __name__ == "__main__":
    unittest.main()
