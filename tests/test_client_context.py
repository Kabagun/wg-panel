import json
import unittest
from unittest.mock import patch

from wg_panel import client_context


class DummyResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(
            {
                "status": "success",
                "country": "Netherlands",
                "countryCode": "NL",
                "regionName": "North Holland",
                "city": "Amsterdam",
                "timezone": "Europe/Amsterdam",
                "isp": "Example ISP",
                "org": "Example Org",
                "as": "AS64500 Example",
                "asname": "EXAMPLE",
                "mobile": False,
                "proxy": True,
                "hosting": False,
                "query": "8.8.8.8",
            }
        ).encode("utf-8")


class DummyRequest:
    remote_addr = "8.8.8.8"

    class user_agent:
        string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0"


class ClientContextTest(unittest.TestCase):
    def setUp(self):
        client_context._geoip_cache.clear()

    def test_private_ip_skips_geoip_lookup(self):
        with patch("urllib.request.urlopen") as urlopen:
            self.assertEqual(client_context.lookup_ip_geo("127.0.0.1"), {})
            urlopen.assert_not_called()

    def test_registration_notification_contains_enriched_ip_context(self):
        with patch("urllib.request.urlopen", return_value=DummyResponse()):
            message = client_context.build_registration_notification(
                "pocoyo52",
                "2026-07-09 15:41 UTC",
                DummyRequest(),
            )

        self.assertIn("IP: `8.8.8.8`", message)
        self.assertIn("Location: `Netherlands, NL, North Holland, Amsterdam`", message)
        self.assertIn("Network: `Example ISP, Example Org`", message)
        self.assertIn("ASN: `AS64500 Example, EXAMPLE`", message)
        self.assertIn("Flags: `mobile=no, proxy=yes, hosting=no`", message)
        self.assertIn("Browser:", message)

    def test_geoip_failure_does_not_raise(self):
        with patch("urllib.request.urlopen", side_effect=TimeoutError):
            message = client_context.build_registration_notification(
                "pocoyo52",
                "2026-07-09 15:41 UTC",
                DummyRequest(),
            )

        self.assertIn("Location: `unknown or private IP`", message)


if __name__ == "__main__":
    unittest.main()
