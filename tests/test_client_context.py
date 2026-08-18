import json
from types import SimpleNamespace
from unittest.mock import patch

from wg_panel import client_context


class DummyResponse:
    def __init__(self, payload=None, content_length=None):
        self.payload = payload or {
            "success": True,
            "ip": "8.8.8.8",
            "country": "Netherlands",
            "country_code": "NL",
            "region": "North Holland",
            "city": "Amsterdam",
            "timezone": {"id": "Europe/Amsterdam"},
            "connection": {
                "isp": "Example ISP",
                "org": "Example Org",
                "asn": 64500,
                "domain": "example.test",
            },
        }
        encoded = json.dumps(self.payload).encode()
        self.headers = {"Content-Length": str(content_length if content_length is not None else len(encoded))}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit=-1):
        return json.dumps(self.payload).encode()


def request_for(address="8.8.8.8", headers=None):
    return SimpleNamespace(
        remote_addr=address,
        headers=headers or {},
        user_agent=SimpleNamespace(
            string="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0"
        ),
    )


def setup_function():
    client_context._geoip_cache.clear()
    client_context._endpoint_cache.update({"time": 0, "ips": []})


def test_private_ip_skips_geoip_lookup():
    with patch("urllib.request.urlopen") as urlopen:
        assert client_context.lookup_ip_geo("127.0.0.1") == {}
        urlopen.assert_not_called()


def test_raw_forwarding_headers_cannot_spoof_proxy_normalized_address():
    request = request_for(
        "10.0.0.4",
        {"X-Forwarded-For": "37.214.29.144", "X-Real-IP": "37.214.29.144"},
    )
    assert client_context.get_client_ip(request) == "10.0.0.4"
    assert client_context.get_client_ip_chain(request) == ["10.0.0.4"]


def test_geoip_uses_https_and_validates_returned_ip():
    with patch("urllib.request.urlopen", return_value=DummyResponse()) as urlopen:
        data = client_context.lookup_ip_geo("8.8.8.8")
    assert urlopen.call_args.args[0].startswith("https://")
    assert data["country"] == "Netherlands"
    assert data["query"] == "8.8.8.8"

    client_context._geoip_cache.clear()
    mismatched = DummyResponse({"success": True, "ip": "1.1.1.1"})
    with patch("urllib.request.urlopen", return_value=mismatched):
        assert client_context.lookup_ip_geo("8.8.8.8") == {}


def test_geoip_rejects_oversize_response():
    response = DummyResponse(content_length=client_context.GEOIP_MAX_RESPONSE_BYTES + 1)
    with patch("urllib.request.urlopen", return_value=response):
        assert client_context.lookup_ip_geo("8.8.8.8") == {}


def test_registration_notification_contains_enriched_context():
    with patch("urllib.request.urlopen", return_value=DummyResponse()):
        message = client_context.build_registration_notification(
            "pocoyo52", "2026-07-09 15:41 UTC", request_for()
        )
    assert "IP: `8.8.8.8`" in message
    assert "Location: `Netherlands, NL, North Holland, Amsterdam`" in message
    assert "Network: `Example ISP, Example Org`" in message
    assert "ASN: `AS64500, example.test`" in message
    assert "Browser:" in message


def test_geoip_failure_does_not_block_notification():
    with patch("urllib.request.urlopen", side_effect=TimeoutError):
        message = client_context.build_registration_notification(
            "pocoyo52", "2026-07-09 15:41 UTC", request_for()
        )
    assert "Location:" in message


def test_private_ip_notification_uses_vpn_endpoint_fallback():
    def geo(address):
        if address == "8.8.8.8":
            return {
                "status": "success",
                "country": "United States",
                "countryCode": "US",
                "regionName": "California",
                "city": "Mountain View",
                "isp": "Google LLC",
                "org": "Google Public DNS",
                "as": "AS15169",
                "asname": "google.com",
            }
        return {}

    with patch.dict("os.environ", {"WG_PANEL_PUBLIC_IP": "8.8.8.8"}), patch(
        "wg_panel.client_context.lookup_ip_geo", side_effect=geo
    ):
        message = client_context.build_registration_notification(
            "pocoyo52", "2026-07-09 15:41 UTC", request_for("10.0.0.4")
        )
    assert "IP: `10.0.0.4`" in message
    assert "Location: `private VPN/local IP`" in message
    assert "VPN Endpoint: `8.8.8.8`" in message
    assert "VPN Location: `United States, US, California, Mountain View`" in message
