
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests

from recon.modules.technologies import identify, scan


def make_response(
    headers=None,
    cookies=None,
    html="",
    url="https://example.test/",
):
    """Build a response-like object without network access."""
    return SimpleNamespace(
        headers=headers or {},
        cookies=cookies or {},
        text=html,
        url=url,
    )


class TestTechnologyIdentification(unittest.TestCase):

    def test_detects_web_server_and_runtime(self):
        response = make_response(headers={
            "Server": "nginx/1.24.0",
            "X-Powered-By": "Express",
        })

        results = identify(response)

        detected = {
            (item["category"], item["name"])
            for item in results
        }

        self.assertIn(("Web Server", "nginx/1.24.0"), detected)
        self.assertIn(
            ("Framework / Runtime", "Express"),
            detected,
        )

    def test_detects_cookie_technology(self):
        response = make_response(cookies={
            "PHPSESSID": "test-session",
            "connect.sid": "another-session",
        })

        results = identify(response)
        names = {item["name"] for item in results}

        self.assertIn("PHP", names)
        self.assertIn("Express", names)

    def test_detects_html_signatures(self):
        response = make_response(html="""
            <html>
              <head>
                <script id="__NEXT_DATA__">{}</script>
              </head>
              <body>
                <div class="wp-content">Test</div>
              </body>
            </html>
        """)

        results = identify(response)
        names = {item["name"] for item in results}

        self.assertIn("Next.js", names)
        self.assertIn("WordPress", names)

    def test_detects_generator_metadata(self):
        response = make_response(html="""
            <html>
              <head>
                <meta name="generator" content="WordPress 6.8">
              </head>
            </html>
        """)

        results = identify(response)

        self.assertTrue(
            any(
                item["name"] == "WordPress 6.8"
                and "HTML generator metadata" in item["evidence"]
                for item in results
            )
        )

    def test_unknown_site_returns_no_findings(self):
        response = make_response(
            headers={"Content-Type": "text/html"},
            html="<html><body>Hello</body></html>",
        )

        self.assertEqual(identify(response), [])

    def test_header_matching_is_case_insensitive(self):
        response = make_response(headers={
            "sErVeR": "nginx",
            "X-pOwErEd-bY": "Express",
        })

        results = identify(response)
        names = {item["name"] for item in results}

        self.assertIn("nginx", names)
        self.assertIn("Express", names)

    def test_duplicate_findings_merge_evidence(self):
        response = make_response(
            headers={"Server": "cloudflare"},
            html='<html><body>Test</body></html>',
        )
        response.headers["CF-Ray"] = "test-ray-id"

        results = identify(response)

        cloudflare = [
            item for item in results
            if item["name"] == "Cloudflare"
        ]

        self.assertEqual(len(cloudflare), 1)
        self.assertEqual(len(cloudflare[0]["evidence"]), 1)

    @patch("recon.modules.technologies.requests.get")
    def test_scan_returns_findings(self, mock_get):
        response = Mock()
        response.url = "https://example.test/"
        response.headers = {"Server": "nginx"}
        response.cookies = {}
        response.text = "<html></html>"
        response.raise_for_status.return_value = None
        mock_get.return_value = response

        result = scan("https://example.test")

        self.assertEqual(result["url"], "https://example.test/")
        self.assertIsNone(result["error"])
        self.assertTrue(result["technologies"])
        mock_get.assert_called_once()

    @patch("recon.modules.technologies.requests.get")
    def test_scan_handles_network_failure(self, mock_get):
        mock_get.side_effect = requests.Timeout("request timed out")

        result = scan("https://example.test")

        self.assertEqual(result["technologies"], [])
        self.assertIsNotNone(result["error"])
        self.assertIn("timed out", result["error"])

    @patch("recon.modules.technologies.requests.get")
    def test_scan_handles_http_error(self, mock_get):
        response = Mock()
        response.url = "https://example.test/"
        response.raise_for_status.side_effect = requests.HTTPError(
            "404 Client Error"
        )
        mock_get.return_value = response

        result = scan("https://example.test")

        self.assertEqual(result["technologies"], [])
        self.assertIn("404", result["error"])


if __name__ == "__main__":
    unittest.main()
