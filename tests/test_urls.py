import unittest
from unittest.mock import Mock, patch

from recon.modules.urls import normalize_url, identify_parameters, extract_endpoint, collect_urls, scan

class TestURLNormalization(unittest.TestCase):

    def test_lowercase_scheme_and_hostname(self):
        self.assertEqual(
            normalize_url("HTTPS://Example.COM/about"),
            "https://example.com/about",
        )

    def test_remove_default_https_port(self):
        self.assertEqual(
            normalize_url("https://example.com:443/login"),
            "https://example.com/login"
        )

    def test_preserves_non_default_port(self):
        self.assertEqual(
            normalize_url("http://example.com:8000/api"),
            "http://example.com:8000/api"
        )

    def test_preserves_query_parameters(self):
        self.assertEqual(
            normalize_url("https://example.com/search?q=test&page=2"),
            "https://example.com/search?q=test&page=2"
        )

    def test_removes_fragments(self):
        self.assertEqual(
            normalize_url("https://example.com/docs#intro"),
            "https://example.com/docs"
        )

    def test_rejects_relative_urls(self):
        with self.assertRaises(ValueError):
            normalize_url("/login")

class TestParameterIdentification(unittest.TestCase):
    def test_extracts_multiple_parameters(self):
        result = identify_parameters(
            "https://example.com/search?q=python&page=2"
        )
        self.assertEqual(result,{
            "q": ["python"],
            "page": ["2"],
        })

    def test_handles_repeated_parameters(self):
        result = identify_parameters(
            "https://example.com/search?tag=web&tag=api"
        )
        self.assertEqual(result, {
            "tag": ["web", "api"],
        })

    def test_handles_empty_values(self):
        result = identify_parameters(
            "https://example.com/search?q="
        )
        self.assertEqual(result, {
            "q": [""],
        })

    def test_handles_url_without_parameters(self):
        result = identify_parameters(
            "https://example.com/about"
        )
        self.assertEqual(result, {})


class TestEndpointExtraction(unittest.TestCase):
    def test_extracts_simple_endpoint(self):
        self.assertEqual(
            extract_endpoint("https://example.com/login"),
            "/login",
        )

    def test_ignores_query_parameters(self):
        self.assertEqual(
            extract_endpoint(
                "https://example.com/api/users?page=2"
            ),
            "/api/users",
        )

    def test_handles_root_endpoint(self):
        self.assertEqual(
            extract_endpoint("https://example.com"),
            "/",
        )

    def test_preserves_nested_path(self):
        self.assertEqual(
            extract_endpoint(
                "https://example.com/api/users/42"
            ),
            "/api/users/42",
        )

    def test_rejects_relative_url(self):
        with self.assertRaises(ValueError):
            extract_endpoint("/login")

class TestURLCollection(unittest.TestCase):
    @patch("recon.modules.urls.requests.get")
    def test_collects_same_origin_links(self, mock_get):
        response = Mock()
        response.headers = {"Content-Type": "text/html"}
        response.text = """
        <html>
            <a href="/login">Login</a>
            <a href="/about">About</a>
            <a href="https://other.example/page">External</a>
        </html>
        """
        mock_get.return_value = response

        result = collect_urls("https://example.com")

        self.assertEqual(result, [
            "https://example.com/about",
            "https://example.com/login",
        ])

    @patch("recon.modules.urls.requests.get")
    def test_resolves_relative_links(self, mock_get):
        response = Mock()
        response.headers = {"Content-Type": "text/html"}
        response.text = '<a href="contact">Contact</a>'
        mock_get.return_value = response

        result = collect_urls("https://example.com/about/")

        self.assertEqual(
            result,
            ["https://example.com/about/contact"],
        )

    @patch("recon.modules.urls.requests.get")
    def test_removes_duplicate_links(self, mock_get):
        response = Mock()
        response.headers = {"Content-Type": "text/html"}
        response.text = """
        <a href="/login">Login</a>
        <a href="/login">Sign in</a>
        """
        mock_get.return_value = response

        result = collect_urls("https://example.com")

        self.assertEqual(result, ["https://example.com/login"])

    @patch("recon.modules.urls.requests.get")
    def test_ignores_non_html_responses(self, mock_get):
        response = Mock()
        response.headers = {"Content-Type": "application/json"}
        response.text = '{"status": "ok"}'
        mock_get.return_value = response

        self.assertEqual(
            collect_urls("https://example.com/api"),
            [],
        )

    @patch("recon.modules.urls.requests.get")
    def test_respects_max_urls(self, mock_get):
        response = Mock()
        response.headers = {"Content-Type": "text/html"}
        response.text = """
        <a href="/one">One</a>
        <a href="/two">Two</a>
        <a href="/three">Three</a>
        """
        mock_get.return_value = response

        result = collect_urls("https://example.com", max_urls=2)

        self.assertEqual(len(result), 2)

    def test_rejects_zero_max_urls(self):
        with self.assertRaises(ValueError):
            collect_urls("https://example.com", max_urls=0)

class TestURLScan(unittest.TestCase):
    @patch("recon.modules.urls.collect_urls")
    def test_combines_url_information(self, mock_collect):
        mock_collect.return_value = [
            "https://example.com/login?next=home",
            "https://example.com/about",
        ]

        result = scan("example.com")

        self.assertEqual(
            result["start_url"],
            "https://example.com/",
        )
        self.assertEqual(result["urls_found"], 3)

        login = next(
            item for item in result["results"]
            if item["endpoint"] == "/login"
        )
        self.assertEqual(login["parameters"], {"next": ["home"]})

    @patch("recon.modules.urls.collect_urls")
    def test_includes_start_url_without_links(self, mock_collect):
        mock_collect.return_value = []

        result = scan("https://example.com")

        self.assertEqual(result["urls_found"], 1)
        self.assertEqual(
            result["results"][0]["url"],
            "https://example.com/",
        )


if __name__ == "__main__":
    unittest.main()