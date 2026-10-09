import unittest
from unittest.mock import patch

from recon.modules import subdomains

class TestSubdomain(unittest.TestCase):

    def test_valid_label(self):
        self.assertTrue(subdomains.is_valid_label("www"))
        self.assertTrue(subdomains.is_valid_label("dev-01"))

    def test_invalid_label(self):
        self.assertFalse(subdomains.is_valid_label("http://example.com"))
        self.assertFalse(subdomains.is_valid_label("admin/path"))

    def test_load_wordlist_removes_duplicates(self):
        from unittest.mock import mock_open

        fake_file = mock_open(
            read_data="www\napi\nwww\n"
        )

        with patch(
            "recon.modules.subdomains.Path.is_file",
            return_value=True,
        ), patch(
            "builtins.open",
            fake_file,
        ):
            names = subdomains.load_wordlist("test.txt")

        self.assertEqual(names, ["www", "api"])

    @patch("recon.modules.subdomains.resolve_subdomain")
    def test_scan_keeps_resolved_subdomains(self, mock_resolve):
        mock_resolve.side_effect = (
            lambda name: (
                {"A": ["192.0.2.10"], "AAAA": []}
                if name == "www.example.com"
                else {"A": [], "AAAA": []}
            )
        )

        results = subdomains.scan("example.com")

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0]["subdomain"],
            "www.example.com",
        )

if __name__ == "__main__":
    unittest.main()