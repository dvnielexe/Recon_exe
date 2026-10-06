import dns.resolver
from unittest.mock import patch
from recon.modules.dns import lookup_record, scan

def test_lookup_record():
    with patch("recon.modules.dns.dns.resolver.resolve") as mock_resolve:
        mock_resolve.return_value = ["1.2.3.4", "5.6.7.8"]

        results = lookup_record("example.com", "A")

        assert isinstance(results, list)

def test_lookup_record_nxdomain():
    with patch("recon.modules.dns.dns.resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN

        results = lookup_record("does-not-exist.example", "A")

        assert results == []


def test_lookup_record_no_answer():
    with patch("recon.modules.dns.dns.resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NoAnswer

        results = lookup_record("example.com", "AAAA")

        assert results == []


def test_lookup_record_timeout():
    with patch("recon.modules.dns.dns.resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.Timeout

        results = lookup_record("example.com", "A")

        assert results == []


def test_scan():
    with patch("recon.modules.dns.dns.resolver.resolve") as mock_resolve:
        mock_resolve.return_value = ["test-result"]

        results = scan("example.com")

        assert isinstance(results, dict)
        assert "A" in results
        assert "AAAA" in results
        assert "CNAME" in results
        assert "MX" in results
        assert "NS" in results
        assert "TXT" in results

        assert results["A"] == ["test-result"]