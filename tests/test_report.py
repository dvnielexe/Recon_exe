import json
import tempfile
import unittest

from pathlib import Path

from recon.core.report import generate_report

class TestReport(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)

        self.target = "example.com"

        self.write_json("dns.json", {
            "A": ["192.0.2.10", "192.0.2.11"],
            "AAAA": [],
            "CNAME": [],
            "MX": ["10 mail.example.com."],
            "NS": [],
            "TXT": [],
        })

        self.write_json("http.json", {
            "https": {
                "url": "https://example.com/",
                "status_code": 200,
                "server": "nginx",
                "content-type": "text/html",
                "redirect": None,
                "security_headers": {
                    "Strict-Transport-Security": "max-age=31536000"
                },
            }
        })

        self.write_json("subdomain.json", [
            {
                "subdomain": "www.example.com",
                "ips": {
                    "A": ["192.0.2.12"],
                    "AAAA": [],
                },
            }
        ])

        self.write_json("technologies.json", {
            "url": "https://example.com/",
            "technologies": [
                {
                    "category": "Web Server",
                    "name": "nginx",
                    "evidence": ["Server response header"],
                }
            ],
            "error": None,
        })

        self.write_json("urls.json", {
            "start_url": "https://example.com/",
            "urls_found": 2,
            "results": [
                {
                    "url": "https://example.com/",
                    "endpoint": "/",
                    "parameters": {},
                },
                {
                    "url": "https://example.com/search?q=test",
                    "endpoint": "/search",
                    "parameters": {"q": ["test"]},
                },
            ],
        })

        self.write_json("services.json", [
            {
                "host": "192.0.2.10",
                "port": 443,
                "protocol": "tcp",
                "state": "open",
                "service": "https",
                "version": "nginx",
            }
        ])

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_json(self, filename, data):
        path = self.output_dir / filename
        path.write_text(json.dumps(data), encoding="utf-8")

    def test_generates_report_file(self):
        report_path = generate_report(self.output_dir, self.target)

        self.assertEqual(report_path, self.output_dir / "report.md")
        self.assertTrue(report_path.is_file())

    def test_report_contains_target_and_sections(self):
        generate_report(self.output_dir, self.target)
        report = (self.output_dir / "report.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("example.com", report)
        self.assertIn("Scan Summary", report)
        self.assertIn("DNS", report)
        self.assertIn("HTTP", report)
        self.assertIn("Subdomains", report)
        self.assertIn("Services", report)
        self.assertIn("Technologies", report)
        self.assertIn("URLs", report)

    def test_report_summary_counts(self):
        generate_report(self.output_dir, self.target)
        report = (self.output_dir / "report.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("DNS records: 3", report)
        self.assertIn("Subdomains: 1", report)
        self.assertIn("Services: 1", report)
        self.assertIn("URLs/endpoints: 2", report)
        self.assertIn("Technologies: 1", report)

    def test_missing_optional_file_does_not_crash(self):
        (self.output_dir / "services.json").unlink()

        report_path = generate_report(self.output_dir, self.target)
        report = report_path.read_text(encoding="utf-8")

        self.assertIn("Services", report)
        self.assertIn("unavailable", report.lower())

    def test_empty_results_produce_valid_markdown(self):
        for filename, data in {
            "dns.json": {},
            "http.json": {},
            "subdomain.json": [],
            "services.json": [],
            "urls.json": {
                "start_url": "https://example.com/",
                "urls_found": 0,
                "results": [],
            },
            "technologies.json": {
                "url": "https://example.com/",
                "technologies": [],
                "error": None,
            },
        }.items():
            self.write_json(filename, data)

        report_path = generate_report(self.output_dir, self.target)
        report = report_path.read_text(encoding="utf-8")

        self.assertTrue(report.startswith("# Reconnaissance Report"))
        self.assertIn("DNS records: 0", report)
        self.assertIn("Subdomains: 0", report)
        self.assertIn("Services: 0", report)
        self.assertIn("URLs/endpoints: 0", report)
        self.assertIn("Technologies: 0", report)

    def test_scan_errors_are_reported(self):
        self.write_json("technologies.json", {
            "url": "https://example.com/",
            "technologies": [],
            "error": "Connection timed out",
        })

        generate_report(self.output_dir, self.target)
        report = (self.output_dir / "report.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("Errors and Incomplete Scans", report)
        self.assertIn("Connection timed out", report)

    def test_report_includes_interesting_assets_section(self):
        self.write_json("subdomain.json", [
            {
                "subdomain": "admin.example.com",
                "ips": {"A": ["192.0.2.10"], "AAAA": []},
            }
        ])

        report_path = generate_report(self.output_dir, "example.com")
        report = report_path.read_text(encoding="utf-8")

        self.assertIn("## Interesting Assets", report)
        self.assertIn("admin.example.com", report)


    def test_report_distinguishes_missing_optional_results(self):
    # Remove optional result files to simulate modules that were not run.
        for filename in ("services.json", "urls.json"):
            path = self.output_dir / filename
            if path.exists():
                path.unlink()

        report_path = generate_report(self.output_dir, "example.com")
        report = report_path.read_text(encoding="utf-8")

        self.assertIn("services.json", report)
        self.assertIn("urls.json", report)
        self.assertIn("skipped or not saved", report)


    def test_report_identifies_unknown_service_states(self):
        self.write_json("services.json", [
            {
                "host": "example.com",
                "port": 3306,
                "protocol": "tcp",
                "state": "unknown",
                "service": None,
                "version": "Unknown",
            }
        ])

        report_path = generate_report(self.output_dir, "example.com")
        report = report_path.read_text(encoding="utf-8")

        self.assertIn("unknown", report.lower())


if __name__ == "__main__":
    unittest.main()
