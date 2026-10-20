"""Identify common technologies from HTTP response evidence."""

import re

import requests

USER_AGENT = "BountyRecon/1.0 (authorized security reconnaisance)"

REQUEST_TIMEOUT = 5

def _normalize_headers(headers):
    """Normalize header names and values for consistent matching"""
    return{
        str(name).lower(): str(value).strip()
        for name, value in headers.items()
    }

def _add_findings(findings, category, name, evidence):
    """Add a finding once retaining distinct evidence"""

    for finding in findings:
        if (
            finding["category"] == category
            and finding["name"].lower() == name.lower()
        ):
            if evidence not in finding["evidence"]:
                finding["evidence"].append(evidence)
            return

    findings.append({
        "category": category,
        "name": name,
        "evidence": [evidence],
    })


def _inspect_headers(headers, findings):
    "Identify technologies revealed by HTTP headers"

    server = headers.get("server", "")
    if server:
        # Keep the exposed verison if the server provides one
        _add_findings(
            findings,
            "Web Server",
            server,
            "Server response header",
        )

    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        _add_findings(
            findings, 
            "Framework / Runtime",
            powered_by,
            "X-Powered-by response header",
        )

    if "cf-ray" in headers or "cloudflare" in server.lower():
        _add_findings(
            findings,
            "CDN / Reverse proxy",
            "Cloudflare",
            "Cloudflare-related response header",
        )

    
    if "x-drupal-cache" in headers:
        _add_findings(
            findings,
            "CMS",
            "Drupal",
            "X-Drupal-Cache response header",
        )

def _inspect_cookies(cookies, findings):
    """Use recognizable cookie names as technology clues"""
    cookie_names = {
        str(name).lower() 
        for name in cookies.keys()
        }

    if "phpsessid" in cookie_names:
        _add_findings(
            findings, "Programming Technology", "PHP", "PHPSESSID Cookie"
        )

    
    if "asp.net_sessionid" in cookie_names:
        _add_findings(
            findings, "Framework / Runtime", "ASP.NET",
            "ASP.NET_SessionId cookie",
        )

    if "connect.sid" in cookie_names:
        _add_findings(
            findings, "Framework / Runtime", "Express",
            "connect.sid cookie",
        )

    if "laravel_session" in cookie_names:
        _add_findings(
            findings, "Framework", "Laravel",
            "laravel_session cookie",
        )

    
    if "django" in cookie_names or "sessionid" in cookie_names:
        _add_findings(
            findings, "Framework", "Django",
            "Django-associated session cookie name",
        )

def _inspect_html(html, findings):
    """Identify technologies from HTML metadata and signatures."""

    content = html.lower()

    # Match a common HTML generator metadata pattern.
    generator_pattern = re.compile(
        r'<meta\b[^>]*\bname\s*=\s*["\']generator["\']'
        r'[^>]*\bcontent\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )

    for match in generator_pattern.finditer(html):
        generator = match.group(1).strip()
        if generator:
            _add_findings(
                findings,
                "CMS / Generator",
                generator,
                "HTML generator metadata",
            )

    signatures = [
        (
            "CMS", "WordPress",
            ("wp-content/", "wp-includes/", 'class="wp-content"'),
            "WordPress HTML path signature",
        ),
        (
            "CMS", "Drupal",
            ("drupal.settings", "drupal.js"),
            "Drupal HTML signature",
        ),
        (
            "CMS", "Joomla",
            ("com_content", "/media/system/js/"),
            "Joomla HTML signature",
        ),
        (
            "JavaScript Framework", "Next.js",
            ("__next_data__", "/_next/static/"),
            "Next.js HTML signature",
        ),
        (
            "JavaScript Framework", "React",
            ("data-reactroot", "__react"),
            "React HTML signature",
        ),
        (
            "JavaScript Framework", "Vue.js",
            ("data-v-app", "__vue__"),
            "Vue.js HTML signature",
        ),
        (
            "JavaScript Framework", "Angular",
            ("ng-version=", "ng-version"),
            "Angular HTML signature",
        ),
    ]

    for category, name, markers, evidence in signatures:
        if any(marker in content for marker in markers):
            _add_findings(findings, category, name, evidence)

def identify(response):
    """Identify technologies from an HTTP response-like object."""

    findings = []

    headers = _normalize_headers(response.headers)
    _inspect_headers(headers, findings)
    _inspect_cookies(response.cookies, findings)
    _inspect_html(response.text or "", findings)

    return findings

def scan(url):
    """Fetch one URL and return it's technology findings."""

    url = url.strip()

    if not url.startswith(("http://" or "https://")):
        url = f"https://{url}"

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()

        return {
            "url": response.url,
            "technologies": identify(response),
            "error": None,
        }

    except requests.RequestException as exc:
        return {
            "url": url,
            "technologies": [],
            "error": str(exc),
        }