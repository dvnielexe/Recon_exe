from pathlib import Path
import dns.resolver 
import re

COMMON_SUBDOMAINS = [
    "www",
    "api",
    "dev",
    "staging",
    "test",
    "mail",
    "admin",
    "portal",
    "app"
]

def is_valid_label(name: str):
    """Check whether a candidate is a valid dns label"""

    return bool(
        re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            name
        )
    )

def resolve_subdomain(subdomain: str):
    """Resole a subdomain and return it's IPv4 and IPv6 addresses."""

    results = {
        "A": [],
        "AAAA": [],
    }

    for record_type in results:
        try:
            answers = dns.resolver.resolve(subdomain, record_type)
            results[record_type] = [
                answer.to_text() for answer in answers 
            ]

        except(
            dns.resolver.NXDOMAIN,
            dns.resolver.Timeout,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers
        ):
            continue

    return results

    


def load_wordlist(path: str):
    """Load subdomains prefixes from a wordlist."""

    wordlist_path = Path(path)
    if not wordlist_path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    
    with open(path, "r", encoding="utf-8") as file:
        names = [
            line.strip().lower()
            for line in file
            if line.strip() and not line.lstrip().startswith("#")
        ]

        names = [name for name in names if is_valid_label(name)]
    
    return list(dict.fromkeys(names))

def scan(domain: str, wordlist: str = None):
    """Discover common subdomains for a domain."""
    if wordlist:
        names = load_wordlist(wordlist)
    else:
        names =COMMON_SUBDOMAINS

    results = []

    for name in names:
        subdomain = f"{name}.{domain}"

        addresses = resolve_subdomain(subdomain)

        if addresses["A"] or addresses["AAAA"]:
            results.append(
                {
                    "subdomain": subdomain,
                    "ips": addresses,
                }
            )

    return results