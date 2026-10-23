import json
from datetime import datetime
from pathlib import Path

RESULT_FILES = {
    "dns": "dns.json",
    "http": "http.json",
    "services": "services.json",
    "subdomains": "subdomain.json",
    "technologies": "technologies.json",
    "urls": "urls.json",
}

def load_json(output_dir: Path, filename: str):
    """Load a JSON result file returning None if unavailable or invalid."""

    path = output_dir / filename

    if not path.is_file():
        return None

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except(OSError, json.JSONDecodeError) as error:
        return {"_error": str(error)}

def count_dns_records(data):
    """Count individual DNS records across all types"""

    if not isinstance(data, dict):
        return 0

    return sum(
        len(records)
        for records in data.values()
        if isinstance(records, list)
    )

def count_urls(data):
    """Count URL results, using the result list as the source of truth"""

    if not isinstance(data, dict):
        return 0

    results = data.get("results", [])
    return len(results) if isinstance(results, list) else 0

def generate_report(output_dir, target):
    output_dir = Path(output_dir)

    results = {
        name: load_json(output_dir, filename)
        for name, filename in RESULT_FILES.items()
    }


    dns_data = results["dns"]
    http_data = results["http"]
    service_data = results["services"]
    subdomain_data = results["subdomains"]
    url_data = results["urls"]
    technology_data = results["technologies"]

    dns_count = count_dns_records(dns_data)

    subdomain_count = (
        len(subdomain_data)
        if isinstance(subdomain_data, list)
        else 0
    )

    service_count = (
        len(service_data)
        if isinstance(service_data, list)
        else 0
    )

    url_count = count_urls(url_data)

    technologies = (
        technology_data.get("technologies", [])
        if isinstance(technology_data, dict)
        else []
    )

    technology_count = (
        len(technologies)
        if isinstance(technologies, list)
        else 0
    )

    lines = [
        "# Reconnaissance Report",
        "",
        f"- **Target:** {target}",
        f"- **Scan report generated:** {datetime.now().astimezone().isoformat(timespec='seconds')}",
        "",
        "## Scan Summary",
        "",
        f"- DNS records: {dns_count}",
        f"- Subdomains: {subdomain_count}",
        f"- Services: {service_count}",
        f"- URLs/endpoints: {url_count}",
        f"- Technologies: {technology_count}",
        "",
        "## DNS",
        "",
    ]

    if dns_data is None:
        lines.append("Results unavailable. `dns.json` is missing")
    elif "_error" in dns_data:
        lines.append(f"Could not read DNS results. {dns_data['_error']}")
    elif not any(
        records for records in dns_data.values()
        if isinstance(records, list)
    ):
        lines.append(" No DNS records found.")
    else:
        for record_type, records in dns_data.items():
            if not isinstance(records, list):
                continue

            lines.append(f"### {record_type}")
            lines.append("")

            if records:
                lines.extend(f"- `{record}`" for record in records)
            else:
                lines.append("- None found")

            lines.append("")

    lines.extend(["## HTTP", ""])

    if http_data is None:
        lines.append("Results unavailable: `http.json` is missing.")
    elif "_error" in http_data:
        lines.append(f"Could not read HTTP results: {http_data['_error']}")
    elif not http_data:
        lines.append("No HTTP results available.")
    else:
        for protocol, result in http_data.items():
            lines.extend([f"### {protocol.upper()}", ""])

            if not isinstance(result, dict):
                lines.extend(["Invalid result format.", ""])
                continue

            if result.get("error"):
                lines.extend([f"- **Error:** {result['error']}", ""])
                continue

            lines.extend([
                f"- **URL:** {result.get('url', 'Unknown')}",
                f"- **Status:** {result.get('status_code', 'Unknown')}",
                f"- **Server:** {result.get('server') or 'Unknown'}",
                f"- **Content type:** {result.get('content-type') or 'Unknown'}",
                f"- **Redirect:** {result.get('redirect') or 'None'}",
                "- **Security headers:**",
            ])

            headers = result.get("security_headers", {})

            if isinstance(headers, dict) and headers:
                lines.extend(
                    f"  - `{header}`: `{value}`"
                    for header, value in headers.items()
                )
            else:
                lines.append("  - None recorded")

            lines.append("")

    lines.extend(["## Subdomains", ""])

    if subdomain_data is None:
        lines.append("Results unavailable: `subdomain.json` is missing.")
    elif (
        isinstance(subdomain_data, dict)
        and "_error" in subdomain_data
    ):
        lines.append(
            f"Could not read subdomain results: {subdomain_data['_error']}"
        )
    elif not subdomain_data:
        lines.append("No subdomains found.")
    else:
        for item in subdomain_data:
            if not isinstance(item, dict):
                continue

            subdomain = item.get("subdomain", "Unknown")
            lines.append(f"### `{subdomain}`")

            ips = item.get("ips", {})
            if isinstance(ips, dict):
                for record_type, addresses in ips.items():
                    if addresses:
                        lines.append(
                            f"- **{record_type}:** {', '.join(addresses)}"
                        )

            lines.append("")

    lines.extend(["## Services", ""])

    if service_data is None:
        lines.append("Results unavailable: `services.json` is missing.")
    elif "_error" in service_data:
        lines.append(
            f"Could not read service results: {service_data['_error']}"
        )
    elif not service_data:
        lines.append("No services found.")
    else:
        lines.extend([
            "| Host | Port | Protocol | State | Service | Version |",
            "|---|---:|---|---|---|---|",
        ])

        for item in service_data:
            if not isinstance(item, dict):
                continue

            lines.append(
                f"| {item.get('host', 'Unknown')} "
                f"| {item.get('port', 'Unknown')} "
                f"| {item.get('protocol', 'Unknown')} "
                f"| {item.get('state', 'Unknown')} "
                f"| {item.get('service', 'Unknown')} "
                f"| {item.get('version') or 'Unknown'} |"
            )

        lines.append("")

    lines.extend(["## Technologies", ""])

    if technology_data is None:
        lines.append("Results unavailable: `technologies.json` is missing.")
    elif "_error" in technology_data:
        lines.append(
            f"Could not read technology results: {technology_data['_error']}"
        )
    else:
        technology_error = technology_data.get("error")

        if technology_error:
            lines.append(f"**Scan error:** {technology_error}")
            lines.append("")

        if not technologies:
            lines.append("No technologies identified.")
        else:
            for item in technologies:
                if not isinstance(item, dict):
                    continue

                lines.extend([
                    f"### {item.get('name', 'Unknown')}",
                    "",
                    f"- **Category:** {item.get('category', 'Unknown')}",
                    "- **Evidence:**",
                ])

                evidence = item.get("evidence", [])

                if evidence:
                    lines.extend(f"  - {entry}" for entry in evidence)
                else:
                    lines.append("  - None recorded")

                lines.append("")

    lines.extend(["## URLs and Endpoints", ""])

    if url_data is None:
        lines.append("Results unavailable: `urls.json` is missing.")
    elif "_error" in url_data:
        lines.append(f"Could not read URL results: {url_data['_error']}")
    elif not url_data.get("results"):
        lines.append("No URLs found.")
    else:
        lines.extend([
            f"- **Starting URL:** {url_data.get('start_url', 'Unknown')}",
            "",
            "| URL | Endpoint | Parameters |",
            "|---|---|---|",
        ])

        for item in url_data["results"]:
            if not isinstance(item, dict):
                continue

            lines.append(
                f"| {item.get('url', 'Unknown')} "
                f"| `{item.get('endpoint', 'Unknown')}` "
                f"| `{json.dumps(item.get('parameters', {}), ensure_ascii=False)}` |"
            )

        lines.append("")

        # Interesting Assets
    lines.extend(["## Interesting Assets", ""])

    interesting_assets = []

    # Highlight subdomains that may deserve manual review.
    if isinstance(subdomain_data, list):
        interesting_names = (
            "admin", "dev", "staging", "test", "api",
            "internal", "vpn", "portal", "dashboard",
        )

        for item in subdomain_data:
            if not isinstance(item, dict):
                continue

            hostname = item.get("subdomain", "")
            prefix = hostname.split(".")[0].lower()

            if prefix in interesting_names:
                interesting_assets.append(
                    f"- **Subdomain for review:** `{hostname}`"
                )

    # Highlight discovered URLs with query parameters.
    if isinstance(url_data, dict):
        url_results = url_data.get("results", [])

        if isinstance(url_results, list):
            for item in url_results:
                if not isinstance(item, dict):
                    continue

                parameters = item.get("parameters", {})

                if parameters:
                    interesting_assets.append(
                        f"- **Parameterized URL:** "
                        f"[{item.get('url', 'Unknown')}]"
                        f"({item.get('url', 'Unknown')})"
                    )

    # Highlight services confirmed open.
    if isinstance(service_data, list):
        for item in service_data:
            if not isinstance(item, dict):
                continue

            if str(item.get("state", "")).lower() == "open":
                interesting_assets.append(
                    f"- **Open service:** "
                    f"`{item.get('host', 'Unknown')}:"
                    f"{item.get('port', 'Unknown')}` "
                    f"({item.get('service') or 'service unidentified'})"
                )

    if interesting_assets:
        lines.extend(interesting_assets)
    else:
        lines.append("No assets matched the current review heuristics.")

    lines.append("")

    lines.extend(["## Errors and Incomplete Scans", ""])

    errors_found = False

    for name, data in results.items():
        if data is None:
            filename = RESULT_FILES[name]

            if name in ("services", "urls"):
                status = "skipped or not saved; check module configuration"
            else:
                status = "expected results file is missing"

            lines.append(
                f"- **{name.title()}:** `{filename}` is missing "
                f"({status})."
            )
            errors_found = True
            continue

        if isinstance(data, dict) and data.get("_error"):
            lines.append(f"- **{name.title()}:** {data['_error']}")
            errors_found = True
            continue

        if name == "technologies" and isinstance(data, dict) and data.get("error"):
            lines.append(
                f"- **Technologies:** {data['error']}"
            )
            errors_found = True

        if name == "http" and isinstance(data, dict):
            for protocol, item in data.items():
                if isinstance(item, dict) and item.get("error"):
                    lines.append(
                        f"- **HTTP ({protocol}):** {item['error']}"
                    )
                    errors_found = True

    if not errors_found:
        lines.append("No recorded errors. Missing files are reported above.")

    lines.append("")

    report_path = output_dir / "report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")

    return report_path