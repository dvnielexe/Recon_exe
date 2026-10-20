from pathlib import Path
from recon.core.config import Config
from recon.modules import dns
from recon.modules import http
from recon.modules import subdomains
from recon.modules import services
from recon.modules import urls
from recon.modules import technologies
from recon.core.output import save_json

class Runner():
    def __init__(self, config: Config):
        self.config = config

    def run(self):
        print(f"Starting reconnaisance on {self.config.target}")
        
        output_dir = self.config.output

        if not output_dir:
            output_dir = Path("results") / self.config.target

        Path(output_dir).mkdir(parents=True, exist_ok=True)    

        if self.config.verbose:
            print(f"[VERBOSE]: Output directory set to {self.config.output}")

        # DNS
        dns_results = dns.scan(self.config.target)

        if output_dir:
            dns_output_path = save_json(output_dir, "dns.json", dns_results)
            print(f"\nDNS results saved to: {dns_output_path}")

        print("\nDNS Results: ")

        for record_type, records in dns_results.items():
            print(f"\n{record_type}:")

            if records:
                for record in records:
                    print(f" -{record}")
            else:
                print(" No records found")

        # Subdomain
        try:
             subdomain_results = subdomains.scan(self.config.target, self.config.wordlist)
        except(FileNotFoundError, PermissionError, UnicodeDecodeError) as error:
            print(f"\n[!] Subdomain scan failed: {error}")
            subdomain_results = []

        if output_dir:
            subdomain_output_path = save_json(output_dir, "subdomain.json", subdomain_results)
            print(f"\nSubdomain results saved to {subdomain_output_path}")

        print("\n[+] Subdomains")

        for result in subdomain_results:
            print(f" - {result['subdomain']}")

            for record_type, addresses in result["ips"].items():
                if addresses:
                    print(f"    {record_type}: {"," .join(addresses)}")

        # HTTP
        http_results = http.scan(self.config.target)

        if output_dir:
            http_output_path = save_json(output_dir, "http.json", http_results)
            print(f"\nHTTP Results saved to: {http_output_path}")

        print(f"\nHTTP Results:")

        for protocol, result in http_results.items():
            print(f"\n{protocol.upper()}:")

            if "error" in result:
                print(f"Error: {result['error']}")
                continue

            print(f"URL: {result['url']}")
            print(f"Status: {result['status_code']}")
            print(f"Server: {result['server']}")
            print(f"Content-Type: {result['content-type']}")
            print(f"Redirect: {result['redirect']}")

            print("Security Headers: ")
            if result["security_headers"]:
                for header, value in result["security_headers"].items():
                    print(f" {header}: {value}")

            else:
                print("None found")

        # Service Discovery scan
        if self.config.services:
            print("\n[+] Service Discovery")

            service_results = services.scan(self.config.target)

            service_output_path = save_json(output_dir, "services.json", service_results)
            print(f"Service results saved to: {service_output_path}")

            for result in service_results:
                print(
                    f" - {result['host']}:{result['port']}/"
                    f"{result['protocol']} | "
                    f"{result['state']} | "
                    f"{result['service']} | "
                    f"Version: {result['version']}"
                )

        else:
            if self.config.verbose:
                print("\n [VERBOSE] Service discovery skipped. Use --services to enable it.")


       # URL Intelligence
        if self.config.urls:
            print("\n[+] Url Intelligence")

            url_results = urls.scan(self.config.target)

            url_output_path = save_json(output_dir, "urls.json", url_results)
            print(f"URL Results saved to: {url_output_path}")

            print(f"Starting URL: {url_results['start_url']}")
            print(f"URLs Found: {url_results['urls_found']}")

            for result in url_results["results"]:

                print(f"\n URL: {result['url']}")
                print(f" Endpoint: {result['endpoint']}")

                if result["parameters"]:
                    print(f" Parameters: {result['parameters']}")
                else:
                    print(f" Parameters: None")


        # Technology Identification
        print("\n[] Technology Identification")

        technology_results = technologies.scan(self.config.target)
        
        if output_dir:
            technology_output_path = save_json(output_dir, "technologies.json", technology_results)
            print(f"Results saved to: {technology_output_path}")

        if technology_results["error"]:
            print(
                f"Technology scan failed: "
                f"{technology_results['error']}"
            )
        elif technology_results["technologies"]:
            for finding in technology_results["technologies"]:
                print(
                    f" - {finding['name']}"
                    f"({finding['category']})"
                )

                for evidence in finding["evidence"]:
                    print(f" Evidence:  {evidence}")

        else:
            print("No technologies identified.")