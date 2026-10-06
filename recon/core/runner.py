from pathlib import Path
from recon.core.config import Config
from recon.modules.dns import scan
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

        
        dns_results = scan(self.config.target)

        if output_dir:
            output_path = save_json(output_dir, "dns.json", dns_results)
            print(f"\nDNS results saved to: {output_path}")

        print("\nDNS Results: ")

        for record_type, records in dns_results.items():
            print(f"\n{record_type}:")

            if records:
                for record in records:
                    print(f" -{record}")
            else:
                print(" No records found")
