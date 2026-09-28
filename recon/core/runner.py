from recon.core.config import Config

class Runner():
    def __init__(self, config: Config):
        self.config = config

    def run(self):
        print(f"Starting reconnaisance on {self.config.target}")
        if self.config.verbose:
            print(f"[VERBOSE]: Output directory set to {self.config.output}")