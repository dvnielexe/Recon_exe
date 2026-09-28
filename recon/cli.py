import argparse
from recon.core.config import Config
from recon.core.runner import Runner

def main():
    parser = argparse.ArgumentParser(description="Recon target parser")

    parser.add_argument("target", help="Target domain or ip address")
    parser.add_argument("-o", "--output", help="Path to save output results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enables verbose logging")

    args = parser.parse_args()

    config = Config(
        target=args.target,
        output=args.output,
        verbose=args.verbose
    )

    runner = Runner(config)

    runner.run()



