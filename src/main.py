"""Port scanner entry point. Resolves domains from config and scans for open ports."""

import argparse
from src.utils.scanner import PortScanner


def parse_args():
    """Parse CLI arguments for port range selection."""
    parser = argparse.ArgumentParser(description='Port Scanner — Infrastructure Recon Tool')
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '--top100',
        action='store_true',
        help='Scan top 100 most common ports (faster)'
    )
    group.add_argument(
        '--full',
        action='store_true',
        help='Scan full port range 1-65535 (slower)'
    )
    return parser.parse_args()


def main():
    """Resolve domains, scan ports, print results and export JSON."""
    print("DEBUG: main() started", flush=True)
    args = parse_args()

    if args.full:
        port_mode = 'full'
    else:
        port_mode = 'top100'

    scanner = PortScanner(port_mode=port_mode)
    scanner.run()


if __name__ == '__main__':
    main()