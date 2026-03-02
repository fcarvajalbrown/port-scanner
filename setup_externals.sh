#!/bin/bash
# setup.sh — installs system dependencies for port-scanner
# Run once from project root: bash setup.sh
# Requires: sudo, ruby (for WPScan), perl (for Nikto)

set -e

echo "===== port-scanner setup ====="

# ─── Nikto ────────────────────────────────────────────────────────────────────
echo ""
echo "[1/2] Installing Nikto..."
if command -v nikto &>/dev/null; then
    echo "  Nikto already installed: $(nikto -Version 2>&1 | head -1)"
else
    sudo apt-get update -qq
    sudo apt-get install -y nikto
    echo "  Nikto installed: $(nikto -Version 2>&1 | head -1)"
fi

# ─── WPScan ───────────────────────────────────────────────────────────────────
echo ""
echo "[2/2] Installing WPScan..."
if command -v wpscan &>/dev/null; then
    echo "  WPScan already installed: $(wpscan --version 2>&1 | head -1)"
else
    # WPScan requires Ruby >= 2.5
    if ! command -v ruby &>/dev/null; then
        echo "  Ruby not found — installing..."
        sudo apt-get install -y ruby ruby-dev
    fi
    echo "  Ruby: $(ruby --version)"
    sudo gem install wpscan
    echo "  WPScan installed: $(wpscan --version 2>&1 | head -1)"
fi

# ─── Optional: update WPScan vulnerability DB ─────────────────────────────────
echo ""
echo "[+] Updating WPScan vulnerability database..."
wpscan --update || echo "  (skipped — no API token or network issue)"

echo ""
echo "===== Setup complete ====="
echo "  nikto:  $(command -v nikto)"
echo "  wpscan: $(command -v wpscan)"
echo ""
echo "Optional: set your WPScan API token for CVE lookups:"
echo "  export WPSCAN_API_TOKEN=your_token_here"
echo "  Get a free token at: https://wpscan.com/register"