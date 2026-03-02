#!/bin/bash
export PATH="/usr/local/bin:$PATH"
export WPSCAN_API_TOKEN=nL5IQBV8aZTVXP4hXdEZWAUrhkSG0axd2foMGUc4SNs
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
mkdir -p reports

echo "[*] Installing dependencies..."
wpscan --update

echo "[*] Starting scan..."
python -m src.main --top100 2>&1 | tee "reports/log_$TIMESTAMP.txt"