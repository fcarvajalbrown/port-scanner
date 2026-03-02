#!/bin/bash
export WPSCAN_API_TOKEN=nL5IQBV8aZTVXP4hXdEZWAUrhkSG0axd2foMGUc4SNs
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
python -m src.main --full 2>&1 | tee "reports/log_$TIMESTAMP.txt"