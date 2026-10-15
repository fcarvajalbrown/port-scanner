# AGENTS.md

## Purpose

Infrastructure recon and exploitation framework for authorized penetration testing: DNS resolution,
threaded port scanning, and a chained extractor pipeline (fingerprinting, brute force, credential
harvesting, CVE-2023-5360 RCE) against open services. Use only against infrastructure the operator
owns or has written authorization to test.

## Entry points

- `python -m src.main --top100` / `--full` — run a scan against targets in `config/domains.json`
- `python -m src.main --target <host>` — single-target scan, overrides `config/domains.json`
- `attack.py` — standalone focused brute force against MySQL/PostgreSQL/FTP on one target
- `python -m pytest tests/` — run the test suite

## Structure

- `src/main.py` — CLI entry point, argument parsing
- `src/utils/scanner.py` — `PortScanner`: DNS resolution, threaded port scan, JSON export
- `src/utils/extractors/router.py` — `ExtractorRouter`: chains extractors in priority order,
  shares a credential pool across stages (see README's "Extractors" section for the full chain)
- `src/utils/extractors/*.py` — one module per extractor/exploit (mysql, postgres, ftp, ssh,
  cpanel, webdav, dns_axfr, cdn_bypass, gobuster_extractor, nikto_extractor, wpscan_extractor,
  http_config_scraper, royal_elementor_exploit)
- `config/domains.json` — scan targets (`id`, `host` pairs)
- `config/settings.ini` — scanner tuning (`timeout_seconds`, `max_threads`, `scan_delay_seconds`)
  and the `[Exploit] run_exploit` gate for brute force/exploit extractors
- `wordlists/` — username/password lists used by brute-force extractors
- `reports/` — `results.json` / `results.csv` output of the most recent scan

## Conventions

- Python stdlib only — no new runtime dependency without discussing it first
- Extractors are self-contained modules dispatched by `ExtractorRouter._dispatch` / the numbered
  methods in `router.py`; a new extractor follows the same shape: `run()` returns a result dict or
  `None`, wrapped by `_run_with_timeout`
- No code comments — if something needs explaining, rename or restructure instead
- Tests live in `tests/`, mirroring `unittest` style already used in `test_scanner.py`
- Never commit real scan targets, live credentials, or scan output from a real engagement into
  `config/domains.json` or `reports/` — keep those local/untracked for any non-placeholder run
