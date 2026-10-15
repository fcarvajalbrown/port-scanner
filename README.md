# Port Scanner

Infrastructure recon and exploitation framework for authorized penetration testing. It resolves
domains via DNS, scans for open ports, and chains automated extractors (service fingerprinting,
brute force, credential harvesting, and a CVE-2023-5360 RCE exploit) against anything it finds open.

**For authorized security testing only.** Only point this at infrastructure you own or have
written permission to test.

## Installation

1. Clone the repo:
```bash
   git clone https://github.com/fcarvajalbrown/port-scanner.git
   cd port-scanner
```

2. Install dependencies (none required, uses Python stdlib only):
```bash
   python --version  # requires 3.8+
```

3. Add your authorized targets to `config/domains.json`:
```json
   {
       "domains": [
           { "id": "main", "host": "yourcompany.com" },
           { "id": "api",  "host": "api.yourcompany.com" }
       ]
   }
```

## Usage

Run from the project root (`port-scanner/`):
```bash
# Scan top 100 most common ports (faster, recommended first run)
python -m src.main --top100

# Scan full port range 1-65535 (slower, thorough)
python -m src.main --full
```

## Output

- **Terminal**: real-time DNS resolution, open port discovery with risk labels, extractor results
- **`reports/results.json`**: structured JSON generated after every scan

## Config

**`config/settings.ini`** tunes performance and gates exploitation:
```ini
[Scanner]
timeout_seconds = 4
max_threads = 10
scan_delay_seconds = 5

[Output]
json_export = true

[Exploit]
run_exploit = false   # set true to enable brute force / RCE extractors below
```

## Extractors

Once a scan finds open ports, `ExtractorRouter` (`src/utils/extractors/router.py`) runs a chain of
extractors in priority order, feeding results from one stage into the next:

1. **CDN bypass**: finds an origin IP behind a CDN and re-scans it directly
2. **Nikto**: web vulnerability scan on 80/443
3. **WPScan**: WordPress plugin/user enumeration; feeds discovered usernames into the credential pool
4. **Royal Elementor RCE**: if WPScan detects the `royal-elementor-addons` plugin, attempts
   CVE-2023-5360 (unauthenticated file upload RCE) and extracts DB credentials from `wp-config.php`
5. **Gobuster**: directory brute force on 80/443; feeds discovered config/backup files into the
   config scraper
6. **HTTP config scraper**: fetches exposed config files and extracts credentials
7. **WebDAV**: unauthenticated PROPFIND listing and PUT write test
8. **DNS AXFR**: attempts a zone transfer on port 53
9. **cPanel / WHM brute force**: credential brute force on 2083/2087 using the bundled wordlists
10. **Service extractors**: MySQL, PostgreSQL, FTP, SSH. Connects with any credentials found in
    earlier stages, or reads the banner if none were found. Flags anonymous FTP as CRITICAL.

Credentials found at any stage (WPScan users, scraped config passwords, RCE-leaked DB credentials)
are injected into a shared pool and tried against later services (SSH, FTP, cPanel/WHM).

Brute-force stages use the wordlists in `wordlists/` (10M usernames, 10M passwords) and only run
when `run_exploit = true` in `config/settings.ini`.

## Risk Labels

| Label    | Meaning                              |
|----------|--------------------------------------|
| CRITICAL | Exposed with no auth by default      |
| HIGH     | Database or remote access service    |
| LOW      | Generally safe but worth noting      |

## File Structure
```
port-scanner/
├── README.md
├── config/
│   ├── domains.json
│   └── settings.ini
├── reports/
│   └── results.json
├── wordlists/
├── src/
│   ├── __init__.py
│   ├── main.py
│   └── utils/
│       ├── __init__.py
│       ├── scanner.py
│       └── extractors/
│           ├── __init__.py
│           ├── router.py
│           ├── mysql.py
│           ├── postgres.py
│           ├── ftp.py
│           ├── ssh.py
│           ├── cpanel.py
│           ├── webdav.py
│           ├── dns_axfr.py
│           ├── cdn_bypass.py
│           ├── gobuster_extractor.py
│           ├── nikto_extractor.py
│           ├── wpscan_extractor.py
│           └── http_config_scraper.py
└── tests/
    ├── __init__.py
    └── test_scanner.py
```

## Run Tests
```bash
python -m pytest tests/
```
