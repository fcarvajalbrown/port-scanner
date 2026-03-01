# Port Scanner

Infrastructure recon tool — resolves domains via DNS and scans for open ports.

## Installation

1. Clone the repo:
```bash
   git clone https://github.com/yourusername/port-scanner.git
   cd port-scanner
```

2. Install dependencies (none required, uses Python stdlib only):
```bash
   python --version  # requires 3.8+
```

3. Add your company domains to `config/domains.json`:
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

- **Terminal** — real-time DNS resolution, open port discovery with risk labels, extractor results
- **`reports/results.json`** — structured JSON generated after every scan

## Config

**`config/settings.ini`** — tune performance:
```ini
[Scanner]
timeout_seconds = 1   # lower = faster but more misses
max_threads = 100     # concurrent threads per target
```

## Extractors

If MySQL (3306), PostgreSQL (5432), or FTP (21) are found open, the tool automatically:
- Connects and reads the service banner
- Reports version info or authentication requirements
- Flags anonymous FTP access as CRITICAL

Results are appended to terminal output after the scan summary.

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
│           └── ftp.py
└── tests/
    ├── __init__.py
    └── test_scanner.py
```

## Run Tests
```bash
python -m pytest tests/
```