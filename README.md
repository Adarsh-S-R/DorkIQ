## DorkIQ

Generate focused Google dorks for a target domain. Handy for quick recon and triage.

### What it does
- Generates dorks across common vuln areas (SQLi, XSS, LFI/RFI, configs, backups, secrets, cloud, etc.)
- Optional subdomain and advanced modes for broader coverage
- Includes intent filters and type dropdown
- Export results

### Quick start
```bash
pip install -r requirements.txt
python app.py
# open http://localhost:8000
```

Tip: set `DEBUG=true` to enable reload during development.

### API
- POST `/generate-dorks`

Request:
```json
{
  "domain": "example.com",
  "include_subdomains": true,
  "vulnerability_category": "all",
  "advanced_mode": false
}
```

Response (trimmed):
```json
[
  {
    "category": "High",
    "intent_category": "Vulnerable Technologies",
    "name": "SQL Injection - ID Parameter",
    "dork": "inurl:id= site:example.com",
    "owasp": "A1",
    "notes": "Search for ID parameters vulnerable to SQL injection",
    "tags": ["SQLi", "Parameter"]
  }
]
```

Other endpoints:
- GET `/` UI
- GET `/styles.css`, `/script.js`
- GET `/api/health`

### Notes
- This is a **community project**: it exists to help other researchers share patterns, improve dork hygiene, and reduce false positives. Contributions, improvements, and curated dork packs are very welcome.
