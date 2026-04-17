# Fast Usage Guide

## 1. Setup environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Optional (only for active dynamic profile):

```bash
python -m playwright install
```

## 1.5 Install Nuclei (required)

This tool uses Nuclei (https://github.com/projectdiscovery/nuclei) for fast vulnerability detection.

### Install via Go

```bash
sudo apt install golang-go -y
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Add to PATH:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

#### (Optional) make it permanent:

```bash
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

### Download Nuclei templates

```bash
nuclei -update-templates
```


---

## 2. Basic usage

Run a simple scan:

```bash
python main.py https://example.com/
```

---

## 3. Recommended profiles (try these)

By default, passive profiles are recommended unless running controlled or authorized tests.

### Low noise (stealth)

```bash
python main.py --profile passive-stealth https://TARGET/
```

### Balanced (recommended)

```bash
python main.py --profile passive-recon-safe https://TARGET/
```

### More coverage (enumeration)

```bash
python main.py --profile passive-recon-enum https://TARGET/
```

### Aggressive (max coverage)

```bash
python main.py --profile active https://TARGET/
```

---

## 4. Using a targets file

```bash
python main.py --targets-file targets.txt --profile passive-recon-safe
```

---

## 5. Important notes

- Passing a target via CLI adds it to YAML/profile targets and deduplicates the final list
- Profiles are located in: `config/profiles/`
- Passive modes do NOT require Playwright
- Active mode may require Playwright

---

## 6. Where to check results

Each run creates a folder:

```bash
scans/<timestamp>/
```

### Main report (read this first)

```bash
scans/<timestamp>/reports/aggregate_report.md
```

### Other useful files

- Summary (JSON):
```bash
scans/<timestamp>/reports/aggregate_summary.json
```

- CSV export:
```bash
scans/<timestamp>/reports/aggregate_findings.csv
```

- Per-target findings:
```bash
scans/<timestamp>/targets/<target>/findings/vulnerabilities.json
```

- Execution metadata:
```bash
scans/<timestamp>/run_manifest.json
```

### Elasticsearch export bundle

You can generate an Elasticsearch-ready bundle from any completed run:

```bash
python scripts/export_elasticsearch_bundle.py --run-dir scans/<timestamp>
```

This creates:

- `scans/<timestamp>/elasticsearch/findings_mapping.json`
- `scans/<timestamp>/elasticsearch/summaries_mapping.json`
- `scans/<timestamp>/elasticsearch/runs_mapping.json`
- `scans/<timestamp>/elasticsearch/findings_bulk.ndjson`
- `scans/<timestamp>/elasticsearch/summaries_bulk.ndjson`
- `scans/<timestamp>/elasticsearch/runs_bulk.ndjson`
- `scans/<timestamp>/elasticsearch/manual_kibana_devtools.md`
- `scans/<timestamp>/elasticsearch/ingest_with_curl.sh`
- `scans/<timestamp>/elasticsearch/ingest_with_python.py`

If you need a different prefix for the indices:

```bash
python scripts/export_elasticsearch_bundle.py --run-dir scans/<timestamp> --index-prefix asm-demo
```

--- 

## 7. What to look at

When testing the tool, compare:

- number of requests (logs)
- endpoints discovered
- findings generated
- differences between profiles

Key idea:

**stealth vs coverage vs signal quality**

---

## 8. Repeatable local lab

Juice Shop is a good low-friction target for checking that passive profiles stay aligned with their intended noise level:

```bash
docker run -d --rm --name asm-juice -p 3000:3000 bkimminich/juice-shop
python main.py --profile passive-stealth http://localhost:3000
python main.py --profile passive-recon-safe http://localhost:3000
docker stop asm-juice
```

Useful files to compare between both runs:

- `run_manifest.json`
- `reports/aggregate_summary.json`
- `targets/<target>/reports/report.summary.json`

On Windows/PowerShell, the same flow can be repeated with:

```powershell
.\scripts\validate_labs.ps1 -Labs juice-shop
.\scripts\validate_labs.ps1 -Labs juice-shop -IncludeEnum
```

The script also validates the generated manifest and summary artifacts. Use
`-MinFindings 2` or similar if you want the smoke test to enforce a stricter
minimum number of correlated findings.
After each run it exports `reviews/lab_findings_review.csv`, ready to annotate
with `verdadero`, `falso` or `dudoso` during false-positive review.
With `-IncludeEnum`, the script applies `config/examples/lab-passive-recon-enum.yml`
so `passive-recon-enum` remains repeatable in Docker without a local Nuclei binary.

Once the run is generated, you can also export the lab results to Elasticsearch:

```powershell
python .\scripts\export_elasticsearch_bundle.py --run-dir scans\lab_juice_shop_passive_recon_enum
```

The generated bundle includes the three ingestion paths requested by the tutor:
- manual / Kibana Dev Tools
- `curl`
- Python

---

## Passive vs Active usage (important)

This tool supports both passive and active analysis modes.

### Passive mode (recommended)

- Low noise
- Non-intrusive
- Suitable for external targets

Example:
```bash
python main.py https://example.com --profile passive-recon-safe
```
---

### Active mode (use with authorization only)

- More aggressive checks
- May generate detectable traffic
- Requires tools like Nmap and Nuclei

Example:

```bash
python main.py http://localhost:3000 --profile active
```
---

### Notes

- Do NOT use active profiles without permission
- For external targets → use passive mode
