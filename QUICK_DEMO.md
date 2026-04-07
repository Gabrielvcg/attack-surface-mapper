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

---

## 2. Basic usage

Run a simple scan:

```bash
python main.py https://example.com/
```

---

## 3. Recommended profiles (try these)

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

- Passing a target via CLI overrides YAML profiles
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

---

## 7. What to look at

When testing the tool, compare:

- number of requests (logs)
- endpoints discovered
- findings generated
- differences between profiles

Key idea:

**stealth vs coverage vs signal quality**
