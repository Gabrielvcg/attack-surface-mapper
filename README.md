# Attack Surface Mapper

## Overview

Attack Surface Mapper is a **pipeline-based security analysis tool** focused on discovering, validating and reporting the attack surface of web applications and exposed services.

It is designed to go beyond a simple scanner. The project combines:

- **HTTP discovery and crawling**
- **passive and active validation**
- **optional network reconnaissance**
- **correlation and deduplication of findings**
- **human-readable and machine-readable reporting**

The result is a tool that can operate with different noise levels, from very stealthy observation to broader enumeration and more aggressive validation.

---

## Main Technologies Used

### Python
The project is implemented in **Python 3.11+** and organised in a modular way so each responsibility is separated:
- orchestration
- pipeline stages
- collectors
- validators
- parsers
- reporting
- batch aggregation

### Nuclei
**Nuclei** is used for template-based security checks.  
It provides fast extensible detection and its findings are parsed and converted into the common internal vulnerability model.

### Nmap
**Nmap** is optional and used to enrich the analysis with **open ports and service discovery**.  
This allows the tool to correlate web findings with network exposure when needed.

### requests / Scrapling
The HTTP layer supports different backends:
- `requests`
- `scrapling`
- `auto`

This makes it possible to run:
- quieter passive navigation
- standard crawling
- more dynamic discovery depending on the selected profile

### Playwright
**Playwright** is only required for the **dynamic active profile**.  
Passive profiles do **not** require browser installation.

### Custom validation and correlation
The core value of the project is not only running third-party tools, but also adding:
- custom validators
- attack-surface discovery logic
- endpoint classification
- finding enrichment
- correlation
- prioritisation
- false-positive reduction

---

## High-Level Architecture

The project is built as a **multi-stage pipeline**.

### 1. Discovery
The tool first collects observable surface from the target:
- root response
- linked resources
- forms
- JavaScript hints
- candidate endpoints
- observed navigation paths

### 2. Validation
It then validates the discovered surface using:
- Nuclei
- security header checks
- TLS checks
- authentication surface analysis
- admin/panel checks
- API exposure checks
- sensitive file checks
- secret discovery

### 3. Optional network reconnaissance
When enabled, Nmap adds:
- open ports
- service banners
- network exposure categories

### 4. Correlation
The raw information is then processed to:
- deduplicate findings
- correlate related evidence
- improve prioritisation
- separate true issues from discovered/protected surface

### 5. Reporting
Finally, the tool generates:
- per-target reports
- aggregate run reports
- JSON summaries
- Markdown / CSV / HTML outputs
- optional Elasticsearch export bundles from an existing run

---

## Project Structure

```text
attack_surface_mapper/
├── main.py
├── pyproject.toml
├── requirements.txt
├── README.md
├── CHANGELOG.md
├── docs/
│   ├── OUTPUTS.md
│   ├── PIPELINE.md
│   ├── PROFILES.md
│   └── STRUCTURE.md
├── config/
│   ├── examples/
│   └── profiles/
│       ├── active-aggressive.yml
│       ├── passive-recon-enum.yml
│       ├── passive-recon-safe.yml
│       ├── passive-recon.yml
│       └── passive-stealth.yml
├── scripts/
│   └── clean_scans.sh
├── src/
│   └── attack_surface_mapper/
│       ├── analysis/
│       ├── batch/
│       ├── collectors/
│       │   ├── crawling/
│       │   ├── nmap/
│       │   ├── nuclei/
│       │   └── web/
│       ├── core/
│       ├── models/
│       ├── parsers/
│       ├── pipeline/
│       ├── reporting/
│       ├── runners/
│       ├── utils/
│       ├── validators/
│       ├── http_client.py
│       └── orchestrator.py
├── tests/
└── scans/
```

### Important directories

#### `config/profiles/`
Contains ready-to-use operational profiles:
- `passive-stealth`
- `passive-recon-safe`
- `passive-recon-enum`
- `active-aggressive`

#### `src/attack_surface_mapper/pipeline/`
Defines the execution stages.

Current stage order:
1. `NucleiStage`
2. `NmapStage`
3. `BrowserDiscoveryStage`
4. `PassiveValidationStage`
5. `CMSRoutingStage`
6. `CorrelationStage`
7. `ReportingStage`

`CMSRoutingStage` detects CMS families from already observed content and routes
to specialized modules only when there is enough evidence. The first supported
module is WordPress, and the global pipeline stays CMS-agnostic.

#### `src/attack_surface_mapper/collectors/`
Responsible for gathering information from:
- HTTP crawling
- browser discovery
- Nuclei
- Nmap

#### `src/attack_surface_mapper/validators/`
Contains the project-specific validation logic:
- headers
- TLS
- authentication
- admin panels
- APIs
- sensitive files
- discovery
- secrets
- fingerprinting

#### `src/attack_surface_mapper/reporting/`
Builds final reports in different formats.

#### `scans/`
Stores execution results.

---

## Installation

### 1. Create virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 2. Optional: install Playwright browsers

Only needed for the **active dynamic profile**:

```bash
python -m playwright install
```

### 3. External tools required

#### Required
- **Python 3.11+**
- **Nuclei** available in `PATH`
- updated Nuclei templates

#### Optional
- **Nmap** available in `PATH` if you want network reconnaissance
- **Playwright browsers** for dynamic crawling in the active profile

### Docker scanner runtime

For repeatable local runs, especially active profiles that need external tools,
build the bundled scanner image instead of installing Nuclei/Nmap on the host:

```powershell
.\scripts\build_scanner_image.ps1
```

From Windows CMD, use the `.cmd` wrappers:

```cmd
scripts\build_scanner_image.cmd
```

Then run scans through that image:

```powershell
.\scripts\run_scanner_image.ps1 --profile passive-recon-safe --run-name demo_safe http://host.docker.internal:3000
.\scripts\run_scanner_image.ps1 --profile active-aggressive --run-name demo_active http://host.docker.internal:8081
```

```cmd
scripts\run_scanner_image.cmd --profile passive-recon-safe --run-name demo_safe http://host.docker.internal:3000
scripts\run_scanner_image.cmd --profile active-aggressive --run-name demo_active http://host.docker.internal:8081
```

The image includes Python dependencies, Nuclei, Nuclei templates and Nmap.
Project outputs still land in the host `scans/` directory because the repository
is mounted into the container at `/workspace`.

---

## Configuration Model

The tool can be configured in two ways:

### CLI configuration
Useful for direct execution and quick testing.

Examples:
- target passed directly as positional argument
- profile selection with `--profile`
- report format selection
- enabling/disabling modules
- Nmap tuning

### YAML configuration
Profiles and example configurations are stored under:

```text
config/profiles/
config/examples/
```

Important note:

> If a target is passed via CLI, it is added to the targets defined inside the YAML profile and the final list is deduplicated.

This is useful because the tutor can execute the same profile against another target without modifying the YAML.

---

## Main Profiles

The project includes several operational profiles.

### 1. `passive-stealth`
Designed for **very low-noise observation**.

Characteristics:
- no Nuclei
- no Nmap
- no invented baseline probes
- no probing of common hardcoded paths
- only observed navigation and linked resources

Recommended when the goal is to minimise visible activity in logs.

Example:

```bash
python main.py --profile passive-stealth https://example.com/
```

---

### 2. `passive-recon-safe`
Designed for **safe passive reconnaissance**.

Characteristics:
- GET-only
- realistic browsing
- JavaScript hints extraction
- observed surface reuse
- avoids aggressive hardcoded enumeration

Recommended when the goal is to balance:
- coverage
- realism
- moderate noise

Example:

```bash
python main.py --profile passive-recon-safe https://example.com/
```

---

### 3. `passive-recon-enum`
Designed for **visible but controlled enumeration**.

Characteristics:
- GET-only
- expands the observed surface with common endpoint probing
- broader coverage than `passive-recon-safe`
- still below active-aggressive in noise

Recommended when the goal is to enlarge the discovered surface without jumping directly to active mode.

Example:

```bash
python main.py --profile passive-recon-enum https://example.com/
```

---

### 4. `active-aggressive`
Designed for **maximum coverage**.

Characteristics:
- adds Nuclei
- can add Nmap
- deeper validation
- dynamic crawling when available
- highest expected noise

Recommended only when broader visibility matters more than stealth.

Profile file:
```text
config/profiles/active-aggressive.yml
```

CLI equivalent commonly used in this project:
```bash
python main.py --profile active https://example.com/
```

---

## Example Usage

### Simple scan against a single target

```bash
python main.py https://example.com/
```

### Run a safe passive reconnaissance profile

```bash
python main.py --profile passive-recon-safe https://example.com/
```

### Run controlled enumeration

```bash
python main.py --profile passive-recon-enum https://example.com/
```

### Run low-noise profile

```bash
python main.py --profile passive-stealth https://example.com/
```

### Run active profile

```bash
python main.py --profile active https://example.com/
```

### Use a targets file

```bash
python main.py --targets-file targets.txt --profile passive-recon-safe
```

### Use YAML configuration

```bash
python main.py --config config/examples/config.example.yml
```

### Add a CLI target to YAML/profile targets

```bash
python main.py --profile passive-recon-safe https://proba-despregamento.onrender.com/
```

### Run with Nmap enabled

```bash
python main.py https://example.com/ --profile deep --use-nmap --nmap-top-ports 200 --debug
```

---

## Simple Demo Flow

A good way to evaluate the project is to execute these three profiles against the same target:

```bash
python main.py --profile passive-stealth https://TARGET/
python main.py --profile passive-recon-safe https://TARGET/
python main.py --profile passive-recon-enum https://TARGET/
```

Then compare:

- number of visible requests in logs
- whether hardcoded probing appears
- amount of discovered endpoints
- quality and relevance of findings
- difference between safer recon and broader enumeration

This is one of the most important values of the project:
**the ability to control the trade-off between stealth, coverage and signal quality**.

### Repeatable local validation

For quick regression checks of the passive profiles, a local Juice Shop container is a practical baseline:

```bash
docker run -d --rm --name asm-juice -p 3000:3000 bkimminich/juice-shop
python main.py --profile passive-stealth http://localhost:3000
python main.py --profile passive-recon-safe http://localhost:3000
docker stop asm-juice
```

When comparing both runs, start with:

- `run_manifest.json`
- `reports/aggregate_summary.json`
- `targets/.../reports/report.summary.json`

For a repeatable PowerShell flow on Windows:

```powershell
.\scripts\validate_labs.ps1 -Labs juice-shop
.\scripts\validate_labs.ps1 -Labs juice-shop -IncludeEnum
```

The script now validates the generated `run_manifest.json`, `aggregate_summary.json`
and `report.summary.json`, and it accepts `-MinFindings` to require a minimum number
of correlated findings per run.
It also exports `reviews/lab_findings_review.csv` so you can label findings as
`verdadero`, `falso` or `dudoso` during false-positive review.
When `-IncludeEnum` is enabled, the script uses
`config/examples/lab-passive-recon-enum.yml` so the enum profile stays reproducible
in Docker without depending on a host-side Nuclei install.

### Repeatable local Elasticsearch validation

To validate the current Elasticsearch integration end-to-end in a repeatable way:

```powershell
.\scripts\validate_elasticsearch_local.ps1
```

On Linux/macOS, use the shell wrapper if PowerShell 7+ (`pwsh`) is available:

```bash
sh ./scripts/validate_elasticsearch_local.sh
```

The helper:
- starts a local single-node Elasticsearch container
- starts Juice Shop locally
- runs a passive scan against Juice Shop
- exports the resulting run with `scripts/export_elasticsearch_bundle.py`
- creates the three indices and ingests the generated NDJSON
- verifies counts and the expected finding contract fields
- reingests the same bundle to confirm stable `_id` behaviour
- deletes and recreates the indices to confirm the exported mappings are sufficient

Useful options:

```powershell
.\scripts\validate_elasticsearch_local.ps1 -RunName es_demo_1 -IndexPrefix asm-demo
.\scripts\validate_elasticsearch_local.ps1 -KeepElasticsearchRunning -KeepLabRunning
.\scripts\validate_elasticsearch_local.ps1 -ElasticsearchHostPort 19200 -ElasticsearchUrl http://localhost:19200
.\scripts\validate_elasticsearch_local.ps1 -LabHostPort 13000 -Target http://host.docker.internal:13000
.\scripts\validate_elasticsearch_local.ps1 -ElasticsearchUsername elastic -ElasticsearchPassword changeme
.\scripts\validate_elasticsearch_local.ps1 -ElasticsearchApiKey <api-key>
```

For Linux Docker engines where `host.docker.internal` is not provided by default,
add Docker's host gateway mapping:

```powershell
.\scripts\validate_elasticsearch_local.ps1 -AddHostGateway
```

The script keeps all project paths relative to the repository and exposes the
main environment knobs as parameters: Docker CLI path, images, container names,
ports, scan target, Elasticsearch URL and optional authentication.

---

## Output Structure

Each execution creates a run directory similar to:

```text
scans/
  2026-03-28_142330/
    run_manifest.json
    reports/
      aggregate_summary.json
      aggregate_report.md
      aggregate_findings.csv
    targets/
      https_example.com_/
        findings/
          vulnerabilities.json
        reports/
          report.md
          report.html
          report.csv
          report.summary.json
        artifacts/
          nuclei_raw.jsonl
          nmap_raw.xml
        debug/
          debug_http_trace.json
          debug_probe.json
          debug_counts.json
```

### Run-level outputs
Available at the root of each run:
- `run_manifest.json`
- `reports/aggregate_summary.json`
- `reports/aggregate_report.md`
- `reports/aggregate_findings.csv`
- `elasticsearch/` after running the export helper

### Target-level outputs
Available per target:
- `findings/vulnerabilities.json`
- `reports/report.*`
- `debug/debug_http_trace.json`
- `debug/debug_probe.json`
- `debug/debug_counts.json`

### Discovery metadata
`run_manifest.json` also captures useful execution metadata such as:
- executed stages
- collectors used
- observed URLs
- observed actions count
- observed API calls

---

## Which Reports to Review

### 1. `reports/aggregate_report.md`
Best file for a quick human-readable overview of the whole run.

### 2. `reports/aggregate_summary.json`
Useful for structured review and automation.

### 3. `targets/.../findings/vulnerabilities.json`
Contains the final structured findings per target.

### 4. `run_manifest.json`
Useful to understand:
- which stages ran
- which collectors were used
- what was actually observed

### 5. console logs
Very useful to compare how noisy each profile is.

### 6. `elasticsearch/`
Optional post-scan bundle for Elasticsearch ingestion.
It is generated from an existing run and includes:
- index mappings
- `_bulk` NDJSON exports
- helper flows for manual/Kibana Dev Tools, `curl` and Python

Example:

```bash
python scripts/export_elasticsearch_bundle.py --run-dir scans/lab_juice_shop_passive_recon_enum
```

This creates:

```text
scans/<run>/elasticsearch/
  findings_mapping.json
  summaries_mapping.json
  runs_mapping.json
  findings_bulk.ndjson
  summaries_bulk.ndjson
  runs_bulk.ndjson
  manual_kibana_devtools.md
  ingest_with_curl.sh
  ingest_with_python.py
  export_manifest.json
```

Default indices:
- `attack-surface-mapper-findings`
- `attack-surface-mapper-summaries`
- `attack-surface-mapper-runs`

You can change the prefix with:

```bash
python scripts/export_elasticsearch_bundle.py --run-dir scans/<run> --index-prefix asm-demo
```

---

## What Makes the Project Valuable

This project is valuable because it is not limited to raw scanner execution.

It adds:
- an explicit pipeline
- operational profiles
- reusable discovery surface
- custom validation modules
- output normalisation
- finding correlation
- human-oriented reporting
- machine-readable artefacts
- lower-noise recon modes
- progressive escalation from stealth to active analysis

In practice, this makes it useful both as:
- a technical project with real engineering depth
- an operational prototype for attack-surface analysis

---

## Recommended Files for the Reviewer

If someone wants to understand the project quickly, the best order is:

1. `README.md`
2. `docs/PROFILES.md`
3. `docs/PIPELINE.md`
4. `docs/OUTPUTS.md`
5. `CHANGELOG.md`

---

## Notes

- Passive profiles do **not** require Playwright browsers.
- Active dynamic mode may require `python -m playwright install`.
- Nmap is optional.
- CLI target input is combined with YAML targets and deduplicated.
- The active YAML profile file is called `active-aggressive.yml`; the CLI accepts both `active` and `active-aggressive`.

---

## Changelog

For the full technical evolution of the project, see:

```text
CHANGELOG.md
```
