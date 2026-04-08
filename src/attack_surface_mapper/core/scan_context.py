from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.reporting.generator import ReportPaths


@dataclass(slots=True)
class ScanArtifacts:
    nuclei_stdout: str = ''
    nuclei_stderr: str = ''
    nuclei_command: list[str] = field(default_factory=list)
    nuclei_return_code: int = 0
    nuclei_raw_findings: list[dict[str, Any]] = field(default_factory=list)

    nmap_stdout: str = ''
    nmap_stderr: str = ''
    nmap_command: list[str] = field(default_factory=list)
    nmap_return_code: int | None = None

    discovered_urls: list[str] = field(default_factory=list)
    crawled_documents: dict[str, str] = field(default_factory=dict)
    discovery_analysis: Any | None = None
    observed_actions: list[dict[str, Any]] = field(default_factory=list)
    observed_api_calls: list[str] = field(default_factory=list)
    entry_response: Any | None = None
    shared_baseline: Any | None = None


@dataclass(slots=True)
class ScanDebug:
    enabled: bool = False
    counts: dict[str, int] = field(default_factory=dict)
    probe: dict[str, Any] = field(default_factory=dict)
    http_trace: list[dict[str, Any]] = field(default_factory=list)
    stages_executed: list[str] = field(default_factory=list)
    collectors_used: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanOutputs:
    output_json_path: str | None = None
    raw_output_jsonl: str | None = None
    report_markdown: str | None = None
    report_html: str | None = None
    report_csv: str | None = None
    report_summary_json: str | None = None
    report_comparison_json: str | None = None
    nmap_xml_output: str | None = None


@dataclass(slots=True)
class ScanSettings:
    severity: Sequence[str] = ('medium', 'high', 'critical')
    tags: Sequence[str] | None = None
    templates: str | None = None
    rate_limit: int | None = 150
    timeout_seconds: int | None = 10
    retries: int | None = 1
    follow_redirects: bool = True
    include_raw: bool = False
    compare_with_json: str | None = None

    run_nuclei: bool = True
    run_nmap: bool = False
    nmap_top_ports: int = 100
    nmap_args: Sequence[str] | None = None
    nmap_timing_template: str | None = None

    run_headers: bool = True
    run_fingerprint: bool = True
    run_panels: bool = True
    run_tls: bool = True
    run_crawl: bool = True
    run_secrets: bool = True
    run_auth: bool = True
    run_api: bool = True
    run_sensitive_files: bool = True

    validator_timeout: int = 8
    crawl_max_pages: int = 20
    crawl_max_depth: int = 2
    crawl_include_js: bool = False
    panel_paths: Sequence[str] | None = None
    http_backend: str = 'auto'
    crawler_backend: str | None = None
    crawler_scrapling_mode: str = 'auto'
    http_mode: str = 'passive'
    user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'
    baseline_probe: bool = True
    observed_only: bool = False
    debug: bool = False

    report_title: str = 'Informe de vulnerabilidades y misconfiguraciones'
    browser_click_budget: int = 12
    browser_discovery_enabled: bool = True


@dataclass(slots=True)
class ScanContext:
    target: str
    settings: ScanSettings = field(default_factory=ScanSettings)
    outputs: ScanOutputs = field(default_factory=ScanOutputs)
    artifacts: ScanArtifacts = field(default_factory=ScanArtifacts)
    debug: ScanDebug = field(default_factory=ScanDebug)
    findings: list[Vulnerability] = field(default_factory=list)
    comparison: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    summary: dict[str, int] = field(default_factory=dict)
    report_paths: ReportPaths = field(default_factory=ReportPaths)
    observed_urls: set[str] = field(default_factory=set)
    observed_actions: list[dict[str, Any]] = field(default_factory=list)
    observed_api_calls: set[str] = field(default_factory=set)

    def add_findings(self, items: Sequence[Vulnerability]) -> None:
        if items:
            self.findings.extend(items)


    def add_observed(self, url: str) -> None:
        if url:
            self.observed_urls.add(url)

    def add_action(self, action: dict[str, Any]) -> None:
        if action:
            self.observed_actions.append(action)

    def add_api_call(self, url: str) -> None:
        if url:
            self.observed_api_calls.add(url)

    def mark_stage(self, name: str) -> None:
        if name and name not in self.debug.stages_executed:
            self.debug.stages_executed.append(name)

    def mark_collector(self, name: str) -> None:
        if name and name not in self.debug.collectors_used:
            self.debug.collectors_used.append(name)
