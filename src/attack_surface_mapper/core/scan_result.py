from __future__ import annotations

from dataclasses import dataclass, field

from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.reporting.generator import ReportPaths


@dataclass(slots=True)
class ScanResult:
    target: str
    vulnerabilities: list[Vulnerability]
    command: list[str]
    return_code: int
    stdout: str
    stderr: str
    raw_findings_count: int
    output_json_path: str | None
    raw_output_path: str | None
    summary: dict[str, int]
    discovered_urls: list[str] = field(default_factory=list)
    report_paths: ReportPaths = field(default_factory=ReportPaths)
    comparison: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    debug_counts: dict[str, int] = field(default_factory=dict)
    debug_probe: dict = field(default_factory=dict)
    debug_http_trace: list[dict] = field(default_factory=list)
    nmap_command: list[str] = field(default_factory=list)
    nmap_return_code: int | None = None
    nmap_stdout: str = ''
    nmap_stderr: str = ''
    stages_executed: list[str] = field(default_factory=list)
    collectors_used: list[str] = field(default_factory=list)
    observed_urls: list[str] = field(default_factory=list)
    observed_actions: list[dict] = field(default_factory=list)
    observed_api_calls: list[str] = field(default_factory=list)
