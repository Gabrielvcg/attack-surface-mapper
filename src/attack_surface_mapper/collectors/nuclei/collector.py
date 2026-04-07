from __future__ import annotations

from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.parsers.nuclei_parser import NucleiParser
from attack_surface_mapper.runners.nuclei_runner import NucleiRunConfig, NucleiRunner


class NucleiCollector:
    """Wrapper that executes Nuclei and normalises output into the common model."""

    def __init__(self, runner: NucleiRunner | None = None, parser: NucleiParser | None = None) -> None:
        self.runner = runner or NucleiRunner()
        self.parser = parser or NucleiParser()

    def collect(self, *, target: str, severity: tuple[str, ...] | list[str], tags: tuple[str, ...] | None = None,
                templates: str | None = None, rate_limit: int | None = 150, timeout_seconds: int | None = 10,
                retries: int | None = 1, follow_redirects: bool = True, raw_output_jsonl: str | None = None,
                include_raw: bool = False) -> tuple[list[Vulnerability], list[dict[str, object]], str, str, int, list[str]]:
        config = NucleiRunConfig(
            target=target,
            severity=severity,
            tags=tags,
            templates=templates,
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
            retries=retries,
            follow_redirects=follow_redirects,
            jsonl_output_path=raw_output_jsonl,
        )
        stdout, stderr, return_code, command = self.runner.run(config)
        raw_findings = self.parser.parse_jsonl(stdout)
        vulnerabilities = self.parser.to_vulnerabilities(raw_findings, include_raw=include_raw)
        return vulnerabilities, raw_findings, stdout, stderr, return_code, command
