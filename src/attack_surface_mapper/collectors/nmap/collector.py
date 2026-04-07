from __future__ import annotations

from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.parsers.nmap_parser import NmapParser
from attack_surface_mapper.runners.nmap_runner import NmapRunConfig, NmapRunner


class NmapCollector:
    """Wrapper around Nmap execution and mapping to the common model."""

    def __init__(self, runner: NmapRunner | None = None, parser: NmapParser | None = None) -> None:
        self.runner = runner or NmapRunner()
        self.parser = parser or NmapParser()

    def collect(self, *, target: str, top_ports: int = 100, extra_args: tuple[str, ...] | list[str] | None = None,
                xml_output_path: str | None = None, include_raw: bool = False,
                timing_template: str | None = None) -> tuple[list[Vulnerability], str, str, int | None, list[str]]:
        stdout, stderr, return_code, command = self.runner.run(NmapRunConfig(
            target=target,
            top_ports=top_ports,
            extra_args=tuple(extra_args or ()),
            xml_output_path=xml_output_path,
            timing_template=timing_template,
        ))
        vulnerabilities = self.parser.to_vulnerabilities(target, stdout, include_raw=include_raw)
        return vulnerabilities, stdout, stderr, return_code, command
