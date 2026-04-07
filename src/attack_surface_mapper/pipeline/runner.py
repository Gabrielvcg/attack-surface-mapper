from __future__ import annotations

from attack_surface_mapper.core import ScanContext, ScanOutputs, ScanSettings
from attack_surface_mapper.core import ScanResult
from attack_surface_mapper.pipeline.stages import BrowserDiscoveryStage, CorrelationStage, NmapStage, NucleiStage, PassiveValidationStage, ReportingStage


class ScanPipeline:
    """Pipeline-oriented scan runner with explicit stages and shared ScanContext."""

    def __init__(self) -> None:
        self.stages = [
            NucleiStage(),
            NmapStage(),
            BrowserDiscoveryStage(),
            PassiveValidationStage(),
            CorrelationStage(),
            ReportingStage(),
        ]

    def run(self, *, target: str, settings: ScanSettings, outputs: ScanOutputs) -> ScanResult:
        context = ScanContext(target=target, settings=settings, outputs=outputs)
        for stage in self.stages:
            context = stage.run(context)
        return ScanResult(
            target=context.target,
            vulnerabilities=context.findings,
            command=context.artifacts.nuclei_command,
            return_code=context.artifacts.nuclei_return_code,
            stdout=context.artifacts.nuclei_stdout,
            stderr=context.artifacts.nuclei_stderr,
            raw_findings_count=len(context.artifacts.nuclei_raw_findings),
            output_json_path=context.outputs.output_json_path,
            raw_output_path=context.outputs.raw_output_jsonl,
            summary=context.summary,
            discovered_urls=context.artifacts.discovered_urls,
            report_paths=context.report_paths,
            comparison=context.comparison,
            debug_counts=context.debug.counts,
            debug_probe=context.debug.probe,
            debug_http_trace=context.debug.http_trace,
            nmap_command=context.artifacts.nmap_command,
            nmap_return_code=context.artifacts.nmap_return_code,
            nmap_stdout=context.artifacts.nmap_stdout,
            nmap_stderr=context.artifacts.nmap_stderr,
            stages_executed=list(context.debug.stages_executed),
            collectors_used=list(context.debug.collectors_used),
            observed_urls=sorted(context.observed_urls),
            observed_actions=list(context.observed_actions),
            observed_api_calls=sorted(context.observed_api_calls),
        )
