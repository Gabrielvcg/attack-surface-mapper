from __future__ import annotations

from typing import Sequence

from attack_surface_mapper.core import ScanOutputs, ScanResult, ScanSettings
from attack_surface_mapper.pipeline.runner import ScanPipeline
from attack_surface_mapper.reporting import ReportPaths




class ScanOrchestrator:
    """Compatibility facade over the newer pipeline-based execution model."""

    def __init__(self, pipeline: ScanPipeline | None = None) -> None:
        self.pipeline = pipeline or ScanPipeline()

    def scan_target(
        self,
        target: str,
        severity: Sequence[str] = ('medium', 'high', 'critical'),
        tags: Sequence[str] | None = None,
        templates: str | None = None,
        rate_limit: int | None = 150,
        timeout_seconds: int | None = 10,
        retries: int | None = 1,
        follow_redirects: bool = True,
        output_json: str | None = None,
        raw_output_jsonl: str | None = None,
        include_raw: bool = False,
        compare_with_json: str | None = None,
        run_headers: bool = True,
        run_fingerprint: bool = True,
        run_panels: bool = True,
        run_tls: bool = True,
        run_crawl: bool = True,
        run_secrets: bool = True,
        run_auth: bool = True,
        run_api: bool = True,
        run_sensitive_files: bool = True,
        validator_timeout: int = 8,
        crawl_max_pages: int = 20,
        crawl_max_depth: int = 2,
        crawl_include_js: bool = False,
        panel_paths: Sequence[str] | None = None,
        http_backend: str = 'auto',
        crawler_backend: str | None = None,
        crawler_scrapling_mode: str = 'auto',
        http_mode: str = 'passive',
        report_title: str = 'Informe de vulnerabilidades y misconfiguraciones',
        run_nuclei: bool = True,
        user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        baseline_probe: bool = True,
        observed_only: bool = False,
        browser_click_budget: int = 12,
        browser_discovery_enabled: bool = True,
        run_cms_detection: bool = True,
        report_markdown: str | None = None,
        report_html: str | None = None,
        report_csv: str | None = None,
        report_summary_json: str | None = None,
        report_comparison_json: str | None = None,
        run_nmap: bool = False,
        nmap_top_ports: int = 100,
        nmap_args: Sequence[str] | None = None,
        nmap_xml_output: str | None = None,
        nmap_timing_template: str | None = None,
        debug: bool = False,
    ) -> ScanResult:
        settings = ScanSettings(
            severity=tuple(severity),
            tags=tuple(tags) if tags else None,
            templates=templates,
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
            retries=retries,
            follow_redirects=follow_redirects,
            include_raw=include_raw,
            compare_with_json=compare_with_json,
            run_nuclei=run_nuclei,
            run_nmap=run_nmap,
            nmap_top_ports=nmap_top_ports,
            nmap_args=tuple(nmap_args) if nmap_args else None,
            nmap_timing_template=nmap_timing_template,
            run_headers=run_headers,
            run_fingerprint=run_fingerprint,
            run_panels=run_panels,
            run_tls=run_tls,
            run_crawl=run_crawl,
            run_secrets=run_secrets,
            run_auth=run_auth,
            run_api=run_api,
            run_sensitive_files=run_sensitive_files,
            validator_timeout=validator_timeout,
            crawl_max_pages=crawl_max_pages,
            crawl_max_depth=crawl_max_depth,
            crawl_include_js=crawl_include_js,
            panel_paths=tuple(panel_paths) if panel_paths else None,
            http_backend=http_backend,
            crawler_backend=crawler_backend,
            crawler_scrapling_mode=crawler_scrapling_mode,
            http_mode=http_mode,
            user_agent=user_agent,
            baseline_probe=baseline_probe,
            observed_only=observed_only,
            browser_click_budget=browser_click_budget,
            browser_discovery_enabled=browser_discovery_enabled,
            run_cms_detection=run_cms_detection,
            debug=debug,
            report_title=report_title,
        )
        outputs = ScanOutputs(
            output_json_path=output_json,
            raw_output_jsonl=raw_output_jsonl,
            report_markdown=report_markdown,
            report_html=report_html,
            report_csv=report_csv,
            report_summary_json=report_summary_json,
            report_comparison_json=report_comparison_json,
            nmap_xml_output=nmap_xml_output,
        )
        return self.pipeline.run(target=target, settings=settings, outputs=outputs)
