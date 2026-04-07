from __future__ import annotations

from collections import Counter
from urllib.parse import urlparse

from attack_surface_mapper.analysis import compare_scans, correlate_vulnerabilities, enrich_vulnerabilities, load_previous_scan
from attack_surface_mapper.collectors.crawling import BrowserDiscoveryCollector, CrawlerCollector
from attack_surface_mapper.collectors.nmap import NmapCollector
from attack_surface_mapper.collectors.nuclei import NucleiCollector
from attack_surface_mapper.collectors.web import RequestError, get_debug_trace, http_get, reset_debug_trace, set_debug_trace_enabled
from attack_surface_mapper.core import ScanContext
from attack_surface_mapper.reporting import ReportGenerator
from attack_surface_mapper.utils.io import save_vulnerabilities_json
from attack_surface_mapper.validators.api_validator import APIValidator
from attack_surface_mapper.validators.auth_validator import AuthValidator
from attack_surface_mapper.validators.debug_probe import probe_target
from attack_surface_mapper.validators.discovery import analyse_documents, findings_from_analysis
from attack_surface_mapper.validators.fingerprint_validator import FingerprintValidator
from attack_surface_mapper.validators.headers_validator import HeadersValidator
from attack_surface_mapper.validators.panels_validator import PanelsValidator
from attack_surface_mapper.validators.secrets_validator import SecretsValidator
from attack_surface_mapper.validators.sensitive_files_validator import SensitiveFilesValidator
from attack_surface_mapper.validators.tls_validator import TLSValidator


class PipelineStage:
    name = 'stage'

    def run(self, context: ScanContext) -> ScanContext:  # pragma: no cover - interface only
        return context


class NucleiStage(PipelineStage):
    name = 'nuclei'

    def __init__(self, collector: NucleiCollector | None = None) -> None:
        self.collector = collector or NucleiCollector()

    def run(self, context: ScanContext) -> ScanContext:
        if not context.settings.run_nuclei:
            context.debug.counts[self.name] = 0
            return context
        context.mark_stage(self.name)
        context.mark_collector('nuclei')
        vulns, raw_findings, stdout, stderr, return_code, command = self.collector.collect(
            target=context.target,
            severity=tuple(context.settings.severity),
            tags=tuple(context.settings.tags) if context.settings.tags else None,
            templates=context.settings.templates,
            rate_limit=context.settings.rate_limit,
            timeout_seconds=context.settings.timeout_seconds,
            retries=context.settings.retries,
            follow_redirects=context.settings.follow_redirects,
            raw_output_jsonl=context.outputs.raw_output_jsonl,
            include_raw=context.settings.include_raw,
        )
        context.artifacts.nuclei_stdout = stdout
        context.artifacts.nuclei_stderr = stderr
        context.artifacts.nuclei_return_code = return_code
        context.artifacts.nuclei_command = command
        context.artifacts.nuclei_raw_findings = raw_findings
        context.add_findings(vulns)
        context.debug.counts[self.name] = len(vulns)
        return context


class NmapStage(PipelineStage):
    name = 'nmap'

    def __init__(self, collector: NmapCollector | None = None) -> None:
        self.collector = collector or NmapCollector()

    def run(self, context: ScanContext) -> ScanContext:
        if not context.settings.run_nmap:
            context.debug.counts[self.name] = 0
            return context
        context.mark_stage(self.name)
        context.mark_collector('nmap')
        vulns, stdout, stderr, return_code, command = self.collector.collect(
            target=context.target,
            top_ports=context.settings.nmap_top_ports,
            extra_args=tuple(context.settings.nmap_args or ()),
            xml_output_path=context.outputs.nmap_xml_output,
            include_raw=context.settings.include_raw,
            timing_template=context.settings.nmap_timing_template,
        )
        context.artifacts.nmap_stdout = stdout
        context.artifacts.nmap_stderr = stderr
        context.artifacts.nmap_return_code = return_code
        context.artifacts.nmap_command = command
        context.add_findings(vulns)
        context.debug.counts[self.name] = len(vulns)
        return context



class BrowserDiscoveryStage(PipelineStage):
    name = 'browser_discovery'

    def run(self, context: ScanContext) -> ScanContext:
        s = context.settings
        if not s.run_crawl or not s.browser_discovery_enabled:
            context.debug.counts[self.name] = 0
            return context
        context.mark_stage(self.name)
        collector_backend = (s.crawler_backend or s.http_backend)
        context.mark_collector(f"browser:{collector_backend}")
        try:
            collector = BrowserDiscoveryCollector(
                timeout=s.validator_timeout,
                max_pages=max(1, s.crawl_max_pages),
                max_depth=max(0, s.crawl_max_depth),
                include_js=s.crawl_include_js,
                user_agent=s.user_agent,
                backend=collector_backend,
                mode=s.http_mode,
                scrapling_mode=s.crawler_scrapling_mode,
                click_budget=s.browser_click_budget,
            )
            result = collector.collect(context.target)
        except Exception as exc:
            context.debug.http_trace.append({'component': 'browser_discovery', 'event': 'collector_error', 'error': str(exc)})
            result = None
        if result is None:
            context.debug.counts[self.name] = 0
            return context
        context.artifacts.crawled_documents = result.documents
        context.artifacts.discovery_analysis = result.analysis
        context.artifacts.entry_response = getattr(result, 'entry_response', None)
        context.artifacts.discovered_urls = list(result.observed_urls)
        context.artifacts.observed_actions = list(result.observed_actions)
        context.artifacts.observed_api_calls = list(result.observed_api_calls)
        for url in result.observed_urls:
            context.add_observed(url)
        for action in result.observed_actions:
            context.add_action(action)
        for api_url in result.observed_api_calls:
            context.add_api_call(api_url)
        context.debug.counts[self.name] = len(result.observed_urls) + len(result.observed_api_calls)
        return context

class PassiveValidationStage(PipelineStage):
    name = 'passive_validation'

    def run(self, context: ScanContext) -> ScanContext:
        s = context.settings
        if not any((s.run_headers, s.run_tls, s.run_fingerprint, s.run_sensitive_files, s.run_panels, s.run_auth, s.run_api, s.run_secrets, s.run_crawl)):
            context.debug.counts[self.name] = 0
            return context
        context.mark_stage(self.name)
        context.mark_collector(context.settings.http_backend or 'requests')
        context.debug.enabled = bool(s.debug)
        set_debug_trace_enabled(bool(s.debug))
        reset_debug_trace()

        preloaded_response = None
        if s.observed_only:
            preloaded_response = context.artifacts.entry_response
            if preloaded_response is not None:
                context.add_observed(preloaded_response.url)
            else:
                try:
                    preloaded_response = http_get(context.target, timeout=s.validator_timeout, allow_redirects=True, user_agent=s.user_agent, backend=s.http_backend, mode=s.http_mode)
                    context.add_observed(preloaded_response.url)
                except RequestError:
                    preloaded_response = None

        def _safe_collect(name: str, fn) -> None:
            try:
                items = fn() or []
            except RequestError:
                items = []
            context.debug.counts[name] = len(items)
            context.add_findings(items)

        if s.run_headers:
            _safe_collect('headers', lambda: HeadersValidator(timeout=s.validator_timeout, backend=s.http_backend, mode=s.http_mode, user_agent=s.user_agent).run(context.target, response=preloaded_response))
        if s.run_tls:
            try:
                items = TLSValidator(timeout=s.validator_timeout).run(context.target)
            except Exception:
                items = []
            context.debug.counts['tls'] = len(items)
            context.add_findings(items)
        _safe_collect('fingerprint', lambda: FingerprintValidator(timeout=s.validator_timeout, backend=s.http_backend, mode=s.http_mode, user_agent=s.user_agent).run(context.target, response=preloaded_response))
        if s.run_sensitive_files:
            _safe_collect('sensitive_files', lambda: SensitiveFilesValidator(timeout=max(3, min(s.validator_timeout, 6)), backend=s.http_backend, mode=s.http_mode, user_agent=s.user_agent, use_baseline_probe=s.baseline_probe).run(context.target))

        crawled_documents: dict[str, str] = context.artifacts.crawled_documents or {}
        if s.run_crawl and not crawled_documents and not s.observed_only:
            try:
                crawler = CrawlerCollector(timeout=s.validator_timeout, max_pages=max(1, s.crawl_max_pages), max_depth=max(0, s.crawl_max_depth), include_js=s.crawl_include_js, user_agent=s.user_agent, backend=(s.crawler_backend or s.http_backend), mode=s.http_mode, scrapling_mode=s.crawler_scrapling_mode)
                crawled_documents = crawler.crawl(context.target)
            except RequestError:
                crawled_documents = {}
            context.artifacts.crawled_documents = crawled_documents
        discovery_analysis = context.artifacts.discovery_analysis or (analyse_documents(context.target, crawled_documents) if crawled_documents else analyse_documents(context.target, {}))
        context.artifacts.discovery_analysis = discovery_analysis
        context.artifacts.discovered_urls = discovery_analysis.discovered_urls
        for url in discovery_analysis.discovered_urls:
            context.add_observed(url)

        observed_auth_paths = [urlparse(u).path for u in sorted(context.observed_urls) if any(tok in (urlparse(u).path or '').lower() for tok in ('login','admin','dashboard','metrics','graphql','api-docs','swagger','auth','rest'))]
        observed_api_paths = [urlparse(u).path for u in sorted(context.observed_api_calls) if any(tok in (urlparse(u).path or '').lower() for tok in ('/api/','/rest/','graphql','swagger','openapi','api-docs','metrics'))]
        enum_mode = not s.observed_only
        if s.run_panels:
            seed_panel_paths = tuple(s.panel_paths) if s.panel_paths else ()
            effective_panel_paths = tuple(dict.fromkeys([*seed_panel_paths, *discovery_analysis.panel_paths, *(observed_auth_paths if s.observed_only else ())])) or None
            _safe_collect('panels', lambda: PanelsValidator(timeout=max(3, min(s.validator_timeout, 6)), paths=effective_panel_paths, backend=s.http_backend, mode=s.http_mode, user_agent=s.user_agent, use_baseline_probe=s.baseline_probe).run(context.target))
        if s.run_auth:
            auth_seed = AuthValidator.DEFAULT_PROTECTED_PATHS if enum_mode else ()
            effective_auth_paths = tuple(dict.fromkeys([*auth_seed, *discovery_analysis.auth_paths, *observed_auth_paths]))
            _safe_collect('auth', lambda: AuthValidator(timeout=max(3, min(s.validator_timeout, 6)), paths=effective_auth_paths, backend=s.http_backend, mode=s.http_mode, user_agent=s.user_agent, use_baseline_probe=s.baseline_probe, observed_only=s.observed_only).run(context.target))
        if s.run_api:
            api_seed = APIValidator.DEFAULT_PATHS if enum_mode else ()
            effective_api_paths = tuple(dict.fromkeys([*api_seed, *discovery_analysis.api_paths, *observed_api_paths]))
            _safe_collect('api', lambda: APIValidator(timeout=max(3, min(s.validator_timeout, 6)), paths=effective_api_paths, backend=s.http_backend, mode=s.http_mode, user_agent=s.user_agent, use_baseline_probe=s.baseline_probe, observed_only=s.observed_only).run(context.target))

        discovery_findings = findings_from_analysis(context.target, discovery_analysis)
        context.debug.counts['discovery'] = len(discovery_findings)
        context.add_findings(discovery_findings)

        if s.run_secrets and not s.observed_only and crawled_documents:
            try:
                items = SecretsValidator().run(context.target, crawled_documents)
            except Exception:
                items = []
            context.debug.counts['secrets'] = len(items)
            context.add_findings(items)
        else:
            context.debug.counts.setdefault('secrets', 0)

        if s.debug and not s.observed_only:
            try:
                context.debug.probe = probe_target(context.target, timeout=max(3, min(s.validator_timeout, 6)), backend=s.http_backend, mode=s.http_mode, user_agent=s.user_agent)
            except Exception:
                context.debug.probe = {}

        context.debug.counts['crawl_urls'] = len(context.artifacts.discovered_urls)
        context.debug.counts['crawl_candidate_paths'] = len(discovery_analysis.candidate_paths)
        context.debug.counts['crawl_forms'] = len(discovery_analysis.forms)
        context.debug.counts['crawl_js_hints'] = len(discovery_analysis.js_hints)
        context.debug.http_trace = get_debug_trace()
        return context


class CorrelationStage(PipelineStage):
    name = 'correlation'

    @staticmethod
    def _deduplicate(findings):
        deduped = []
        seen = set()
        for vuln in findings:
            key = vuln.dedup_key()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(vuln)
        return deduped

    @staticmethod
    def _summarise(vulnerabilities):
        order = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
        counts = Counter(v.priority or v.severity.lower() for v in vulnerabilities)
        return {severity: counts[severity] for severity in order if counts.get(severity, 0) > 0}

    def run(self, context: ScanContext) -> ScanContext:
        deduped = self._deduplicate(context.findings)
        context.debug.counts['after_dedup'] = len(deduped)
        enriched = enrich_vulnerabilities(deduped)
        context.debug.counts['after_enrich'] = len(enriched)
        correlated = correlate_vulnerabilities(enriched)
        context.debug.counts['after_correlation'] = len(correlated)
        context.findings = correlated
        context.summary = self._summarise(context.findings)
        if context.settings.compare_with_json:
            context.comparison = compare_scans(context.findings, load_previous_scan(context.settings.compare_with_json))
        return context


class ReportingStage(PipelineStage):
    name = 'reporting'

    def run(self, context: ScanContext) -> ScanContext:
        if context.outputs.output_json_path:
            save_vulnerabilities_json(context.findings, context.outputs.output_json_path)
        if any([
            context.outputs.report_markdown,
            context.outputs.report_html,
            context.outputs.report_csv,
            context.outputs.report_summary_json,
            context.outputs.report_comparison_json,
        ]):
            context.report_paths = ReportGenerator(title=context.settings.report_title).generate_all(
                context.findings,
                context.target,
                markdown_path=context.outputs.report_markdown,
                html_path=context.outputs.report_html,
                csv_path=context.outputs.report_csv,
                summary_json_path=context.outputs.report_summary_json,
                comparison_json_path=context.outputs.report_comparison_json,
                comparison=context.comparison,
            )
        return context
