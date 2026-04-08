from __future__ import annotations

from attack_surface_mapper.http_client import HttpResponse, add_debug_trace
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.pipeline.stages import BrowserDiscoveryStage, PassiveValidationStage
from attack_surface_mapper.reporting.generator import ReportGenerator
from attack_surface_mapper.core.scan_context import ScanContext, ScanOutputs, ScanSettings
from main import build_arg_parser, resolve_targets


def test_debug_trace_keeps_browser_events_across_passive_validation(monkeypatch) -> None:
    entry_response = HttpResponse(
        status_code=200,
        url='https://target.example/',
        headers={'Content-Type': 'text/html'},
        text='<html><title>home</title></html>',
        content=b'<html><title>home</title></html>',
    )

    class DummyCollector:
        def __init__(self, *args, **kwargs):
            pass

        def collect(self, target):
            add_debug_trace({'component': 'browser_discovery', 'event': 'dummy_collect', 'target': target})
            class DummyResult:
                documents = {'https://target.example/': '<html><title>home</title></html>'}
                observed_urls = ['https://target.example/']
                observed_actions = []
                observed_api_calls = []
                analysis = None

            result = DummyResult()
            result.entry_response = entry_response
            return result

    monkeypatch.setattr('attack_surface_mapper.pipeline.stages.BrowserDiscoveryCollector', DummyCollector)

    settings = ScanSettings(
        debug=True,
        run_crawl=True,
        browser_discovery_enabled=True,
        observed_only=True,
        run_headers=True,
        run_tls=False,
        run_sensitive_files=False,
        run_panels=False,
        run_auth=False,
        run_api=False,
        run_secrets=False,
    )
    ctx = ScanContext(target='https://target.example/', settings=settings, outputs=ScanOutputs())

    BrowserDiscoveryStage().run(ctx)
    PassiveValidationStage().run(ctx)

    assert any(event.get('event') == 'dummy_collect' for event in ctx.debug.http_trace)


def test_executive_summary_reflects_confirmed_high_findings() -> None:
    vuln = Vulnerability(
        source='custom-api-check',
        title='GraphQL Surface Exposed',
        description='d',
        severity='high',
        target='https://target.example/graphql',
        matched_at='https://target.example/graphql',
        category='api',
        priority='high',
        confidence='high',
        verification_status='confirmed',
        evidence_summary='graphql marker',
        kind='validation',
        asset_host='target.example',
        asset_port='443',
    )

    payload = ReportGenerator().build_summary_payload([vuln], 'https://target.example/')

    assert 'Se observaron 1 hallazgos confirmados de prioridad alta o crítica.' in payload['executive_summary']
    assert payload['top_findings'][0]['kind'] == 'validation'
    assert payload['top_findings'][0]['confidence'] == 'high'
    assert payload['top_findings'][0]['asset_host'] == 'target.example'
    assert payload['top_findings'][0]['evidence_summary'] == 'graphql marker'


def test_cli_targets_are_combined_with_yaml_targets_and_deduplicated() -> None:
    args = build_arg_parser().parse_args(['https://cli.example'])

    targets = resolve_targets(args, {'targets': ['https://yaml.example', 'https://cli.example']})

    assert targets == ['https://cli.example', 'https://yaml.example']
