from __future__ import annotations

from attack_surface_mapper.analysis.enrichment import enrich_vulnerabilities
from attack_surface_mapper.batch.aggregate import build_aggregate_payload
from attack_surface_mapper.core.scan_context import ScanContext, ScanOutputs, ScanSettings
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.orchestrator import ScanResult
from attack_surface_mapper.pipeline.stages import PassiveValidationStage
from attack_surface_mapper.reporting import ReportPaths
from attack_surface_mapper.utils.asset_normalizer import normalize_asset


def test_normalize_asset_keeps_stable_host_and_resolved_ip_separate(monkeypatch) -> None:
    monkeypatch.setattr('attack_surface_mapper.utils.asset_normalizer.socket.gethostbyname', lambda host: '203.0.113.10')

    asset = normalize_asset('https://App.Example/login')

    assert asset['target_host_original'] == 'app.example'
    assert asset['asset_host'] == 'app.example'
    assert asset['asset_host_resolved'] == '203.0.113.10'
    assert asset['asset_port'] == '443'


def test_enrichment_populates_stable_asset_fields_and_ids(monkeypatch) -> None:
    monkeypatch.setattr('attack_surface_mapper.utils.asset_normalizer.socket.gethostbyname', lambda host: '203.0.113.10')
    vuln = Vulnerability(
        source='custom-api-check',
        title='GraphQL Surface Exposed',
        description='d',
        severity='high',
        target='https://App.Example/graphql',
        matched_at='https://App.Example/graphql',
        category='api',
    )

    enrich_vulnerabilities([vuln])

    assert vuln.target_host_original == 'app.example'
    assert vuln.asset_host == 'app.example'
    assert vuln.asset_host_resolved == '203.0.113.10'
    assert vuln.asset_port == '443'
    assert vuln.finding_id
    assert vuln.correlation_id
    assert vuln.finding_id != vuln.correlation_id


def test_aggregate_groups_network_assets_by_resolved_ip_but_keeps_display_host() -> None:
    first = Vulnerability(
        source='nmap',
        title='Exposed PostgreSQL Service',
        description='d',
        severity='medium',
        priority='high',
        target='db.example:5432',
        matched_at='db.example:5432',
        category='database',
        verification_status='confirmed',
        recommendation='rec',
        asset_host='db.example',
        asset_host_resolved='203.0.113.10',
        asset_port='5432',
        port='5432',
    )
    second = Vulnerability(
        source='nmap',
        title='Exposed PostgreSQL Service',
        description='d',
        severity='medium',
        priority='high',
        target='db-alias.example:5432',
        matched_at='db-alias.example:5432',
        category='database',
        verification_status='confirmed',
        recommendation='rec',
        asset_host='db-alias.example',
        asset_host_resolved='203.0.113.10',
        asset_port='5432',
        port='5432',
    )

    payload = build_aggregate_payload([
        ScanResult(target='https://app-one.example', vulnerabilities=[first], command=[], return_code=0, stdout='', stderr='', raw_findings_count=0, output_json_path=None, raw_output_path=None, summary={'high': 1}, report_paths=ReportPaths()),
        ScanResult(target='https://app-two.example', vulnerabilities=[second], command=[], return_code=0, stdout='', stderr='', raw_findings_count=0, output_json_path=None, raw_output_path=None, summary={'high': 1}, report_paths=ReportPaths()),
    ])

    assert len(payload['shared_asset_findings']) == 1
    finding = payload['shared_asset_findings'][0]
    assert finding['asset_host'] == 'db.example'
    assert finding['asset_host_resolved'] == '203.0.113.10'
    assert finding['target_count'] == 2


def test_passive_validation_reuses_shared_baseline_once(monkeypatch) -> None:
    shared_baseline = object()
    calls: dict[str, list[object] | int] = {
        'baseline': 0,
        'validators': [],
    }

    class DummySession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

    class DummyValidator:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, target, baseline=None):
            calls['validators'].append(baseline)
            return []

    class DummyAuthValidator(DummyValidator):
        DEFAULT_PROTECTED_PATHS: tuple[str, ...] = ()

    class DummyAPIValidator(DummyValidator):
        DEFAULT_PATHS: tuple[str, ...] = ()

    monkeypatch.setattr('attack_surface_mapper.pipeline.stages.build_http_session', lambda **kwargs: DummySession())

    def fake_baseline(session, target, timeout):
        calls['baseline'] += 1
        return shared_baseline

    monkeypatch.setattr('attack_surface_mapper.pipeline.stages.baseline_fingerprint', fake_baseline)
    monkeypatch.setattr('attack_surface_mapper.pipeline.stages.PanelsValidator', DummyValidator)
    monkeypatch.setattr('attack_surface_mapper.pipeline.stages.AuthValidator', DummyAuthValidator)
    monkeypatch.setattr('attack_surface_mapper.pipeline.stages.APIValidator', DummyAPIValidator)
    monkeypatch.setattr('attack_surface_mapper.pipeline.stages.SensitiveFilesValidator', DummyValidator)

    settings = ScanSettings(
        baseline_probe=True,
        run_headers=False,
        run_fingerprint=False,
        run_tls=False,
        run_crawl=False,
        run_secrets=False,
        run_panels=True,
        run_auth=True,
        run_api=True,
        run_sensitive_files=True,
    )
    ctx = ScanContext(target='https://target.example', settings=settings, outputs=ScanOutputs())

    PassiveValidationStage().run(ctx)

    assert calls['baseline'] == 1
    assert calls['validators'] == [shared_baseline, shared_baseline, shared_baseline, shared_baseline]
    assert ctx.artifacts.shared_baseline is shared_baseline
