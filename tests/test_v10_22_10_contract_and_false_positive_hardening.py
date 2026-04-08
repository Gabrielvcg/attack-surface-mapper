from __future__ import annotations

from types import SimpleNamespace

from attack_surface_mapper.batch.aggregate import build_aggregate_payload
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.orchestrator import ScanResult
from attack_surface_mapper.reporting import ReportGenerator, ReportPaths
from attack_surface_mapper.validators.api_validator import APIValidator
from attack_surface_mapper.validators.sensitive_files_validator import SensitiveFilesValidator
from main import build_run_manifest


class FakeResponse:
    def __init__(self, url: str, text: str, status_code: int = 200, headers: dict | None = None, content: bytes | None = None):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.headers = headers or {'Content-Type': 'text/html'}
        self.content = content if content is not None else text.encode()
        self.raw = SimpleNamespace(headers=SimpleNamespace(getlist=lambda name: []))


def test_summary_payload_exposes_stable_schema_and_comparison_counts() -> None:
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
        finding_id='finding-1',
        correlation_id='corr-1',
        asset_host='target.example',
        asset_host_resolved='203.0.113.10',
        asset_port='443',
    )

    payload = ReportGenerator().build_summary_payload([vuln], 'https://target.example', comparison={'new_findings': [{'title': 'x'}]})

    assert payload['schema_version'] == '1.0'
    assert payload['comparison'] == {
        'new_findings': [{'title': 'x'}],
        'resolved_findings': [],
        'changed_findings': [],
    }
    assert payload['comparison_summary'] == {
        'new_findings': 1,
        'resolved_findings': 0,
        'changed_findings': 0,
    }
    assert payload['stats']['priority_counts'] == {'critical': 0, 'high': 1, 'medium': 0, 'low': 0}
    assert payload['stats']['severity_counts']['info'] == 0
    assert payload['top_finding_count'] == 1


def test_aggregate_payload_exposes_stable_summary_and_finding_fields() -> None:
    vuln = Vulnerability(
        source='custom-api-check',
        title='GraphQL Surface Exposed',
        description='d',
        severity='high',
        priority='high',
        target='https://target.example/graphql',
        matched_at='https://target.example/graphql',
        category='api',
        kind='validation',
        confidence='high',
        verification_status='confirmed',
        source_count=2,
        evidence_summary='graphql marker',
        finding_id='finding-1',
        correlation_id='corr-1',
        asset_host='target.example',
        asset_host_resolved='203.0.113.10',
        asset_port='443',
    )
    result = ScanResult(
        target='https://target.example',
        vulnerabilities=[vuln],
        command=[],
        return_code=0,
        stdout='',
        stderr='',
        raw_findings_count=1,
        output_json_path=None,
        raw_output_path=None,
        summary={'high': 1},
        report_paths=ReportPaths(),
    )

    payload = build_aggregate_payload([result])

    assert payload['schema_version'] == '1.0'
    assert payload['summary']['priority_counts'] == {'critical': 0, 'high': 1, 'medium': 0, 'low': 0}
    assert payload['summary']['severity_counts']['high'] == 1
    finding = payload['top_findings'][0]
    assert finding['kind'] == 'validation'
    assert finding['confidence'] == 'high'
    assert finding['source_count'] == 2
    assert finding['evidence_summary'] == 'graphql marker'
    assert finding['asset_hosts'] == ['target.example']


def test_build_run_manifest_separates_effective_config_and_results(tmp_path) -> None:
    result = ScanResult(
        target='https://target.example',
        vulnerabilities=[
            Vulnerability(
                source='custom-api-check',
                title='GraphQL Surface Exposed',
                description='d',
                severity='high',
                target='https://target.example/graphql',
            )
        ],
        command=[],
        return_code=0,
        stdout='',
        stderr='',
        raw_findings_count=3,
        output_json_path=str(tmp_path / 'vulnerabilities.json'),
        raw_output_path=None,
        summary={'high': 1},
        report_paths=ReportPaths(summary_json=str(tmp_path / 'report.summary.json')),
        stages_executed=['browser-discovery', 'passive-validation'],
        collectors_used=['browser-discovery'],
        observed_urls=['https://target.example/'],
        observed_actions=[{'kind': 'navigate'}],
        observed_api_calls=['https://target.example/graphql'],
    )

    payload = build_run_manifest(
        base_dir=tmp_path,
        requested_targets=['https://target.example'],
        aggregate_paths={'summary_json': str(tmp_path / 'aggregate_summary.json')},
        results=[result],
        errors=[],
        effective_config={'profile': 'passive-recon-safe', 'debug': False},
    )

    assert payload['schema_version'] == '1.0'
    assert payload['effective_config']['profile'] == 'passive-recon-safe'
    assert payload['results_summary']['successful_targets'] == 1
    assert payload['results_summary']['correlated_findings_count'] == 1
    assert payload['per_target'][0]['summary']['raw_findings_count'] == 3
    assert payload['per_target'][0]['observed']['api_calls_count'] == 1
    assert payload['per_target'][0]['reports']['summary_json'].endswith('report.summary.json')


def test_api_validator_discards_login_surface_served_from_swagger_path(monkeypatch) -> None:
    login_html = "<html><form><input name='username'><input type='password'><input name='csrfmiddlewaretoken'></form></html>"

    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html>not found</html>', status_code=404)
        if url.endswith('/swagger'):
            return FakeResponse('https://target.example/login?next=/swagger', login_html, headers={'Content-Type': 'text/html'})
        return FakeResponse(url, '<html>home</html>')

    monkeypatch.setattr('requests.sessions.Session.get', fake_get)

    findings = APIValidator(timeout=1, paths=('/swagger',)).run('https://target.example')

    assert findings == []


def test_sensitive_files_env_requires_multiple_assignments_and_strong_markers(monkeypatch) -> None:
    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html>not found</html>', status_code=404)
        if url.endswith('/.env'):
            return FakeResponse(url, 'DEBUG=true\nPORT=3000', headers={'Content-Type': 'text/plain'})
        return FakeResponse(url, '<html>home</html>')

    monkeypatch.setattr('requests.sessions.Session.get', fake_get)

    findings = SensitiveFilesValidator(timeout=1, paths=('/.env',)).run('https://target.example')

    assert findings == []
