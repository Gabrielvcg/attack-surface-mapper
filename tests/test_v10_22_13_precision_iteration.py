from __future__ import annotations

from types import SimpleNamespace

from attack_surface_mapper.batch.aggregate import build_aggregate_payload
from attack_surface_mapper.analysis.enrichment import enrich_vulnerabilities
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.orchestrator import ScanResult
from attack_surface_mapper.reporting import ReportGenerator, ReportPaths
from attack_surface_mapper.validators.api_validator import APIValidator
from attack_surface_mapper.validators.http_fingerprint import fingerprint_response, normalise_text
from attack_surface_mapper.validators.panels_validator import PanelsValidator
from attack_surface_mapper.validators.sensitive_files_validator import SensitiveFilesValidator


class FakeResponse:
    def __init__(self, url: str, text: str, status_code: int = 200, headers: dict | None = None, content: bytes | None = None):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.headers = headers or {'Content-Type': 'text/html'}
        self.content = content if content is not None else text.encode()
        self.raw = SimpleNamespace(headers=SimpleNamespace(getlist=lambda name: []))


def test_api_validator_discards_baseline_like_graphql_without_strong_signature() -> None:
    response = FakeResponse(
        'https://target.example/graphql',
        '{"errors":[{"message":"try again"}],"data":[]}',
        headers={'Content-Type': 'application/json'},
    )
    preview = normalise_text(response.text, 1500)
    baseline = fingerprint_response(response)

    include, confidence, reason, verification, title, _, _ = APIValidator()._classify_path(
        '/graphql',
        response,
        preview,
        'application/json',
        baseline,
    )

    assert include is False
    assert confidence == 'low'
    assert verification == 'discarded'
    assert title == 'GraphQL Surface Exposed'
    assert 'sin firma graphql fuerte' in reason


def test_api_validator_keeps_swagger_as_likely_review_surface_even_with_strong_markers() -> None:
    response = FakeResponse(
        'https://target.example/swagger',
        '<html><body>swagger-ui openapi docs</body></html>',
        headers={'Content-Type': 'text/html'},
    )
    preview = normalise_text(response.text, 1500)

    include, confidence, reason, verification, title, _, _ = APIValidator()._classify_path(
        '/swagger',
        response,
        preview,
        'text/html',
        baseline=None,
    )

    assert include is True
    assert title == 'Swagger UI Exposed'
    assert confidence == 'high'
    assert verification == 'likely'
    assert 'documentación api pública' in reason


def test_auth_validator_reports_graphql_as_api_surface_not_auth_failure(monkeypatch) -> None:
    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if url == 'http://localhost:3000':
            return FakeResponse(url, '<html>home</html>')
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html><title>SPA</title>shell</html>')
        if url.endswith('/graphql'):
            return FakeResponse(url, '{"errors":[{"message":"must provide query string"}],"data":null}', headers={'Content-Type': 'application/json'})
        return FakeResponse(url, '<html><title>SPA</title>shell</html>')

    monkeypatch.setattr('requests.sessions.Session.get', fake_get)

    from attack_surface_mapper.validators.auth_validator import AuthValidator

    findings = AuthValidator(timeout=1, paths=('/graphql',)).run('http://localhost:3000')

    assert len(findings) == 1
    assert findings[0].title == 'GraphQL Surface Exposed'
    assert findings[0].category == 'api'
    assert findings[0].verification_status == 'likely'
    enrich_vulnerabilities(findings)
    assert findings[0].priority == 'medium'


def test_panels_validator_skips_swagger_login_surface(monkeypatch) -> None:
    login_html = "<html><form><input name='username'><input type='password'><input name='csrfmiddlewaretoken'></form></html>"

    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if url == 'https://target.example':
            return FakeResponse(url, '<html>home</html>')
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html>not found</html>', status_code=404)
        if url.endswith('/swagger'):
            return FakeResponse('https://target.example/login?next=/swagger', login_html, headers={'Content-Type': 'text/html'})
        return FakeResponse(url, '<html>not found</html>', status_code=404)

    monkeypatch.setattr('requests.sessions.Session.get', fake_get)

    findings = PanelsValidator(timeout=1, paths=('/swagger',)).run('https://target.example')

    assert findings == []


def test_sensitive_files_validator_rejects_html_shell_for_robots(monkeypatch) -> None:
    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html>not found</html>', status_code=404)
        if url.endswith('/robots.txt'):
            return FakeResponse(url, '<html><body>User-Agent: demo</body></html>', headers={'Content-Type': 'text/html'})
        return FakeResponse(url, '<html>home</html>')

    monkeypatch.setattr('requests.sessions.Session.get', fake_get)

    findings = SensitiveFilesValidator(timeout=1, paths=('/robots.txt',)).run('https://target.example')

    assert findings == []


def test_summary_top_findings_prioritise_application_risk_over_headers_and_inventory() -> None:
    findings = [
        Vulnerability(
            source='custom-header-check',
            title='Missing Content-Security-Policy Header',
            description='d',
            severity='medium',
            priority='medium',
            target='https://target.example/',
            category='headers',
            confidence='high',
            verification_status='confirmed',
        ),
        Vulnerability(
            source='custom-api-check',
            title='Multiple API Endpoints Exposed (10)',
            description='d',
            severity='medium',
            priority='medium',
            target='https://target.example/api',
            category='api',
            confidence='medium',
            verification_status='likely',
        ),
        Vulnerability(
            source='custom-api-check',
            title='GraphQL Surface Exposed',
            description='d',
            severity='high',
            priority='critical',
            target='https://target.example/graphql',
            category='api',
            confidence='high',
            verification_status='confirmed',
        ),
        Vulnerability(
            source='custom-fingerprint-check',
            title='Technology Fingerprint Detected (Angular)',
            description='d',
            severity='low',
            priority='low',
            target='https://target.example/',
            category='discovery',
            confidence='medium',
            verification_status='likely',
        ),
    ]

    payload = ReportGenerator().build_summary_payload(findings, 'https://target.example')
    titles = [item['title'] for item in payload['top_findings']]

    assert titles[:4] == [
        'GraphQL Surface Exposed',
        'Missing Content-Security-Policy Header',
        'Multiple API Endpoints Exposed (10)',
        'Technology Fingerprint Detected (Angular)',
    ]
    assert payload['top_risk_findings'][0]['title'] == 'GraphQL Surface Exposed'
    assert payload['top_hygiene_findings'][0]['title'] == 'Missing Content-Security-Policy Header'
    assert payload['top_discovery_findings'][0]['title'] == 'Technology Fingerprint Detected (Angular)'


def test_top_risk_findings_skip_low_likely_application_noise_when_stronger_items_exist() -> None:
    findings = [
        Vulnerability(
            source='custom-api-check',
            title='GraphQL Surface Exposed',
            description='d',
            severity='medium',
            priority='medium',
            target='https://target.example/graphql',
            category='api',
            confidence='medium',
            verification_status='likely',
        ),
        Vulnerability(
            source='custom-api-check',
            title='Broad CORS Policy Observed',
            description='d',
            severity='low',
            priority='low',
            target='https://target.example',
            category='api',
            confidence='medium',
            verification_status='likely',
        ),
    ]

    payload = ReportGenerator().build_summary_payload(findings, 'https://target.example')

    assert [item['title'] for item in payload['top_risk_findings']] == ['GraphQL Surface Exposed']


def test_top_risk_findings_follow_review_matrix_and_hide_review_only_surface_when_prioritised_item_exists() -> None:
    findings = [
        Vulnerability(
            source='custom-auth-check',
            title='Metrics Endpoint Accessible Without Authentication',
            description='d',
            severity='high',
            priority='critical',
            target='https://target.example/metrics',
            category='authentication',
            confidence='high',
            verification_status='confirmed',
        ),
        Vulnerability(
            source='custom-api-check',
            title='Swagger UI Exposed',
            description='d',
            severity='medium',
            priority='medium',
            target='https://target.example/swagger',
            category='api',
            confidence='high',
            verification_status='likely',
        ),
        Vulnerability(
            source='custom-api-check',
            title='GraphQL Surface Exposed',
            description='d',
            severity='medium',
            priority='medium',
            target='https://target.example/graphql',
            category='api',
            confidence='high',
            verification_status='likely',
        ),
    ]

    payload = ReportGenerator().build_summary_payload(findings, 'https://target.example')

    assert [item['title'] for item in payload['top_risk_findings']] == ['Metrics Endpoint Accessible Without Authentication']


def test_markdown_has_dedicated_hygiene_section(tmp_path) -> None:
    findings = [
        Vulnerability(
            source='custom-api-check',
            title='GraphQL Surface Exposed',
            description='d',
            severity='high',
            priority='high',
            target='https://target.example/graphql',
            category='api',
            confidence='high',
            verification_status='confirmed',
        ),
        Vulnerability(
            source='custom-header-check',
            title='Missing Content-Security-Policy Header',
            description='d',
            severity='medium',
            priority='medium',
            target='https://target.example/',
            category='headers',
            confidence='high',
            verification_status='confirmed',
        ),
    ]

    content_path = ReportGenerator().generate_markdown(findings, 'https://target.example', str(tmp_path / 'report.md'))
    content = open(content_path, encoding='utf-8').read()

    assert '## Hallazgos confirmados de aplicación' in content
    assert '## Hallazgos de higiene y endurecimiento' in content
    assert 'Missing Content-Security-Policy Header' in content


def test_aggregate_top_findings_prioritise_application_risk_over_headers_and_inventory() -> None:
    findings = [
        Vulnerability(
            source='custom-header-check',
            title='Missing Content-Security-Policy Header',
            description='d',
            severity='medium',
            priority='medium',
            target='https://target.example/',
            category='headers',
            kind='validation',
            confidence='high',
            verification_status='confirmed',
        ),
        Vulnerability(
            source='custom-api-check',
            title='Multiple API Endpoints Exposed (10)',
            description='d',
            severity='medium',
            priority='medium',
            target='https://target.example/api',
            category='api',
            kind='validation',
            confidence='medium',
            verification_status='likely',
        ),
        Vulnerability(
            source='custom-api-check',
            title='GraphQL Surface Exposed',
            description='d',
            severity='high',
            priority='critical',
            target='https://target.example/graphql',
            category='api',
            kind='validation',
            confidence='high',
            verification_status='confirmed',
        ),
        Vulnerability(
            source='custom-fingerprint-check',
            title='Technology Fingerprint Detected (Angular)',
            description='d',
            severity='low',
            priority='low',
            target='https://target.example/',
            category='discovery',
            kind='discovery',
            confidence='medium',
            verification_status='likely',
        ),
    ]
    result = ScanResult(
        target='https://target.example',
        vulnerabilities=findings,
        command=[],
        return_code=0,
        stdout='',
        stderr='',
        raw_findings_count=len(findings),
        output_json_path=None,
        raw_output_path=None,
        summary={'critical': 1, 'medium': 2, 'low': 1},
        report_paths=ReportPaths(),
    )

    payload = build_aggregate_payload([result])
    titles = [item['title'] for item in payload['top_findings']]

    assert titles[:4] == [
        'GraphQL Surface Exposed',
        'Missing Content-Security-Policy Header',
        'Multiple API Endpoints Exposed (10)',
        'Technology Fingerprint Detected (Angular)',
    ]
