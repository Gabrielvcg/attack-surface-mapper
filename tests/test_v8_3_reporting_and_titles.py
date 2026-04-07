from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from attack_surface_mapper.analysis.enrichment import enrich_vulnerabilities
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.reporting.generator import ReportGenerator
from attack_surface_mapper.validators.auth_validator import AuthValidator
from attack_surface_mapper.validators.sensitive_files_validator import SensitiveFilesValidator


class FakeResponse:
    def __init__(self, url: str, text: str, status_code: int = 200, headers: dict | None = None, content: bytes | None = None):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.headers = headers or {'Content-Type': 'text/html'}
        self.content = content if content is not None else text.encode()
        self.raw = SimpleNamespace(headers=SimpleNamespace(getlist=lambda name: []))


def test_auth_validator_uses_specific_title(monkeypatch):
    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if url == 'http://localhost:3000':
            return FakeResponse(url, '<html>home</html>')
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html><title>Juice Shop</title>spa shell</html>')
        if url.endswith('/metrics'):
            return FakeResponse(url, '# HELP x test\n# TYPE x counter', headers={'Content-Type': 'text/plain'})
        return FakeResponse(url, '<html><title>Juice Shop</title>spa shell</html>')
    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = AuthValidator(timeout=1, paths=('/metrics',)).run('http://localhost:3000')
    assert findings[0].title == 'Metrics Endpoint Accessible Without Authentication'
    assert findings[0].verification_status == 'confirmed'


def test_sensitive_files_validator_classifies_robots_as_discovery(monkeypatch):
    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html>spa shell</html>')
        if url.endswith('/robots.txt'):
            return FakeResponse(url, 'User-agent: *\nDisallow: /admin')
        return FakeResponse(url, '<html>spa shell</html>')
    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = SensitiveFilesValidator(timeout=1, paths=('/robots.txt',)).run('http://localhost:3000')
    assert findings[0].category == 'discovery'
    assert findings[0].severity == 'low'
    assert findings[0].title == 'robots.txt Exposed'


def test_markdown_report_includes_priority_reason_and_verification(tmp_path: Path):
    vuln = Vulnerability(
        source='custom-api-check',
        title='Permissive CORS Policy',
        description='desc',
        severity='medium',
        target='http://localhost:3000',
        category='api',
        confidence='high',
        verification_status='confirmed',
        evidence='Access-Control-Allow-Origin: *',
    )
    enrich_vulnerabilities([vuln])
    path = tmp_path / 'report.md'
    ReportGenerator().generate_markdown([vuln], 'http://localhost:3000', str(path))
    content = path.read_text(encoding='utf-8')
    assert 'Motivo de prioridad' in content
    assert 'Estado de verificación' in content
