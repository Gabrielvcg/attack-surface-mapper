from __future__ import annotations

from types import SimpleNamespace

from attack_surface_mapper.validators.api_validator import APIValidator
from attack_surface_mapper.validators.auth_validator import AuthValidator
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


def test_panels_validator_filters_spa_fallback(monkeypatch):
    calls = []
    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        calls.append(url)
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html><title>Juice Shop</title>same shell</html>')
        if url.endswith('/metrics'):
            return FakeResponse(url, '# HELP x test\n# TYPE x counter', headers={'Content-Type': 'text/plain'})
        return FakeResponse(url, '<html><title>Juice Shop</title>same shell</html>')
    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = PanelsValidator(timeout=1).run('http://localhost:3000')
    assert [f.target for f in findings] == ['http://localhost:3000/metrics']


def test_sensitive_files_validator_requires_real_signature(monkeypatch):
    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html>spa shell</html>')
        if url.endswith('/backup.zip'):
            return FakeResponse(url, '', headers={'Content-Type': 'application/zip'}, content=b'PK\x03\x04rest')
        return FakeResponse(url, '<html>spa shell</html>')
    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = SensitiveFilesValidator(timeout=1, paths=('/backup.zip','/.env')).run('http://localhost:3000')
    assert len(findings) == 1
    assert findings[0].target.endswith('/backup.zip')


def test_auth_validator_filters_baseline_false_positive(monkeypatch):
    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if url == 'http://localhost:3000':
            return FakeResponse(url, '<html>home</html>')
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html><title>Juice Shop</title>spa shell</html>')
        if url.endswith('/graphql'):
            return FakeResponse(url, '{"data":"graphql query mutation"}', headers={'Content-Type': 'application/json'})
        return FakeResponse(url, '<html><title>Juice Shop</title>spa shell</html>')
    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = AuthValidator(timeout=1, paths=('/admin','/graphql')).run('http://localhost:3000')
    assert len(findings) == 1
    assert findings[0].target.endswith('/graphql')


def test_api_validator_filters_docs_baseline(monkeypatch):
    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html>spa shell</html>')
        if url == 'http://localhost:3000':
            return FakeResponse(url, '<html>home</html>', headers={'Access-Control-Allow-Origin': ''})
        if url.endswith('/openapi.json'):
            return FakeResponse(url, '{"openapi":"3.0.0"}', headers={'Content-Type': 'application/json'})
        return FakeResponse(url, '<html>spa shell</html>')
    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = APIValidator(timeout=1, paths=('/swagger','/openapi.json')).run('http://localhost:3000')
    assert len(findings) == 1
    assert findings[0].target.endswith('/openapi.json')
