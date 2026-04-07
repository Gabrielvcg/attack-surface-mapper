from __future__ import annotations

from types import SimpleNamespace

from attack_surface_mapper.validators.api_validator import APIValidator
from attack_surface_mapper.validators.auth_validator import AuthValidator


class FakeResponse:
    def __init__(self, url: str, text: str, status_code: int = 200, headers: dict | None = None, content: bytes | None = None):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.headers = headers or {'Content-Type': 'text/html'}
        self.content = content if content is not None else text.encode()
        self.raw = SimpleNamespace(headers=SimpleNamespace(getlist=lambda name: []))


def test_auth_validator_keeps_likely_non_baseline_ops_endpoint(monkeypatch):
    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if url == 'http://localhost:3000':
            return FakeResponse(url, '<html>home</html>')
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html><title>SPA</title>shell</html>')
        if url.endswith('/actuator'):
            return FakeResponse(url, '{"ping":"ok"}', headers={'Content-Type': 'application/json'})
        return FakeResponse(url, '<html><title>SPA</title>shell</html>')

    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = AuthValidator(timeout=1, paths=('/actuator',)).run('http://localhost:3000')
    assert len(findings) == 1
    assert findings[0].verification_status == 'likely'
    assert findings[0].confidence == 'medium'


def test_api_validator_keeps_likely_non_baseline_swagger_surface(monkeypatch):
    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html>spa shell</html>')
        if url == 'http://localhost:3000':
            return FakeResponse(url, '<html>home</html>', headers={'Access-Control-Allow-Origin': ''})
        if url.endswith('/swagger'):
            return FakeResponse(url, '<html><body>Docs landing</body></html>', headers={'Content-Type': 'text/html'})
        return FakeResponse(url, '<html>spa shell</html>')

    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = APIValidator(timeout=1, paths=('/swagger',)).run('http://localhost:3000')
    assert len(findings) == 1
    assert findings[0].verification_status == 'likely'
