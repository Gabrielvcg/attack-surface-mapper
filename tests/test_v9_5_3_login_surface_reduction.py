from __future__ import annotations

from types import SimpleNamespace

from attack_surface_mapper.validators.auth_validator import AuthValidator
from attack_surface_mapper.validators.panels_validator import PanelsValidator


class FakeResponse:
    def __init__(self, url: str, text: str, status_code: int = 200, headers: dict | None = None, content: bytes | None = None):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.headers = headers or {'Content-Type': 'text/html'}
        self.content = content if content is not None else text.encode()
        self.raw = SimpleNamespace(headers=SimpleNamespace(getlist=lambda name: []))


def test_auth_validator_downgrades_admin_redirect_to_login_surface(monkeypatch):
    login_html = "<html><form><input name='username'><input type='password'><input name='csrfmiddlewaretoken'></form></html>"

    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if url == 'https://target.example':
            return FakeResponse(url, '<html>home</html>')
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html>not found</html>', status_code=404)
        if url.endswith('/admin'):
            return FakeResponse('https://target.example/admin/login/?next=/admin/', login_html, headers={'Content-Type': 'text/html'})
        return FakeResponse(url, '<html>not found</html>', status_code=404)

    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = AuthValidator(timeout=1, paths=('/admin',)).run('https://target.example')
    assert len(findings) == 1
    assert findings[0].title == 'Protected Admin Panel Login Surface Discovered'
    assert findings[0].category == 'discovery'
    assert findings[0].severity == 'low'


def test_panels_validator_skips_admin_login_surface(monkeypatch):
    login_html = "<html><form><input name='username'><input type='password'><input name='csrfmiddlewaretoken'></form></html>"

    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if url == 'https://target.example':
            return FakeResponse(url, '<html>home</html>')
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html>not found</html>', status_code=404)
        if url.endswith('/admin'):
            return FakeResponse('https://target.example/admin/login/?next=/admin/', login_html, headers={'Content-Type': 'text/html'})
        return FakeResponse(url, '<html>not found</html>', status_code=404)

    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = PanelsValidator(timeout=1, paths=('/admin',)).run('https://target.example')
    assert findings == []
