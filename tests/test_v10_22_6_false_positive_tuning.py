from __future__ import annotations

from types import SimpleNamespace

from attack_surface_mapper.http_client import HttpResponse
from attack_surface_mapper.validators.api_validator import APIValidator
from attack_surface_mapper.validators.auth_validator import AuthValidator
from attack_surface_mapper.validators.headers_validator import HeadersValidator
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


def test_headers_validator_skips_browser_headers_for_json_response() -> None:
    response = HttpResponse(
        status_code=200,
        url='https://api.example.test/status',
        headers={'Content-Type': 'application/json'},
        text='{"ok":true}',
        content=b'{"ok":true}',
    )

    findings = HeadersValidator(timeout=1).run('https://api.example.test/status', response=response)

    assert [finding.title for finding in findings] == ['Missing Strict-Transport-Security Header']


def test_panels_validator_treats_public_login_as_discovery(monkeypatch) -> None:
    login_html = "<html><form><input name='email'><input type='password'></form></html>"

    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html>not found</html>', status_code=404)
        if url.endswith('/login'):
            return FakeResponse(url, login_html, headers={'Content-Type': 'text/html'})
        return FakeResponse(url, '<html>home</html>')

    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = PanelsValidator(timeout=1, paths=('/login',)).run('https://target.example')

    assert len(findings) == 1
    assert findings[0].title == 'Login Surface Discovered (200)'
    assert findings[0].category == 'discovery'
    assert findings[0].severity == 'low'


def test_sensitive_files_rejects_content_type_only_binary_matches(monkeypatch) -> None:
    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html>not found</html>', status_code=404)
        if url.endswith('/backup.zip'):
            return FakeResponse(url, '', headers={'Content-Type': 'application/zip'}, content=b'not-a-zip')
        if url.endswith('/.DS_Store'):
            return FakeResponse(url, '', headers={'Content-Type': 'application/octet-stream'}, content=b'not-ds-store')
        return FakeResponse(url, '<html>home</html>')

    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = SensitiveFilesValidator(timeout=1, paths=('/backup.zip', '/.DS_Store')).run('https://target.example')

    assert findings == []


def test_cors_wildcard_without_credentials_is_low_confidence_signal(monkeypatch) -> None:
    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if headers and headers.get('Origin'):
            return FakeResponse(
                url,
                '{"ok": true}',
                headers={'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            )
        return FakeResponse(url, '<html>home</html>')

    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = APIValidator(timeout=1, paths=()).run('https://api.example.test')

    assert len(findings) == 1
    assert findings[0].title == 'Broad CORS Policy Observed'
    assert findings[0].severity == 'low'
    assert findings[0].confidence == 'medium'
    assert findings[0].verification_status == 'likely'


def test_auth_cookie_flags_ignore_non_auth_cookie_and_do_not_require_httponly_on_csrf_cookie() -> None:
    validator = AuthValidator(timeout=1)
    response = FakeResponse(
        'https://target.example',
        '<html>home</html>',
        headers={'Content-Type': 'text/html'},
    )
    response.raw = SimpleNamespace(headers=SimpleNamespace(getlist=lambda name: [
        'analytics_id=abc123; Path=/',
        'csrftoken=abc123; Path=/; Secure',
        'sessionid=abc123; Path=/; Secure',
    ]))

    findings = validator._check_cookie_flags(response, 'https://target.example', 'target.example', None, 'https')

    titles = [finding.title for finding in findings]
    assert 'Cookie Without HttpOnly Flag' in titles
    assert titles.count('Cookie Without SameSite Attribute') == 2
    assert not any('analytics_id' in (finding.evidence or '') for finding in findings)
    assert not any(finding.title == 'Cookie Without HttpOnly Flag' and 'csrftoken' in (finding.evidence or '') for finding in findings)
