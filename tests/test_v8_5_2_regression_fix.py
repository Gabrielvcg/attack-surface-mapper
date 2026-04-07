from attack_surface_mapper.validators.api_validator import APIValidator
from attack_surface_mapper.validators.auth_validator import AuthValidator


class DummyResponse:
    def __init__(self, url, text='', status_code=200, headers=None):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.headers = headers or {'Content-Type': 'text/html'}


def test_auth_validator_includes_protected_endpoint_discovery(monkeypatch):
    validator = AuthValidator(paths=('/management',))

    class Session:
        def get(self, url, timeout=0, allow_redirects=True):
            if url.rstrip('/') == 'http://x':
                return DummyResponse('http://x', text='home', status_code=200, headers={'Content-Type': 'text/html'})
            return DummyResponse('http://x/management', text='', status_code=401, headers={})

    monkeypatch.setattr('requests.Session', lambda: Session())
    monkeypatch.setattr('attack_surface_mapper.validators.auth_validator.baseline_fingerprint', lambda session, target, timeout: None)
    findings = validator.run('http://x')
    assert findings
    assert findings[0].category == 'discovery'
    assert 'Protected' in findings[0].title


def test_api_validator_does_not_report_openapi_on_404(monkeypatch):
    validator = APIValidator(paths=('/openapi.json',))

    class Session:
        def get(self, url, timeout=0, allow_redirects=True, headers=None):
            if url.rstrip('/') == 'http://x' and headers:
                return DummyResponse('http://x', text='home', status_code=200, headers={})
            if url.rstrip('/') == 'http://x':
                return DummyResponse('http://x', text='home', status_code=200, headers={'Content-Type': 'text/html'})
            return DummyResponse('http://x/openapi.json', text='{"detail":"no static resource openapi.json"}', status_code=404, headers={'Content-Type': 'application/problem+json'})

    monkeypatch.setattr('requests.Session', lambda: Session())
    monkeypatch.setattr('attack_surface_mapper.validators.api_validator.baseline_fingerprint', lambda session, target, timeout: None)
    findings = validator.run('http://x')
    assert findings == []


def test_api_validator_includes_protected_api_surface(monkeypatch):
    validator = APIValidator(paths=('/api-docs',))

    class Session:
        def get(self, url, timeout=0, allow_redirects=True, headers=None):
            if url.rstrip('/') == 'http://x' and headers:
                return DummyResponse('http://x', text='home', status_code=200, headers={})
            if url.rstrip('/') == 'http://x':
                return DummyResponse('http://x', text='home', status_code=200, headers={'Content-Type': 'text/html'})
            return DummyResponse('http://x/api-docs', text='', status_code=401, headers={})

    monkeypatch.setattr('requests.Session', lambda: Session())
    monkeypatch.setattr('attack_surface_mapper.validators.api_validator.baseline_fingerprint', lambda session, target, timeout: None)
    findings = validator.run('http://x')
    assert findings
    assert findings[0].category == 'discovery'
