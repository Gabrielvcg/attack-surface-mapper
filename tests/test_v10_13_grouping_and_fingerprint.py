from __future__ import annotations

from attack_surface_mapper.analysis.correlation import correlate_vulnerabilities
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.validators.fingerprint_validator import FingerprintValidator


class _Resp:
    def __init__(self, url: str, headers: dict[str, str], text: str) -> None:
        self.url = url
        self.headers = headers
        self.text = text


class _Session:
    def __init__(self, response: _Resp) -> None:
        self.response = response

    def get(self, target: str, timeout: int, allow_redirects: bool = True):
        return self.response


def test_group_api_exposure_findings_into_single_summary() -> None:
    items = [
        Vulnerability(source='custom-api-check', title='API Surface Exposed', description='d', severity='medium', target='http://localhost:3000/api/Users', matched_at='http://localhost:3000/api/Users', category='api', confidence='medium', verification_status='likely'),
        Vulnerability(source='custom-api-check', title='API Surface Exposed', description='d', severity='medium', target='http://localhost:3000/api/Products', matched_at='http://localhost:3000/api/Products', category='api', confidence='medium', verification_status='likely'),
        Vulnerability(source='custom-api-check', title='API Surface Exposed', description='d', severity='medium', target='http://localhost:3000/api/Orders', matched_at='http://localhost:3000/api/Orders', category='api', confidence='medium', verification_status='likely'),
    ]

    correlated = correlate_vulnerabilities(items)

    assert len(correlated) == 1
    assert correlated[0].title == 'Multiple API Endpoints Exposed (3)'
    assert correlated[0].category == 'api'
    assert 'Endpoints expuestos' in (correlated[0].evidence_summary or '')


def test_fingerprint_validator_detects_apache_and_php() -> None:
    response = _Resp(
        url='http://localhost:8080/login.php',
        headers={'Server': 'Apache/2.4.25 (Debian)', 'X-Powered-By': 'PHP/8.2.0', 'Content-Type': 'text/html'},
        text='<html><head><title>DVWA</title></head><body><form><input type="password" /></form></body></html>',
    )
    validator = FingerprintValidator()
    validator.run.__globals__['build_http_session'] = lambda **kwargs: _Session(response)

    findings = validator.run('http://localhost:8080')

    titles = {f.title for f in findings}
    assert 'Technology Fingerprint Detected (Apache httpd)' in titles
    assert 'Technology Fingerprint Detected (PHP)' in titles
