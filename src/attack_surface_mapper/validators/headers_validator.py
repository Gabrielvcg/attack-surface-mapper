from __future__ import annotations

from urllib.parse import urlparse

from attack_surface_mapper.http_client import HttpResponse, http_get
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.validators.base import BaseValidator


def _header_value(headers: dict[str, str], name: str) -> str:
    lower_name = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lower_name:
            return str(value)
    return ''


def _is_browser_document(response: HttpResponse) -> bool:
    content_type = _header_value(response.headers, 'Content-Type').lower()
    body_preview = (response.text or '')[:800].lstrip().lower()
    if any(token in content_type for token in ('text/html', 'application/xhtml+xml')):
        return True
    if not content_type and any(token in body_preview for token in ('<!doctype html', '<html', '<form', '<title')):
        return True
    return False


class HeadersValidator(BaseValidator):
    REQUIRED_HEADERS: dict[str, dict[str, object]] = {
        'content-security-policy': {
            'title': 'Missing Content-Security-Policy Header',
            'description': 'La aplicación no devuelve la cabecera Content-Security-Policy.',
            'severity': 'medium',
            'cwe': ['CWE-693'],
            'category': 'headers',
        },
        'x-frame-options': {
            'title': 'Missing X-Frame-Options Header',
            'description': 'La aplicación no devuelve la cabecera X-Frame-Options.',
            'severity': 'medium',
            'cwe': ['CWE-1021'],
            'category': 'headers',
        },
        'x-content-type-options': {
            'title': 'Missing X-Content-Type-Options Header',
            'description': 'La aplicación no devuelve la cabecera X-Content-Type-Options.',
            'severity': 'low',
            'cwe': ['CWE-16'],
            'category': 'headers',
        },
        'referrer-policy': {
            'title': 'Missing Referrer-Policy Header',
            'description': 'La aplicación no devuelve la cabecera Referrer-Policy.',
            'severity': 'low',
            'cwe': ['CWE-200'],
            'category': 'headers',
        },
    }

    def __init__(self, timeout: int = 8, user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36', *, backend: str = 'auto', mode: str = 'passive') -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.backend = backend
        self.mode = mode

    def run(self, target: str, response: HttpResponse | None = None) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []
        response = response or http_get(target, timeout=self.timeout, allow_redirects=True, user_agent=self.user_agent, backend=self.backend, mode=self.mode)

        headers = {key.lower(): value for key, value in response.headers.items()}
        parsed = urlparse(response.url)
        base_target = response.url
        browser_document = _is_browser_document(response)

        for header_name, metadata in self.REQUIRED_HEADERS.items():
            if not browser_document:
                continue
            if header_name in headers:
                continue

            vulnerabilities.append(
                Vulnerability(
                    source='custom-header-check',
                    title=str(metadata['title']),
                    description=str(metadata['description']),
                    severity=str(metadata['severity']),
                    target=base_target,
                    evidence=f'Cabecera ausente: {header_name}',
                    cwe=list(metadata['cwe']),
                    tags=['headers', 'misconfig'],
                    template_id=f'custom-header-{header_name}',
                    matched_at=base_target,
                    host=parsed.hostname,
                    port=str(parsed.port) if parsed.port else None,
                    scheme=parsed.scheme,
                    type='http',
                    category=str(metadata['category']),
                    confidence='high',
                )
            )

        if parsed.scheme == 'https' and 'strict-transport-security' not in headers:
            vulnerabilities.append(
                Vulnerability(
                    source='custom-header-check',
                    title='Missing Strict-Transport-Security Header',
                    description='La aplicación HTTPS no devuelve la cabecera HSTS.',
                    severity='medium',
                    target=base_target,
                    evidence='Cabecera ausente: strict-transport-security',
                    cwe=['CWE-319'],
                    tags=['headers', 'tls', 'misconfig'],
                    template_id='custom-header-strict-transport-security',
                    matched_at=base_target,
                    host=parsed.hostname,
                    port=str(parsed.port) if parsed.port else None,
                    scheme=parsed.scheme,
                    type='http',
                    category='headers',
                    confidence='high',
                )
            )

        return vulnerabilities
