from __future__ import annotations

import re
from urllib.parse import urlparse

from attack_surface_mapper.http_client import HttpResponse, build_http_session
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.validators.base import BaseValidator

TITLE_RE = re.compile(r'<title>(.*?)</title>', re.IGNORECASE | re.DOTALL)
GENERATOR_META_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)


class FingerprintValidator(BaseValidator):
    def __init__(
        self,
        timeout: int = 6,
        *,
        backend: str = 'auto',
        mode: str = 'passive',
        user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    ) -> None:
        self.timeout = timeout
        self.backend = backend
        self.mode = mode
        self.user_agent = user_agent

    def _detect_stack(self, headers: dict[str, str], body: str) -> list[tuple[str, str, str]]:
        body_lower = (body or '').lower()
        server = ' '.join(v for k, v in headers.items() if k.lower() == 'server').lower()
        powered = ' '.join(v for k, v in headers.items() if k.lower() == 'x-powered-by').lower()
        title_match = TITLE_RE.search(body or '')
        title = ' '.join(title_match.group(1).split()).strip().lower() if title_match else ''
        generator = ''
        gen_match = GENERATOR_META_RE.search(body or '')
        if gen_match:
            generator = gen_match.group(1).strip().lower()

        findings: list[tuple[str, str, str]] = []

        def add(stack: str, evidence: str, confidence: str = 'medium') -> None:
            key = stack.lower()
            if any(existing[0].lower() == key for existing in findings):
                return
            findings.append((stack, evidence, confidence))

        if 'apache' in server:
            add('Apache httpd', f'Server={server}', 'high')
        if 'nginx' in server:
            add('Nginx', f'Server={server}', 'high')
        if 'iis' in server:
            add('Microsoft IIS', f'Server={server}', 'high')
        if 'express' in powered or 'express' in body_lower:
            add('Express', f'X-Powered-By={powered or "n/a"}', 'medium')
        if 'php' in powered or 'php' in body_lower:
            add('PHP', f'X-Powered-By={powered or "body pattern"}', 'medium')
        if 'django' in powered or 'csrfmiddlewaretoken' in body_lower:
            add('Django', 'csrfmiddlewaretoken detectado', 'medium')
        if 'spring' in body_lower or 'whitelabel error page' in body_lower:
            add('Spring Boot', 'Patrón Spring detectado en HTML', 'medium')
        if 'wordpress' in body_lower or 'wp-content/' in body_lower or 'wp-includes/' in body_lower or 'wordpress' in generator:
            add('WordPress', generator or 'Patrón WordPress detectado', 'medium')
        if 'next.js' in body_lower or '/_next/' in body_lower:
            add('Next.js', 'Patrón Next.js detectado', 'medium')
        if 'ng-version' in body_lower or '<app-root' in body_lower:
            add('Angular', title or 'Patrón Angular detectado', 'medium')
        if '__next' in body_lower or 'id="__next"' in body_lower:
            add('Next.js', title or 'Contenedor __next detectado', 'medium')
        if 'react' in body_lower and ('root' in body_lower or 'reactroot' in body_lower):
            add('React', title or 'Patrón React detectado', 'low')
        if 'vue' in body_lower and 'id="app"' in body_lower:
            add('Vue.js', title or 'Patrón Vue detectado', 'low')
        return findings

    def run(self, target: str, response: HttpResponse | None = None) -> list[Vulnerability]:
        if response is None:
            session = build_http_session(backend=self.backend, mode=self.mode, timeout=self.timeout, include_js=False, user_agent=self.user_agent, scrapling_mode='auto')
            try:
                if hasattr(session, '__enter__'):
                    with session as managed_session:
                        response = managed_session.get(target, timeout=self.timeout, allow_redirects=True)
                else:
                    response = session.get(target, timeout=self.timeout, allow_redirects=True)
            finally:
                close = getattr(session, 'close', None)
                if close is not None and not hasattr(session, '__enter__'):
                    try:
                        close()
                    except Exception:
                        pass
        parsed = urlparse(response.url)
        host = parsed.hostname
        port = str(parsed.port) if parsed.port else None
        findings: list[Vulnerability] = []
        for stack, evidence, confidence in self._detect_stack(response.headers, response.text):
            findings.append(Vulnerability(
                source='custom-fingerprint-check',
                title=f'Technology Fingerprint Detected ({stack})',
                description='Se ha identificado una tecnología o framework probable a partir de cabeceras y patrones del contenido servido.',
                severity='low',
                target=response.url,
                evidence=evidence,
                cwe=['CWE-200'],
                tags=['fingerprint', 'discovery', stack.lower().replace(' ', '-')],
                template_id=f'custom-fingerprint-{stack.lower().replace(" ", "-")}',
                matched_at=response.url,
                host=host,
                port=port,
                scheme=parsed.scheme,
                type='http',
                category='discovery',
                confidence=confidence,
                verification_status='confirmed' if confidence == 'high' else 'likely',
                needs_manual_validation=False,
            ))
        return findings
