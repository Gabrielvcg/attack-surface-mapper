from __future__ import annotations

from urllib.parse import urljoin, urlparse

from attack_surface_mapper.http_client import RequestError, build_http_session
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.validators.base import BaseValidator
from attack_surface_mapper.validators.http_fingerprint import baseline_fingerprint, is_static_asset_path, looks_like_baseline, looks_like_login_surface, looks_like_setup_surface, normalise_text


class PanelsValidator(BaseValidator):
    DEFAULT_PATHS: tuple[str, ...] = (
        '/admin',
        '/login',
        '/dashboard',
        '/management',
        '/swagger',
        '/swagger-ui',
        '/actuator',
        '/metrics',
    )

    def __init__(self, timeout: int = 5, paths: tuple[str, ...] | None = None, *, backend: str = 'requests', mode: str = 'passive', user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36', use_baseline_probe: bool = True) -> None:
        self.timeout = timeout
        self.paths = paths or self.DEFAULT_PATHS
        self.backend = backend
        self.mode = mode
        self.user_agent = user_agent
        self.use_baseline_probe = use_baseline_probe

    def run(self, target: str, baseline=None) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []
        parsed = urlparse(target)
        with build_http_session(backend=self.backend, mode=self.mode, timeout=self.timeout, user_agent=self.user_agent) as session:
            baseline = baseline if baseline is not None else (baseline_fingerprint(session, target, self.timeout) if self.use_baseline_probe else None)
            for path in self.paths:
                if is_static_asset_path(path):
                    continue
                url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
                try:
                    response = session.get(url, timeout=self.timeout, allow_redirects=True)
                except RequestError:
                    continue

                if response.status_code >= 400:
                    continue

                preview = normalise_text(response.text)
                if looks_like_setup_surface(response, preview):
                    continue
                if path != '/login' and looks_like_login_surface(response, preview):
                    continue
                include, confidence, reason, verification = self._classify(path, response, preview, baseline)
                if not include:
                    continue

                final_url = response.url
                vulnerabilities.append(
                    Vulnerability(
                        source='custom-panel-check',
                        title=self._build_title(path, response),
                        description=self._description_for(path, final_url),
                        severity=self._severity_for(path, confidence),
                        target=final_url,
                        evidence=f'Status {response.status_code} en {final_url}; validación={reason}',
                        cwe=['CWE-200'],
                        tags=self._tags_for(path),
                        template_id=f"custom-panel-{path.strip('/') or 'root'}",
                        matched_at=final_url,
                        host=parsed.hostname,
                        port=str(parsed.port) if parsed.port else None,
                        scheme=parsed.scheme,
                        type='http',
                        category=self._category_for(path),
                        confidence=confidence,
                        needs_manual_validation=verification != 'confirmed',
                        verification_status=verification,
                    )
                )
        return vulnerabilities

    def _classify(self, path: str, response, body_preview: str, baseline) -> tuple[bool, str, str, str]:
        content_type = (response.headers.get('Content-Type') or '').lower()
        baseline_like = looks_like_baseline(response, baseline)
        score = 0
        reasons: list[str] = []

        if response.status_code in (200, 201, 202, 204):
            score += 2
            reasons.append('endpoint respondió con éxito')
        if not baseline_like:
            score += 2
            reasons.append('respuesta distinta del fallback')
        else:
            reasons.append('respuesta similar al fallback')

        if path == '/metrics':
            if '# help' in body_preview or '# type' in body_preview or 'prometheus' in body_preview:
                score += 3
                reasons.append('firma prometheus encontrada')
            if 'text/plain' in content_type:
                score += 1
                reasons.append('content-type text/plain')
        elif path in {'/actuator', '/management'}:
            if any(token in body_preview for token in ('"_links"', 'actuator', '"status"', 'health')):
                score += 3
                reasons.append('marcadores operativos encontrados')
            if 'json' in content_type:
                score += 1
                reasons.append('content-type json')
        elif path in {'/swagger', '/swagger-ui'}:
            if any(token in body_preview for token in ('swagger-ui', 'swagger ui', 'swagger', 'openapi')):
                score += 3
                reasons.append('marcadores swagger/openapi')
            if 'html' in content_type or 'json' in content_type:
                score += 1
                reasons.append('content-type compatible')
        elif path == '/login':
            if any(token in body_preview for token in ('password', 'sign in', 'log in', 'remember me', 'email')):
                score += 2
                reasons.append('marcadores de login encontrados')
            if 'html' in content_type:
                score += 1
                reasons.append('content-type html')
        elif path in {'/admin', '/dashboard'}:
            if any(token in body_preview for token in ('admin', 'dashboard', 'users', 'settings', 'logout', 'panel')):
                score += 2
                reasons.append('marcadores de panel encontrados')
            if 'html' in content_type:
                score += 1
                reasons.append('content-type html')

        if baseline_like and score < 4:
            return False, 'low', '; '.join(reasons), 'discarded'
        if score >= 6:
            return True, 'high', '; '.join(reasons), 'confirmed'
        if score >= 4:
            return True, 'medium', '; '.join(reasons), 'likely'
        return False, 'low', '; '.join(reasons), 'discarded'

    @staticmethod
    def _severity_for(path: str, confidence: str) -> str:
        if confidence == 'high' and path in {'/metrics', '/actuator', '/management'}:
            return 'medium'
        if path in {'/metrics', '/actuator', '/management', '/admin', '/dashboard', '/swagger', '/swagger-ui'}:
            return 'medium'
        return 'low'

    @staticmethod
    def _build_title(path: str, response) -> str:
        status = response.status_code
        if path == '/metrics':
            return 'Exposed Metrics Endpoint'
        if path == '/actuator':
            return 'Exposed Actuator Endpoint'
        if path == '/management':
            return 'Exposed Management Endpoint'
        if path in {'/swagger', '/swagger-ui'}:
            return 'Exposed API Documentation Panel'
        if path == '/admin':
            return f'Accessible Admin Panel ({status})'
        if path == '/dashboard':
            return f'Accessible Dashboard ({status})'
        if path == '/login':
            return f'Login Surface Discovered ({status})'
        return f'Accessible Sensitive Endpoint ({status})'

    @staticmethod
    def _category_for(path: str) -> str:
        if path == '/login':
            return 'discovery'
        return 'panel-exposure'

    @staticmethod
    def _tags_for(path: str) -> list[str]:
        if path == '/login':
            return ['panel', 'auth', 'discovery']
        return ['panel', 'exposure']

    @staticmethod
    def _description_for(path: str, final_url: str) -> str:
        if path == '/login':
            return f'Se ha descubierto una superficie de autenticación pública en {final_url}; se registra como inventario de superficie, no como acceso indebido.'
        return f'Se ha detectado un panel o endpoint potencialmente sensible accesible en {final_url}.'
