from __future__ import annotations

from urllib.parse import urljoin, urlparse

from attack_surface_mapper.http_client import RequestError, build_http_session
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.validators.base import BaseValidator
from attack_surface_mapper.validators.http_fingerprint import baseline_fingerprint, looks_like_baseline, looks_like_login_surface, normalise_text


def _header_value(headers: dict[str, str], name: str) -> str:
    lower_name = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == lower_name:
            return str(value)
    return ''


def _graphql_signature_strength(preview: str) -> str:
    strong_tokens = (
        'graphql',
        '__schema',
        'graphiql',
        'graphql-playground',
        'apollo sandbox',
        'must provide query string',
    )
    if any(token in preview for token in strong_tokens):
        return 'strong'
    weak_token_groups = (
        ('errors', 'message'),
        ('query', 'mutation'),
        ('operationname', 'variables'),
    )
    if any(all(token in preview for token in group) for group in weak_token_groups):
        return 'weak'
    return ''


class APIValidator(BaseValidator):
    DEFAULT_PATHS: tuple[str, ...] = (
        '/swagger',
        '/swagger-ui',
        '/openapi.json',
        '/api-docs',
        '/graphql',
        '/graphql/playground',
    )

    def __init__(self, timeout: int = 6, paths: tuple[str, ...] | None = None, *, backend: str = 'requests', mode: str = 'passive', user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36', use_baseline_probe: bool = True, observed_only: bool = False) -> None:
        self.timeout = timeout
        self.paths = paths or self.DEFAULT_PATHS
        self.backend = backend
        self.mode = mode
        self.user_agent = user_agent
        self.use_baseline_probe = use_baseline_probe
        self.observed_only = observed_only

    def run(self, target: str, baseline=None) -> list[Vulnerability]:
        findings: list[Vulnerability] = []
        parsed_target = urlparse(target)
        host = parsed_target.hostname
        port = str(parsed_target.port) if parsed_target.port else None
        scheme = parsed_target.scheme
        with build_http_session(backend=self.backend, mode=self.mode, timeout=self.timeout, user_agent=self.user_agent) as session:
            baseline = baseline if baseline is not None else (baseline_fingerprint(session, target, self.timeout) if self.use_baseline_probe else None)
            if not self.observed_only:
                findings.extend(self._check_cors(session, target, host, port, scheme))
                findings.extend(self._check_api_docs(session, target, host, port, scheme, baseline))
        return findings

    def _check_cors(self, session, target: str, host: str | None, port: str | None, scheme: str | None) -> list[Vulnerability]:
        findings: list[Vulnerability] = []
        headers = {'Origin': 'https://evil.example'}
        try:
            response = session.get(target, headers=headers, timeout=self.timeout, allow_redirects=True)
        except RequestError:
            return findings

        allow_origin = _header_value(response.headers, 'Access-Control-Allow-Origin').strip()
        allow_credentials = _header_value(response.headers, 'Access-Control-Allow-Credentials').strip()
        credentials_enabled = allow_credentials.lower() == 'true'
        if allow_origin == '*':
            findings.append(Vulnerability(
                source='custom-api-check',
                title='Permissive CORS Policy' if credentials_enabled else 'Broad CORS Policy Observed',
                description='El servidor permite cualquier origen mediante Access-Control-Allow-Origin: *.',
                severity='medium' if credentials_enabled else 'low',
                target=response.url,
                evidence=f'Access-Control-Allow-Origin: {allow_origin}; Access-Control-Allow-Credentials: {allow_credentials or "<absent>"}',
                cwe=['CWE-942'],
                tags=['api', 'cors'],
                template_id='custom-api-cors-wildcard',
                matched_at=response.url,
                host=host,
                port=port,
                scheme=scheme,
                type='http',
                category='api',
                confidence='high' if credentials_enabled else 'medium',
                needs_manual_validation=not credentials_enabled,
                verification_status='confirmed' if credentials_enabled else 'likely',
            ))
        return findings

    def _check_api_docs(self, session, target: str, host: str | None, port: str | None, scheme: str | None, baseline) -> list[Vulnerability]:
        findings: list[Vulnerability] = []
        for path in self.paths:
            url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
            try:
                response = session.get(url, timeout=self.timeout, allow_redirects=True)
            except RequestError:
                continue

            if response.status_code in (401, 403):
                findings.append(Vulnerability(
                    source='custom-api-check',
                    title=f'Protected API Surface Discovered ({path})',
                    description=f'Se ha descubierto una superficie de API protegida en {path}.',
                    severity='low',
                    target=response.url,
                    evidence=f'GET {response.url} devolvió {response.status_code}; el recurso parece existir y requiere autenticación.',
                    cwe=['CWE-200'],
                    tags=['api', 'discovery'],
                    template_id=f"custom-api-protected-{path.strip('/') or 'root'}",
                    matched_at=response.url,
                    host=host,
                    port=port,
                    scheme=scheme,
                    type='http',
                    category='discovery',
                    confidence='medium',
                    needs_manual_validation=False,
                    verification_status='confirmed',
                ))
                continue

            if response.status_code >= 400:
                continue
            preview = normalise_text(response.text, 1500)
            content_type = (response.headers.get('Content-Type') or '').lower()
            include, confidence, reason, verification, title, description, severity = self._classify_path(path, response, preview, content_type, baseline)
            if not include:
                continue
            findings.append(Vulnerability(
                source='custom-api-check',
                title=title,
                description=description,
                severity=severity,
                target=response.url,
                evidence=f'GET {response.url} devolvió documentación o superficie API; validación={reason}',
                cwe=['CWE-200'],
                tags=['api', 'documentation', 'exposure'],
                template_id=f"custom-api-docs-{path.strip('/') or 'root'}",
                matched_at=response.url,
                host=host,
                port=port,
                scheme=scheme,
                type='http',
                category='api',
                confidence=confidence,
                needs_manual_validation=verification != 'confirmed',
                verification_status=verification,
            ))
        return findings

    def _classify_path(self, path: str, response, preview: str, content_type: str, baseline):
        baseline_like = looks_like_baseline(response, baseline)
        graphql_signature = ''
        if looks_like_login_surface(response, preview):
            title = 'API Surface Exposed'
            description = 'Se ha detectado una superficie de API accesible públicamente.'
            if path in {'/swagger', '/swagger-ui', '/api-docs'}:
                title = 'Swagger UI Exposed'
                description = 'Se ha detectado una interfaz de documentación Swagger accesible sin restricciones claras.'
            elif path == '/openapi.json':
                title = 'OpenAPI Specification Exposed'
                description = 'Se ha detectado un documento OpenAPI/Swagger accesible públicamente.'
            elif path.startswith('/graphql'):
                title = 'GraphQL Surface Exposed'
                description = 'Se ha detectado un endpoint o interfaz GraphQL accesible.'
            return False, 'low', 'respuesta parece una superficie de login pública', 'discarded', title, description, 'medium'
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

        title = 'API Surface Exposed'
        description = 'Se ha detectado una superficie de API accesible públicamente.'
        severity = 'medium'

        if path in {'/swagger', '/swagger-ui', '/api-docs'}:
            title = 'Swagger UI Exposed'
            description = 'Se ha detectado una interfaz de documentación Swagger accesible sin restricciones claras.'
            if any(token in preview for token in ('swagger-ui', 'swagger ui', 'swagger', 'openapi')):
                score += 3
                reasons.append('marcadores swagger/openapi')
            if 'html' in content_type or 'json' in content_type:
                score += 1
                reasons.append('content-type compatible con documentación')
        elif path == '/openapi.json':
            title = 'OpenAPI Specification Exposed'
            description = 'Se ha detectado un documento OpenAPI/Swagger accesible públicamente.'
            if response.status_code == 200 and ('openapi' in preview or 'swagger' in preview):
                score += 3
                reasons.append('marcadores openapi encontrados')
            if response.status_code == 200 and 'json' in content_type:
                score += 1
                reasons.append('content-type json')
        elif path.startswith('/graphql'):
            title = 'GraphQL Surface Exposed'
            description = 'Se ha detectado un endpoint o interfaz GraphQL accesible.'
            severity = 'high'
            graphql_signature = _graphql_signature_strength(preview)
            if graphql_signature == 'strong':
                score += 3
                reasons.append('marcadores graphql fuertes encontrados')
            elif graphql_signature == 'weak':
                score += 2
                reasons.append('marcadores graphql plausibles encontrados')
            if 'json' in content_type or 'html' in content_type:
                score += 1
                reasons.append('content-type compatible')

        if path.startswith('/graphql') and not graphql_signature:
            reasons.append('sin firma graphql suficiente')
            return False, 'low', '; '.join(reasons), 'discarded', title, description, severity
        if path.startswith('/graphql') and baseline_like and graphql_signature != 'strong':
            reasons.append('respuesta similar al fallback sin firma graphql fuerte')
            return False, 'low', '; '.join(reasons), 'discarded', title, description, severity
        if baseline_like and score < 4:
            return False, 'low', '; '.join(reasons), 'discarded', title, description, severity
        if path in {'/swagger', '/swagger-ui', '/api-docs', '/openapi.json'} and score >= 4:
            confidence = 'high' if score >= 6 else 'medium'
            reasons.append('documentación api pública: revisar antes de tratarla como riesgo principal')
            return True, confidence, '; '.join(reasons), 'likely', title, description, severity
        if path.startswith('/graphql') and score >= 4:
            confidence = 'high' if graphql_signature == 'strong' else 'medium'
            reasons.append('superficie graphql pública: requiere evidencia adicional para acceso indebido')
            return True, confidence, '; '.join(reasons), 'likely', title, description, severity
        if score >= 6:
            return True, 'high', '; '.join(reasons), 'confirmed', title, description, severity
        if score >= 4:
            return True, 'medium', '; '.join(reasons), 'likely', title, description, severity
        return False, 'low', '; '.join(reasons), 'discarded', title, description, severity
