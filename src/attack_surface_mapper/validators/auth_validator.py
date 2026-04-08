from __future__ import annotations

from urllib.parse import urljoin, urlparse

from attack_surface_mapper.http_client import RequestError, build_http_session
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.validators.base import BaseValidator
from attack_surface_mapper.validators.http_fingerprint import baseline_fingerprint, looks_like_baseline, looks_like_login_surface, normalise_text


class AuthValidator(BaseValidator):
    API_SURFACE_PATHS: tuple[str, ...] = (
        '/swagger',
        '/swagger-ui',
        '/openapi.json',
        '/graphql',
        '/api-docs',
    )

    DEFAULT_PROTECTED_PATHS: tuple[str, ...] = (
        '/admin',
        '/dashboard',
        '/management',
        '/actuator',
        '/metrics',
        '/swagger',
        '/swagger-ui',
        '/openapi.json',
        '/graphql',
        '/api-docs',
    )

    PUBLIC_AUTH_ENTRY_PATHS: tuple[str, ...] = (
        '/login',
        '/signin',
        '/sign-in',
        '/signup',
        '/register',
        '/accounts/login',
        '/accounts/register',
        '/admin/login',
    )

    def __init__(self, timeout: int = 6, paths: tuple[str, ...] | None = None, *, backend: str = 'requests', mode: str = 'passive', user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36', use_baseline_probe: bool = True, observed_only: bool = False) -> None:
        self.timeout = timeout
        self.paths = paths or self.DEFAULT_PROTECTED_PATHS
        self.backend = backend
        self.mode = mode
        self.user_agent = user_agent
        self.use_baseline_probe = use_baseline_probe
        self.observed_only = observed_only

    def run(self, target: str, baseline=None) -> list[Vulnerability]:
        findings: list[Vulnerability] = []
        parsed_target = urlparse(target)
        with build_http_session(backend=self.backend, mode=self.mode, timeout=self.timeout, user_agent=self.user_agent) as session:
            response = session.get(target, timeout=self.timeout, allow_redirects=True)
            final_url = response.url
            final_parsed = urlparse(final_url)
            host = final_parsed.hostname or parsed_target.hostname
            port = str(final_parsed.port) if final_parsed.port else (str(parsed_target.port) if parsed_target.port else None)
            scheme = final_parsed.scheme or parsed_target.scheme
            baseline = baseline if baseline is not None else (baseline_fingerprint(session, target, self.timeout) if self.use_baseline_probe else None)

            findings.extend(self._check_cookie_flags(response, final_url, host, port, scheme))
            if not self.observed_only:
                findings.extend(self._check_protected_paths(session, target, host, port, scheme, baseline))
        return findings

    def _check_cookie_flags(self, response, url: str, host: str | None, port: str | None, scheme: str | None) -> list[Vulnerability]:
        findings: list[Vulnerability] = []
        raw_cookie_headers = self._extract_set_cookie_headers(response)
        for cookie_header in raw_cookie_headers:
            lower_header = cookie_header.lower()
            name = cookie_header.split('=', 1)[0].strip() or 'cookie'
            is_session_cookie = self._is_likely_session_cookie(name)
            is_csrf_cookie = self._is_csrf_cookie(name)
            if not is_session_cookie and not is_csrf_cookie:
                continue
            if is_session_cookie and 'httponly' not in lower_header:
                findings.append(Vulnerability(source='custom-auth-check', title='Cookie Without HttpOnly Flag', description='La aplicación establece una cookie sin el flag HttpOnly.', severity='medium', target=url, evidence=f'Set-Cookie: {self._truncate(cookie_header)}', cwe=['CWE-1004'], tags=['auth', 'cookie', 'session'], template_id=f'custom-auth-cookie-httponly-{name.lower()}', matched_at=url, host=host, port=port, scheme=scheme, type='http', category='authentication', confidence='high', verification_status='confirmed'))
            if (scheme == 'https') and ('secure' not in lower_header):
                findings.append(Vulnerability(source='custom-auth-check', title='Cookie Without Secure Flag', description='La aplicación HTTPS establece una cookie sin el flag Secure.', severity='medium', target=url, evidence=f'Set-Cookie: {self._truncate(cookie_header)}', cwe=['CWE-614'], tags=['auth', 'cookie', 'session'], template_id=f'custom-auth-cookie-secure-{name.lower()}', matched_at=url, host=host, port=port, scheme=scheme, type='http', category='authentication', confidence='high', verification_status='confirmed'))
            if 'samesite=' not in lower_header:
                findings.append(Vulnerability(source='custom-auth-check', title='Cookie Without SameSite Attribute', description='La aplicación establece una cookie sin el atributo SameSite.', severity='low', target=url, evidence=f'Set-Cookie: {self._truncate(cookie_header)}', cwe=['CWE-1275'], tags=['auth', 'cookie', 'session'], template_id=f'custom-auth-cookie-samesite-{name.lower()}', matched_at=url, host=host, port=port, scheme=scheme, type='http', category='authentication', confidence='high', verification_status='confirmed'))
        return findings

    def _check_protected_paths(self, session, target: str, host: str | None, port: str | None, scheme: str | None, baseline) -> list[Vulnerability]:
        findings: list[Vulnerability] = []
        for path in self.paths:
            url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
            try:
                response = session.get(url, timeout=self.timeout, allow_redirects=True)
            except RequestError:
                continue

            if response.status_code in (401, 403):
                endpoint_name = self._endpoint_name(path)
                findings.append(Vulnerability(
                    source='custom-auth-check',
                    title=f'Protected {endpoint_name} Discovered',
                    description=f'Se ha descubierto un endpoint sensible protegido ({response.status_code}) en {path}.',
                    severity='low',
                    target=response.url,
                    evidence=f'GET {response.url} devolvió {response.status_code}; el recurso parece existir y requiere autenticación.',
                    cwe=['CWE-200'],
                    tags=['auth', 'access-control', 'discovery'],
                    template_id=f"custom-auth-protected-{path.strip('/') or 'root'}",
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

            if response.status_code not in (200, 201, 202, 204):
                continue
            body_preview = normalise_text(response.text, 1500)
            normalised_path = self._normalise_candidate_path(path)
            normalised_response_path = self._normalise_candidate_path(urlparse(response.url).path)

            # Public auth entry points such as login/register pages are expected to be
            # reachable without prior authentication. They should be handled as discovery
            # surfaces elsewhere, not as access-control findings here. Admin/dashboard
            # redirects to login are still useful as low-impact discovery signals.
            if normalised_path in self.PUBLIC_AUTH_ENTRY_PATHS:
                continue
            if normalised_response_path in self.PUBLIC_AUTH_ENTRY_PATHS and normalised_path not in {'/admin', '/dashboard'}:
                continue

            if self._is_public_auth_entry(path, response.url, body_preview) or looks_like_login_surface(response, body_preview):
                if path in {'/admin', '/dashboard'}:
                    endpoint_name = self._endpoint_name(path)
                    findings.append(Vulnerability(
                        source='custom-auth-check',
                        title=f'Protected {endpoint_name} Login Surface Discovered',
                        description=f'Se ha descubierto una superficie de login asociada a {path}; el recurso sensible parece requerir autenticación.',
                        severity='low',
                        target=response.url,
                        evidence=f'GET {response.url} devolvió {response.status_code}; la respuesta parece una pantalla de login y no un acceso autenticado al recurso.',
                        cwe=['CWE-200'],
                        tags=['auth', 'access-control', 'discovery', 'login'],
                        template_id=f"custom-auth-login-surface-{path.strip('/') or 'root'}",
                        matched_at=response.url,
                        host=host,
                        port=port,
                        scheme=scheme,
                        type='http',
                        category='discovery',
                        confidence='high',
                        needs_manual_validation=False,
                        verification_status='confirmed',
                    ))
                continue
            include, confidence, reason, verification = self._classify_open_access(path, response, body_preview, baseline)
            if not include:
                continue
            if path in self.API_SURFACE_PATHS:
                if verification == 'confirmed':
                    verification = 'likely'
                    reason = f'{reason}; superficie api pública no demuestra acceso privilegiado por sí sola'
                if confidence == 'high':
                    confidence = 'medium'
                title, description, severity = self._api_surface_metadata(path)
                findings.append(Vulnerability(
                    source='custom-auth-check',
                    title=title,
                    description=description,
                    severity=severity,
                    target=response.url,
                    evidence=f'GET {response.url} devolviÃ³ {response.status_code}; validaciÃ³n={reason}',
                    cwe=['CWE-200'],
                    tags=['api', 'exposure'],
                    template_id=f"custom-auth-open-{path.strip('/') or 'root'}",
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
                continue
            endpoint_name = self._endpoint_name(path)
            findings.append(Vulnerability(
                source='custom-auth-check',
                title=f'{endpoint_name} Accessible Without Authentication',
                description=f'Se ha detectado acceso sin autenticación a un endpoint sensible: {path}.',
                severity=self._severity_for(path, confidence),
                target=response.url,
                evidence=f'GET {response.url} devolvió {response.status_code}; validación={reason}',
                cwe=['CWE-306'],
                tags=['auth', 'access-control', 'exposure'],
                template_id=f"custom-auth-open-{path.strip('/') or 'root'}",
                matched_at=response.url,
                host=host,
                port=port,
                scheme=scheme,
                type='http',
                category='authentication',
                confidence=confidence,
                needs_manual_validation=verification != 'confirmed',
                verification_status=verification,
            ))
        return findings

    def _classify_open_access(self, path: str, response, body_preview: str, baseline) -> tuple[bool, str, str, str]:
        baseline_like = looks_like_baseline(response, baseline)
        content_type = (response.headers.get('Content-Type') or '').lower()
        score = 0
        reasons: list[str] = []

        score += 2
        reasons.append('endpoint sensible respondió con éxito')

        if not baseline_like:
            score += 2
            reasons.append('respuesta distinta del fallback')
        else:
            reasons.append('parece fallback/base')

        if path == '/graphql':
            if 'graphql' in body_preview:
                score += 2
                reasons.append('marca graphql encontrada')
            if any(token in body_preview for token in ('query', 'mutation', '__schema', 'errors', 'data')):
                score += 2
                reasons.append('estructura graphql detectada')
            if 'json' in content_type:
                score += 1
                reasons.append('content-type json')
        elif path in {'/swagger', '/swagger-ui', '/openapi.json', '/api-docs'}:
            if any(token in body_preview for token in ('swagger', 'openapi', 'swagger-ui')):
                score += 3
                reasons.append('marcadores swagger/openapi')
            if 'json' in content_type or 'html' in content_type:
                score += 1
                reasons.append('content-type compatible con docs de api')
        elif path in {'/metrics', '/actuator', '/management'}:
            if any(token in body_preview for token in ('# help', '# type', 'prometheus')):
                score += 3
                reasons.append('firma de métricas/prometheus')
            if any(token in body_preview for token in ('actuator', '_links', 'health', 'status')):
                score += 2
                reasons.append('marcadores operativos encontrados')
            if any(token in content_type for token in ('json', 'text/plain')):
                score += 1
                reasons.append('content-type operativo compatible')
        elif path in {'/admin', '/dashboard'}:
            if any(token in body_preview for token in ('admin', 'dashboard', 'users', 'settings', 'logout', 'panel')):
                score += 2
                reasons.append('marcadores de panel encontrados')
            if 'html' in content_type:
                score += 1
                reasons.append('content-type html')
        else:
            if not baseline_like:
                score += 1

        if baseline_like and score < 4:
            return False, 'low', '; '.join(reasons), 'discarded'
        if score >= 6:
            return True, 'high', '; '.join(reasons), 'confirmed'
        if score >= 4:
            return True, 'medium', '; '.join(reasons), 'likely'
        return False, 'low', '; '.join(reasons), 'discarded'

    @staticmethod
    def _endpoint_name(path: str) -> str:
        mapping = {
            '/metrics': 'Metrics Endpoint',
            '/actuator': 'Actuator Endpoint',
            '/management': 'Management Endpoint',
            '/swagger': 'Swagger UI',
            '/swagger-ui': 'Swagger UI',
            '/openapi.json': 'OpenAPI Specification',
            '/api-docs': 'API Documentation',
            '/graphql': 'GraphQL Endpoint',
            '/admin': 'Admin Panel',
            '/dashboard': 'Dashboard',
            '/login': 'Login Endpoint',
        }
        return mapping.get(path, f'Endpoint {path}')

    @staticmethod
    def _api_surface_metadata(path: str) -> tuple[str, str, str]:
        if path in {'/swagger', '/swagger-ui', '/api-docs'}:
            return (
                'Swagger UI Exposed',
                'Se ha detectado una interfaz de documentación o superficie API accesible sin restricciones claras.',
                'medium',
            )
        if path == '/openapi.json':
            return (
                'OpenAPI Specification Exposed',
                'Se ha detectado un documento OpenAPI/Swagger accesible públicamente.',
                'medium',
            )
        if path == '/graphql':
            return (
                'GraphQL Surface Exposed',
                'Se ha detectado una superficie GraphQL accesible sin evidencia suficiente de control de acceso fuerte.',
                'medium',
            )
        return (
            'API Surface Exposed',
            f'Se ha detectado una superficie de API accesible públicamente en {path}.',
            'medium',
        )

    @staticmethod
    def _extract_set_cookie_headers(response) -> list[str]:
        raw = getattr(response, 'raw', None)
        if raw and hasattr(raw, 'headers'):
            try:
                return list(raw.headers.getlist('Set-Cookie'))
            except Exception:
                pass
        header = response.headers.get('Set-Cookie')
        return [header] if header else []

    @staticmethod
    def _truncate(value: str, max_length: int = 160) -> str:
        return value if len(value) <= max_length else value[:max_length] + '...[truncated]'

    @staticmethod
    def _is_csrf_cookie(name: str) -> bool:
        lowered = (name or '').strip().lower()
        return any(token in lowered for token in ('csrf', 'xsrf'))

    @classmethod
    def _is_likely_session_cookie(cls, name: str) -> bool:
        lowered = (name or '').strip().lower()
        if cls._is_csrf_cookie(lowered):
            return False
        return any(token in lowered for token in ('session', 'sess', 'sid', 'jwt', 'auth', 'access', 'refresh', 'remember', 'login'))

    @classmethod
    def _is_public_auth_entry(cls, path: str, response_url: str, body_preview: str) -> bool:
        response_path = urlparse(response_url or '').path
        candidates = {cls._normalise_candidate_path(path), cls._normalise_candidate_path(response_path)}
        if not any(candidate in cls.PUBLIC_AUTH_ENTRY_PATHS for candidate in candidates):
            return False
        return cls._looks_like_public_auth_page(body_preview)

    @staticmethod
    def _normalise_candidate_path(value: str) -> str:
        return (value or '').split('?', 1)[0].rstrip('/').lower() or '/'

    @staticmethod
    def _looks_like_public_auth_page(body_preview: str) -> bool:
        return any(token in body_preview for token in ('password', 'sign in', 'log in', 'remember me', 'email', 'username', 'register', 'create account', 'csrfmiddlewaretoken'))

    @staticmethod
    def _severity_for(path: str, confidence: str) -> str:
        if confidence == 'high' and path in {'/metrics', '/actuator', '/management', '/graphql', '/openapi.json'}:
            return 'high'
        if path in {'/metrics', '/actuator', '/management', '/graphql', '/openapi.json'}:
            return 'medium'
        if path in {'/admin', '/dashboard', '/swagger', '/swagger-ui', '/api-docs'}:
            return 'medium'
        return 'medium'
