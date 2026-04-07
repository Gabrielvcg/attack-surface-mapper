from __future__ import annotations

import re
from dataclasses import dataclass, field
from html import unescape
from urllib.parse import urljoin, urlparse

from attack_surface_mapper.models.vulnerability import Vulnerability

FORM_RE = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.IGNORECASE | re.DOTALL)
ATTR_RE = re.compile(r'''([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?''', re.DOTALL)
INPUT_RE = re.compile(r"<(?:input|textarea|select)\b(?P<attrs>[^>]*)>", re.IGNORECASE | re.DOTALL)
SCRIPT_SRC_RE = re.compile(r'''<script\b[^>]*\bsrc\s*=\s*(["\'])(.*?)\1''', re.IGNORECASE | re.DOTALL)
ABSOLUTE_HINT_RE = re.compile(r'''https?://[^"\'\s<>]+''', re.IGNORECASE)
RELATIVE_HINT_RE = re.compile(r'''(?<![A-Za-z0-9_])(/(?:api|graphql|swagger|swagger-ui|openapi|api-docs|admin|dashboard|login|auth|upload|debug|actuator|metrics|v[0-9]+)[^"\'\s<>]*)''', re.IGNORECASE)
GENERIC_ENDPOINT_RE = re.compile(r'''(?<![A-Za-z0-9_])(/[^"\'\s<>]*(?:login|admin|dashboard|upload|graphql|swagger|openapi|api-docs|actuator|metrics|debug|reset|export)[^"\'\s<>]*)''', re.IGNORECASE)
STATIC_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.woff', '.woff2', '.ttf', '.eot', '.map', '.mp4', '.webm', '.pdf')


@dataclass(slots=True)
class DiscoveredForm:
    page_url: str
    action_url: str
    action_path: str
    method: str
    input_names: list[str] = field(default_factory=list)
    input_types: list[str] = field(default_factory=list)
    has_password: bool = False
    has_file_input: bool = False
    has_csrf_token: bool = False


@dataclass(slots=True)
class DiscoveryAnalysis:
    discovered_urls: list[str] = field(default_factory=list)
    candidate_paths: list[str] = field(default_factory=list)
    panel_paths: list[str] = field(default_factory=list)
    api_paths: list[str] = field(default_factory=list)
    auth_paths: list[str] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    js_hints: list[str] = field(default_factory=list)


def _parse_attrs(raw: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for key, dbl_quoted, sgl_quoted, bare_value in ATTR_RE.findall(raw or ''):
        value = dbl_quoted or sgl_quoted or bare_value
        attrs[key.lower()] = unescape((value or '').strip())
    return attrs


def _normalise_same_host_path(candidate: str, base_url: str, target: str) -> str | None:
    if not candidate:
        return None
    candidate = candidate.strip()
    if not candidate or candidate.startswith(('javascript:', 'mailto:', 'data:', '#')):
        return None
    absolute = urljoin(base_url, candidate)
    parsed_abs = urlparse(absolute)
    parsed_target = urlparse(target)
    if parsed_abs.scheme not in ('http', 'https'):
        return None
    if parsed_abs.netloc and parsed_abs.netloc != parsed_target.netloc:
        return None
    path = parsed_abs.path or '/'
    if parsed_abs.query:
        path = f"{path}?{parsed_abs.query}"
    return path


def _dedupe_preserve(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _looks_like_static_asset(path: str) -> bool:
    lower = (path or '').lower()
    return lower.endswith(STATIC_EXTENSIONS)


def _is_probable_auth_form(form: DiscoveredForm) -> bool:
    joined_names = ' '.join(form.input_names).lower()
    joined_types = ' '.join(form.input_types).lower()
    action = form.action_path.lower()
    page = form.page_url.lower()
    if form.has_password:
        return True
    auth_tokens = ('login', 'signin', 'auth', 'password', 'passwd', 'username', 'user')
    return any(token in joined_names for token in auth_tokens) and ('password' in joined_types or 'login' in action or 'login' in page)


def _csrf_indicator_present(page_body: str) -> bool:
    lower_body = (page_body or '').lower()
    return any(token in lower_body for token in ('csrf', 'xsrf', 'authenticity_token', 'requesttoken', 'user_token'))


def analyse_documents(target: str, documents: dict[str, str]) -> DiscoveryAnalysis:
    candidate_paths: list[str] = []
    panel_paths: list[str] = []
    api_paths: list[str] = []
    auth_paths: list[str] = []
    forms: list[DiscoveredForm] = []
    js_hints: list[str] = []

    discovered_urls = sorted(documents.keys())
    for document_url, body in documents.items():
        doc_path = _normalise_same_host_path(document_url, document_url, target)
        if doc_path and not _looks_like_static_asset(doc_path):
            candidate_paths.append(doc_path)
        lower_body = body.lower()
        if '<form' in lower_body:
            page_has_csrf_indicator = _csrf_indicator_present(body)
            for match in FORM_RE.finditer(body):
                attrs = _parse_attrs(match.group('attrs'))
                form_body = match.group('body') or ''
                action_candidate = attrs.get('action') or document_url
                action_url = urljoin(document_url, action_candidate)
                action_path = _normalise_same_host_path(action_url, document_url, target) or (urlparse(document_url).path or '/')
                method = (attrs.get('method') or 'get').upper()
                input_names: list[str] = []
                input_types: list[str] = []
                has_password = False
                has_file_input = False
                has_csrf_token = False
                for input_match in INPUT_RE.finditer(form_body):
                    input_attrs = _parse_attrs(input_match.group('attrs'))
                    input_name = input_attrs.get('name', '').strip()
                    input_type = input_attrs.get('type', 'text').strip().lower()
                    if input_name:
                        input_names.append(input_name)
                    input_types.append(input_type)
                    if input_type == 'password':
                        has_password = True
                    if input_type == 'file':
                        has_file_input = True
                    if 'csrf' in input_name.lower() or 'token' in input_name.lower():
                        has_csrf_token = True
                discovered_form = DiscoveredForm(
                    page_url=document_url,
                    action_url=action_url,
                    action_path=action_path,
                    method=method,
                    input_names=_dedupe_preserve(input_names),
                    input_types=_dedupe_preserve(input_types),
                    has_password=has_password,
                    has_file_input=has_file_input,
                    has_csrf_token=(has_csrf_token or page_has_csrf_indicator),
                )
                forms.append(discovered_form)
                candidate_paths.append(action_path)
                if _is_probable_auth_form(discovered_form):
                    auth_paths.append(action_path)
                    auth_paths.append(urlparse(document_url).path or '/')
                if has_file_input:
                    panel_paths.append(action_path)
        for _q, script_src in SCRIPT_SRC_RE.findall(body):
            script_path = _normalise_same_host_path(script_src, document_url, target)
            if script_path and not _looks_like_static_asset(script_path):
                candidate_paths.append(script_path)
        for pattern in (ABSOLUTE_HINT_RE, RELATIVE_HINT_RE, GENERIC_ENDPOINT_RE):
            for raw in pattern.findall(body):
                candidate = raw if isinstance(raw, str) else raw[0]
                hint_path = _normalise_same_host_path(candidate, document_url, target)
                if not hint_path or hint_path.lower().endswith(STATIC_EXTENSIONS):
                    continue
                candidate_paths.append(hint_path)
                js_hints.append(hint_path)

    for path in candidate_paths:
        lower_path = path.lower()
        if any(token in lower_path for token in ('/swagger', '/openapi', '/api-docs', '/graphql', '/graphql/playground', '/api/', '/v1/', '/v2/', '/auth/')):
            api_paths.append(path)
        if any(token in lower_path for token in ('/admin', '/dashboard', '/upload', '/actuator', '/metrics', '/debug', '/setup', '/install')):
            panel_paths.append(path)
        if any(token in lower_path for token in ('/login', '/signin', '/auth', '/dashboard', '/admin')):
            auth_paths.append(path)

    for form in forms:
        if _is_probable_auth_form(form):
            auth_paths.append(form.action_path)
        if form.has_file_input:
            panel_paths.append(form.action_path)

    return DiscoveryAnalysis(
        discovered_urls=discovered_urls,
        candidate_paths=_dedupe_preserve(candidate_paths),
        panel_paths=_dedupe_preserve(panel_paths),
        api_paths=_dedupe_preserve(api_paths),
        auth_paths=_dedupe_preserve(auth_paths),
        forms=forms,
        js_hints=_dedupe_preserve(js_hints),
    )


def _auth_form_title(form: FormDiscovery) -> str:
    lower_action = (form.action_path or '').lower()
    lower_page = (form.page_url or '').lower()
    combined = f'{lower_page} {lower_action}'
    if any(token in combined for token in ('register', 'signup', 'sign-up', 'create-account', 'create_account')):
        return 'Registration Form Discovered Via Crawl'
    return 'Login Form Discovered Via Crawl'


def findings_from_analysis(target: str, analysis: DiscoveryAnalysis) -> list[Vulnerability]:
    findings: list[Vulnerability] = []
    for form in analysis.forms:
        parsed = urlparse(form.page_url)
        names = ', '.join(form.input_names[:6]) or '<sin nombres>'
        action_slug = (form.action_path.strip('/') or 'root').replace('/', '-')
        if _is_probable_auth_form(form):
            form_title = _auth_form_title(form)
            findings.append(Vulnerability(
                source='custom-discovery-check',
                title=form_title,
                description='El crawler ha descubierto un formulario de autenticación que amplía la superficie de ataque útil para validaciones posteriores.',
                severity='low',
                target=form.page_url,
                evidence=f'Formulario en {form.page_url} -> {form.method} {form.action_url}; campos={names}; csrf_token_visible={form.has_csrf_token}',
                cwe=['CWE-200'],
                tags=['crawl', 'discovery', 'auth', 'form'],
                template_id=f'custom-discovery-login-form-{action_slug}',
                matched_at=form.action_url,
                host=parsed.hostname,
                port=str(parsed.port) if parsed.port else None,
                scheme=parsed.scheme,
                type='http',
                category='discovery',
                confidence='medium',
                verification_status='confirmed',
                needs_manual_validation=False,
            ))
            if not form.has_csrf_token:
                findings.append(Vulnerability(
                    source='custom-discovery-check',
                    title='Login Form Without Visible CSRF Token',
                    description='Se ha detectado un formulario de login sin un token CSRF visible en el HTML. Requiere validación manual o activa.',
                    severity='medium',
                    target=form.page_url,
                    evidence=f'Formulario en {form.page_url} -> {form.method} {form.action_url}; campos={names}',
                    cwe=['CWE-352'],
                    tags=['crawl', 'auth', 'csrf', 'form'],
                    template_id=f'custom-discovery-login-csrf-{action_slug}',
                    matched_at=form.action_url,
                    host=parsed.hostname,
                    port=str(parsed.port) if parsed.port else None,
                    scheme=parsed.scheme,
                    type='http',
                    category='authentication',
                    confidence='low',
                    verification_status='likely',
                    needs_manual_validation=True,
                ))
        if form.has_file_input:
            findings.append(Vulnerability(
                source='custom-discovery-check',
                title='File Upload Form Discovered Via Crawl',
                description='El crawler ha descubierto un formulario de subida de ficheros que puede requerir validaciones específicas de seguridad.',
                severity='medium',
                target=form.page_url,
                evidence=f'Formulario en {form.page_url} -> {form.method} {form.action_url}; campos={names}',
                cwe=['CWE-434'],
                tags=['crawl', 'discovery', 'upload', 'form'],
                template_id=f'custom-discovery-upload-form-{action_slug}',
                matched_at=form.action_url,
                host=parsed.hostname,
                port=str(parsed.port) if parsed.port else None,
                scheme=parsed.scheme,
                type='http',
                category='panel-exposure',
                confidence='medium',
                verification_status='confirmed',
                needs_manual_validation=False,
            ))
    parsed_target = urlparse(target)
    for hint in analysis.js_hints[:10]:
        lower_hint = hint.lower()
        if any(token in lower_hint for token in ('/api/', '/graphql', '/swagger', '/openapi', '/api-docs')):
            hint_slug = (hint.strip('/') or 'root').replace('/', '-')
            findings.append(Vulnerability(
                source='custom-discovery-check',
                title='Client-Side API Reference Observed',
                description='El cliente revela referencias a endpoints API en HTML o JavaScript; sirven para inventario pasivo de superficie sin hacer probing directo.',
                severity='low',
                target=target,
                evidence=f'Referencia cliente observada: {hint}',
                cwe=['CWE-200'],
                tags=['crawl', 'discovery', 'api', 'javascript'],
                template_id=f'custom-discovery-api-hint-{hint_slug}',
                matched_at=hint,
                host=parsed_target.hostname,
                port=str(parsed_target.port) if parsed_target.port else None,
                scheme=parsed_target.scheme,
                type='http',
                category='discovery',
                confidence='medium',
                verification_status='confirmed',
            ))
    return findings
