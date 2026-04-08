from __future__ import annotations

import hashlib

from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.utils.asset_normalizer import normalize_asset

SEVERITY_SCORE = {
    'info': 1,
    'low': 2,
    'medium': 3,
    'high': 4,
    'critical': 5,
    'unknown': 0,
}

PRIORITY_LABELS = {
    1: 'low',
    2: 'medium',
    3: 'medium',
    4: 'high',
    5: 'critical',
    6: 'critical',
    7: 'critical',
}

NETWORK_DISCOVERY_CATEGORIES = {'network-service', 'database', 'remote-access', 'message-broker', 'admin-surface', 'web-service', 'file-transfer', 'search-service'}

CATEGORY_RECOMMENDATIONS: dict[str, str] = {
    'headers': 'Aplicar y verificar cabeceras HTTP de seguridad como Content-Security-Policy, Strict-Transport-Security, X-Frame-Options y X-Content-Type-Options.',
    'tls': 'Deshabilitar protocolos y cifrados inseguros, revisar la cadena de certificados y activar HTTPS robusto en el servicio publicado.',
    'panel-exposure': 'Restringir por autenticación y por red el acceso a paneles administrativos, métricas y endpoints operativos.',
    'secret': 'Eliminar el secreto expuesto del contenido público, rotarlo inmediatamente y moverlo a un gestor seguro de secretos.',
    'authentication': 'Exigir autenticación para recursos sensibles, endurecer la gestión de sesión y revisar control de acceso y cookies.',
    'api': 'Proteger la superficie de API, limitar documentación expuesta y endurecer CORS, GraphQL y endpoints internos.',
    'sensitive-file': 'Bloquear la exposición de copias de seguridad, configuraciones y ficheros temporales desde el servidor web.',
    'discovery': 'Revisar la información de descubrimiento expuesta, valorar si ayuda a enumerar superficie interna y reducir detalle innecesario.',
    'exposure': 'Reducir la información operativa expuesta y aplicar autenticación o segmentación de red cuando corresponda.',
    'misconfiguration': 'Corregir la configuración insegura, revisar valores por defecto y documentar un baseline endurecido de despliegue.',
    'network-service': 'Revisar si el servicio de red descubierto debe estar accesible, limitar exposición mediante firewall o segmentación y validar autenticación y endurecimiento.',
    'database': 'Restringir el acceso a la base de datos a redes internas, revisar autenticación, cifrado y listas de control de acceso.',
    'remote-access': 'Limitar acceso remoto a IPs autorizadas, reforzar autenticación y revisar el hardening del servicio.',
    'message-broker': 'Restringir el broker o middleware a redes internas y revisar autenticación, puertos auxiliares y exposición innecesaria.',
    'admin-surface': 'Restringir el acceso a la superficie administrativa y revisar si el servicio debe estar publicado.',
    'web-service': 'Revisar la necesidad del servicio web descubierto y su endurecimiento (TLS, autenticación y exposición).',
}


TITLE_RECOMMENDATIONS = {
    'Prometheus Metrics - Detect': 'Restringir el endpoint /metrics a una red de administración o exigir autenticación; en producción, deshabilitarlo si no es imprescindible.',
    'Exposed Metrics Endpoint': 'Restringir el endpoint /metrics a red interna o autenticación y revisar si la exportación de métricas es necesaria en producción.',
    'Missing HSTS Header': 'Añadir Strict-Transport-Security con un max-age apropiado y aplicar HTTPS de forma consistente.',
    'Missing Content-Security-Policy Header': 'Definir una Content-Security-Policy adaptada a la aplicación para reducir XSS y carga de recursos no confiables.',
    'Missing Referrer-Policy Header': 'Añadir Referrer-Policy para limitar la fuga de información en cabeceras Referer.',
    'Permissive CORS Policy': 'Restringir Access-Control-Allow-Origin a orígenes de confianza y evitar el uso indiscriminado de comodines.',
}





def infer_kind(vulnerability: Vulnerability) -> str:
    category = (vulnerability.category or '').lower()
    if category in {'discovery'} or vulnerability.title.startswith('Technology Fingerprint Detected'):
        return 'discovery'
    if category in {'headers', 'tls', 'authentication', 'api', 'panel-exposure', 'web-service', 'network-service', 'secret', 'sensitive-file'}:
        return 'validation'
    return 'other'


def clean_evidence(text: str | None, max_len: int = 280) -> str | None:
    if not text:
        return text
    value = ' '.join(str(text).split())
    return value[:max_len] + '...' if len(value) > max_len else value

def _base_priority(vulnerability: Vulnerability) -> int:
    return SEVERITY_SCORE.get((vulnerability.severity or 'unknown').lower(), 0)


def compute_priority(vulnerability: Vulnerability) -> tuple[str, str]:
    score = _base_priority(vulnerability)
    reasons: list[str] = [f'severidad base={vulnerability.severity.lower()}']
    category = (vulnerability.category or '').lower()
    target = (vulnerability.target or '').lower()
    title = (vulnerability.title or '').lower()
    confidence = (vulnerability.confidence or '').lower()
    verification = (vulnerability.verification_status or '').lower()

    if category in {'secret', 'authentication', 'database', 'message-broker'}:
        score += 1
        reasons.append(f'categoría sensible={category}')
    if category in {'panel-exposure', 'api', 'sensitive-file', 'network-service', 'message-broker', 'admin-surface', 'remote-access'} and confidence in {'medium', 'high'}:
        score += 1
        reasons.append('superficie expuesta confirmada')
    if '/admin' in target or '/metrics' in target or '/swagger' in target or '/graphql' in target:
        score += 1
        reasons.append('endpoint de alto interés')
    if vulnerability.cvss_score is not None and vulnerability.cvss_score >= 7:
        score += 1
        reasons.append(f'cvss elevado={vulnerability.cvss_score}')
    if verification == 'confirmed' and category not in {'headers', 'discovery'} and (vulnerability.severity or '').lower() not in {'low', 'info'}:
        score += 1
        reasons.append('hallazgo confirmado')
    if vulnerability.source_count > 1 and verification == 'confirmed':
        score += 1
        reasons.append('múltiples fuentes correlacionadas con confirmación')
    elif vulnerability.source_count > 1 and confidence == 'high':
        score += 1
        reasons.append('múltiples fuentes correlacionadas de alta confianza')
    elif vulnerability.source_count > 1:
        reasons.append('múltiples fuentes correlacionadas sin confirmación')
    if vulnerability.title.startswith('Multiple API Endpoints Exposed'):
        score += 1
        reasons.append('múltiples endpoints de API expuestos')
    if any(token in target for token in ('/metrics', '/actuator', '/swagger', '/openapi', '/graphql')) and 'localhost' not in target:
        score += 1
        reasons.append('exposición remota fuera de localhost')
    if verification in {'likely', 'heuristic', 'needs_manual_validation'}:
        score -= 1
        reasons.append(f'validación={verification}')
    if confidence == 'low':
        score -= 2
        reasons.append('confianza baja')
    elif confidence == 'medium' and vulnerability.needs_manual_validation:
        score -= 1
        reasons.append('requiere validación manual')
    if category == 'headers' and (vulnerability.severity or '').lower() in {'low', 'info'}:
        score = min(score, 1)
        reasons.append('cabecera de bajo impacto')
    if title in {'swagger ui exposed', 'openapi specification exposed', 'api surface exposed'}:
        max_score = 4 if verification == 'confirmed' and confidence == 'high' else 3
        score = min(score, max_score)
        reasons.append('documentación o superficie api: prioridad acotada')
    if title == 'graphql surface exposed':
        max_score = 4 if verification == 'confirmed' and confidence == 'high' else 3
        score = min(score, max_score)
        reasons.append('superficie graphql pública: prioridad acotada')
    if title == 'graphql endpoint accessible without authentication' and verification != 'confirmed':
        score = min(score, 3)
        reasons.append('graphql sin prueba suficiente de acceso indebido')
    if title.startswith('multiple api endpoints exposed'):
        max_score = 4 if verification == 'confirmed' and confidence == 'high' else 3
        score = min(score, max_score)
        reasons.append('inventario de múltiples endpoints api')
    if category == 'discovery':
        score = 1
        reasons.append('hallazgo de descubrimiento, impacto limitado')
    if vulnerability.source == 'nuclei' and ('epmd' in target or 'rabbit' in (vulnerability.evidence_summary or '').lower() or 'erlang port mapper' in (vulnerability.title or '').lower()):
        score = max(score, 2)
        score = min(score, 3)
        reasons.append('middleware Erlang/RabbitMQ potencialmente expuesto')

    if vulnerability.source == 'nmap' and category in NETWORK_DISCOVERY_CATEGORIES and category not in {'database', 'admin-surface'}:
        score = min(score, 3)
        reasons.append('descubrimiento de red, prioridad acotada')
    if vulnerability.source == 'nmap' and category == 'web-service' and (vulnerability.port or '') in {'80', '443'}:
        score = 1
        reasons.append('servicio web estándar esperado; prioridad reducida')

    score = max(1, min(score, 7))
    return PRIORITY_LABELS[score], '; '.join(reasons)


def compute_confidence(vulnerability: Vulnerability) -> str:
    if vulnerability.confidence:
        return vulnerability.confidence
    if vulnerability.verification_status == 'confirmed':
        return 'high'
    if vulnerability.source_count >= 2 or vulnerability.cvss_score is not None or vulnerability.cve:
        return 'high'
    if vulnerability.source == 'nuclei' or vulnerability.category in {'headers', 'tls', 'panel-exposure', 'sensitive-file', 'discovery'}:
        return 'medium'
    return 'low'


def _normalise_validation_state(vulnerability: Vulnerability) -> None:
    verification = (vulnerability.verification_status or '').lower()
    confidence = (vulnerability.confidence or '').lower()
    category = (vulnerability.category or '').lower()

    if verification == 'confirmed':
        vulnerability.needs_manual_validation = False
        if confidence == 'low':
            vulnerability.confidence = 'medium'
            confidence = 'medium'
    elif verification in {'likely', 'needs_manual_validation', 'heuristic'}:
        vulnerability.needs_manual_validation = True

    if category in {'authentication', 'api', 'secret'} and verification != 'confirmed':
        vulnerability.needs_manual_validation = True

    if confidence in {'low', 'medium'} and category in {'authentication', 'api', 'panel-exposure', 'sensitive-file'} and verification != 'confirmed':
        vulnerability.needs_manual_validation = True

    if not vulnerability.verification_status:
        if vulnerability.confidence == 'high' and not vulnerability.needs_manual_validation:
            vulnerability.verification_status = 'confirmed'
        elif vulnerability.needs_manual_validation:
            vulnerability.verification_status = 'needs_manual_validation'
        else:
            vulnerability.verification_status = 'likely'


def compute_recommendation(vulnerability: Vulnerability) -> str:
    if vulnerability.title.startswith('Technology Fingerprint Detected'):
        return 'Usar el fingerprint como contexto para priorizar rutas, hardening y validaciones específicas del stack detectado.'
    if vulnerability.title.startswith('Multiple API Endpoints Exposed'):
        return 'Inventariar la superficie API expuesta, aplicar autenticación donde proceda y revisar documentación, CORS y endpoints no necesarios.'
    if vulnerability.title.startswith('Protected API Surface Discovered'):
        return 'Mantener la protección de acceso, inventariar los endpoints detectados y revisar si revelan más superficie de la necesaria.'
    if vulnerability.title.startswith('Multiple Client-Side API References Observed') or vulnerability.title == 'Client-Side API Reference Observed':
        return 'Reducir la exposición innecesaria de rutas internas en cliente y revisar si esa información facilita enumeración adicional.'
    if vulnerability.title in TITLE_RECOMMENDATIONS:
        return TITLE_RECOMMENDATIONS[vulnerability.title]
    if vulnerability.category and vulnerability.category in CATEGORY_RECOMMENDATIONS:
        return CATEGORY_RECOMMENDATIONS[vulnerability.category]
    if (vulnerability.severity or '').lower() in {'high', 'critical'}:
        return 'Validar manualmente el hallazgo, medir impacto y priorizar su remediación inmediata.'
    return 'Revisar el hallazgo y aplicar medidas de endurecimiento acordes al servicio afectado.'


def build_evidence_summary(vulnerability: Vulnerability) -> str | None:
    evidence = vulnerability.evidence or ''
    if not evidence:
        return None
    compact = evidence.replace('\n', ' ').replace('\r', ' ').strip()
    if len(compact) > 180:
        compact = compact[:180].rstrip() + '...'
    return compact


def _stable_identifier(namespace: str, *parts: object) -> str:
    raw = '|'.join('' if part is None else str(part).strip().lower() for part in (namespace, *parts))
    return hashlib.sha1(raw.encode('utf-8')).hexdigest()


def _normalise_validation_state(vulnerability: Vulnerability) -> None:
    verification = (vulnerability.verification_status or '').lower()
    confidence = (vulnerability.confidence or '').lower()
    category = (vulnerability.category or '').lower()

    if verification == 'confirmed':
        vulnerability.needs_manual_validation = False
        if confidence == 'low':
            vulnerability.confidence = 'medium'
            confidence = 'medium'
    elif verification in {'likely', 'needs_manual_validation', 'heuristic'}:
        vulnerability.needs_manual_validation = True

    if category in {'authentication', 'api', 'secret'} and verification != 'confirmed':
        vulnerability.needs_manual_validation = True

    if confidence in {'low', 'medium'} and category in {'authentication', 'api', 'panel-exposure', 'sensitive-file'} and verification != 'confirmed':
        vulnerability.needs_manual_validation = True

    if not vulnerability.verification_status:
        if vulnerability.confidence == 'high' and not vulnerability.needs_manual_validation:
            vulnerability.verification_status = 'confirmed'
        elif vulnerability.needs_manual_validation:
            vulnerability.verification_status = 'needs_manual_validation'
        else:
            vulnerability.verification_status = 'likely'


def enrich_vulnerabilities(vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
    for vulnerability in vulnerabilities:
        vulnerability.confidence = compute_confidence(vulnerability)
        if vulnerability.category == 'discovery' and (vulnerability.verification_status or '').lower() == 'confirmed':
            vulnerability.confidence = 'high'
        _normalise_validation_state(vulnerability)
        vulnerability.priority, vulnerability.priority_reason = compute_priority(vulnerability)
        vulnerability.recommendation = vulnerability.recommendation or compute_recommendation(vulnerability)
        vulnerability.evidence_summary = clean_evidence(vulnerability.evidence_summary or build_evidence_summary(vulnerability))
        vulnerability.evidence = clean_evidence(vulnerability.evidence, max_len=1200)
        vulnerability.kind = infer_kind(vulnerability)
        asset = normalize_asset(vulnerability.target or vulnerability.matched_at or '')
        vulnerability.target_host_original = asset.get('target_host_original')
        vulnerability.asset_host = asset.get('asset_host')
        vulnerability.asset_host_resolved = asset.get('asset_host_resolved')
        vulnerability.asset_port = asset.get('asset_port')
        if vulnerability.host and not vulnerability.asset_host:
            vulnerability.asset_host = str(vulnerability.host).lower()
        if vulnerability.host and not vulnerability.asset_host_resolved and str(vulnerability.host).lower() != str(vulnerability.asset_host or '').lower():
            vulnerability.asset_host_resolved = str(vulnerability.host).lower()
        if vulnerability.port and not vulnerability.asset_port:
            vulnerability.asset_port = vulnerability.port
        _normalise_validation_state(vulnerability)
        vulnerability.finding_id = _stable_identifier(
            'finding',
            *(vulnerability.dedup_key()),
            vulnerability.asset_host,
            vulnerability.asset_port,
        )
        vulnerability.correlation_id = _stable_identifier(
            'correlation',
            *(vulnerability.correlation_key()),
            vulnerability.asset_host,
            vulnerability.asset_port,
        )
    return vulnerabilities
