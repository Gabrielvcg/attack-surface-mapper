from __future__ import annotations

import re
from urllib.parse import urlparse

from attack_surface_mapper.models.vulnerability import Vulnerability


class SecretsValidator:
    PATTERNS: dict[str, dict[str, object]] = {
        'generic-api-key': {
            'regex': re.compile(r'''(?i)(?:api[_-]?key|secret|token|access[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']'''),
            'title': 'Potential Secret Exposed in Web Content',
            'description': 'Se ha detectado un posible secreto o API key en contenido HTML/JS rastreado.',
            'severity': 'high',
            'cwe': ['CWE-200', 'CWE-798'],
            'confidence': 'medium',
        },
        'jwt': {
            'regex': re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'),
            'title': 'Potential JWT Exposed in Web Content',
            'description': 'Se ha detectado un token con formato JWT en contenido HTML/JS rastreado.',
            'severity': 'high',
            'cwe': ['CWE-200'],
            'confidence': 'medium',
        },
        'aws-access-key': {
            'regex': re.compile(r'AKIA[0-9A-Z]{16}'),
            'title': 'Potential AWS Access Key Exposed',
            'description': 'Se ha detectado una cadena con formato de AWS Access Key ID.',
            'severity': 'critical',
            'cwe': ['CWE-200', 'CWE-798'],
            'confidence': 'high',
        },
        'github-token': {
            'regex': re.compile(r'gh[pousr]_[A-Za-z0-9]{20,}'),
            'title': 'Potential GitHub Token Exposed',
            'description': 'Se ha detectado una cadena con formato de token de GitHub.',
            'severity': 'critical',
            'cwe': ['CWE-200', 'CWE-798'],
            'confidence': 'high',
        },
        'google-api-key': {
            'regex': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            'title': 'Potential Google API Key Exposed',
            'description': 'Se ha detectado una cadena con formato de Google API Key.',
            'severity': 'high',
            'cwe': ['CWE-200', 'CWE-798'],
            'confidence': 'high',
        },
        'slack-token': {
            'regex': re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,}'),
            'title': 'Potential Slack Token Exposed',
            'description': 'Se ha detectado un token con formato de Slack.',
            'severity': 'high',
            'cwe': ['CWE-200', 'CWE-798'],
            'confidence': 'high',
        },
        'private-key': {
            'regex': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
            'title': 'Private Key Material Exposed',
            'description': 'Se ha detectado material de clave privada en contenido rastreado.',
            'severity': 'critical',
            'cwe': ['CWE-200', 'CWE-321'],
            'confidence': 'high',
        },
    }

    def run(self, target: str, documents: dict[str, str]) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []
        for url, body in documents.items():
            parsed = urlparse(url)
            for key, metadata in self.PATTERNS.items():
                regex: re.Pattern[str] = metadata['regex']  # type: ignore[assignment]
                match = regex.search(body)
                if not match:
                    continue
                evidence = match.group(0)
                if len(evidence) > 120:
                    evidence = evidence[:120] + '...[truncated]'
                vulnerabilities.append(
                    Vulnerability(
                        source='custom-secret-check',
                        title=str(metadata['title']),
                        description=str(metadata['description']),
                        severity=str(metadata['severity']),
                        target=url,
                        evidence=f'Coincidencia {key}: {evidence}',
                        cwe=list(metadata['cwe']),
                        tags=['secrets', 'exposure', 'crawl'],
                        template_id=f'custom-secret-{key}',
                        matched_at=url,
                        host=parsed.hostname,
                        port=str(parsed.port) if parsed.port else None,
                        scheme=parsed.scheme,
                        type='http',
                        category='secret',
                        confidence=str(metadata['confidence']),
                    )
                )
        return vulnerabilities
