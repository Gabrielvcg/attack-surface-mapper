from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urlparse

from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.validators.base import BaseValidator


class TLSValidator(BaseValidator):
    def __init__(self, timeout: int = 8) -> None:
        self.timeout = timeout

    def run(self, target: str) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []
        parsed = urlparse(target)
        if parsed.scheme != 'https' or not parsed.hostname:
            return vulnerabilities

        port = parsed.port or 443
        hostname = parsed.hostname

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                protocol = tls_sock.version() or 'UNKNOWN'
                cipher = tls_sock.cipher()[0] if tls_sock.cipher() else 'UNKNOWN'

        if protocol in {'TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'}:
            vulnerabilities.append(
                Vulnerability(
                    source='custom-tls-check',
                    title='Legacy TLS Protocol Negotiated',
                    description=f'El servicio negocia un protocolo legado ({protocol}).',
                    severity='high',
                    target=target,
                    evidence=f'Protocol: {protocol}, cipher: {cipher}',
                    cwe=['CWE-326'],
                    tags=['tls', 'crypto', 'misconfig'],
                    template_id=f'custom-tls-legacy-{protocol.lower()}',
                    matched_at=target,
                    host=hostname,
                    port=str(port),
                    scheme='https',
                    type='network',
                    category='tls',
                    confidence='high',
                )
            )

        not_after = cert.get('notAfter')
        if not_after:
            expires_at = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=UTC)
            remaining_days = (expires_at - datetime.now(UTC)).days
            if remaining_days < 0:
                vulnerabilities.append(
                    Vulnerability(
                        source='custom-tls-check',
                        title='Expired TLS Certificate',
                        description='El certificado TLS del servicio está caducado.',
                        severity='high',
                        target=target,
                        evidence=f'Caducó el {expires_at.isoformat()}',
                        cwe=['CWE-295'],
                        tags=['tls', 'certificate'],
                        template_id='custom-tls-expired-cert',
                        matched_at=target,
                        host=hostname,
                        port=str(port),
                        scheme='https',
                        type='network',
                        category='tls',
                        confidence='high',
                    )
                )
            elif remaining_days <= 30:
                vulnerabilities.append(
                    Vulnerability(
                        source='custom-tls-check',
                        title='TLS Certificate Near Expiration',
                        description='El certificado TLS del servicio caduca pronto.',
                        severity='medium',
                        target=target,
                        evidence=f'Caduca el {expires_at.isoformat()} ({remaining_days} días)',
                        cwe=['CWE-295'],
                        tags=['tls', 'certificate'],
                        template_id='custom-tls-expiring-cert',
                        matched_at=target,
                        host=hostname,
                        port=str(port),
                        scheme='https',
                        type='network',
                        category='tls',
                        confidence='high',
                    )
                )

        return vulnerabilities
