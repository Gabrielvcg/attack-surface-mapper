from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from attack_surface_mapper.http_client import RequestError, build_http_session
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.validators.base import BaseValidator
from attack_surface_mapper.validators.http_fingerprint import baseline_fingerprint, looks_like_baseline, normalise_text


class SensitiveFilesValidator(BaseValidator):
    DEFAULT_PATHS: tuple[str, ...] = (
        '/.git/HEAD',
        '/.env',
        '/application.properties',
        '/application.yml',
        '/docker-compose.yml',
        '/backup.zip',
        '/db.sql',
        '/.DS_Store',
        '/robots.txt',
        '/sitemap.xml',
    )

    def __init__(self, timeout: int = 6, paths: tuple[str, ...] | None = None, *, backend: str = 'requests', mode: str = 'passive', user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36', use_baseline_probe: bool = True) -> None:
        self.timeout = timeout
        self.paths = paths or self.DEFAULT_PATHS
        self.backend = backend
        self.mode = mode
        self.user_agent = user_agent
        self.use_baseline_probe = use_baseline_probe

    def run(self, target: str, baseline=None) -> list[Vulnerability]:
        findings: list[Vulnerability] = []
        parsed_target = urlparse(target)
        host = parsed_target.hostname
        port = str(parsed_target.port) if parsed_target.port else None
        scheme = parsed_target.scheme
        with build_http_session(backend=self.backend, mode=self.mode, timeout=self.timeout, user_agent=self.user_agent) as session:
            baseline = baseline if baseline is not None else (baseline_fingerprint(session, target, self.timeout) if self.use_baseline_probe else None)
            for path in self.paths:
                url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
                try:
                    response = session.get(url, timeout=self.timeout, allow_redirects=True)
                except RequestError:
                    continue
                if response.status_code >= 400 or looks_like_baseline(response, baseline):
                    continue
                preview = normalise_text(response.text, 1800)
                valid, confidence, reason = self._classify(path, response, preview)
                if not valid:
                    continue
                category = 'discovery' if path in {'/robots.txt', '/sitemap.xml'} else 'sensitive-file'
                verification = 'confirmed' if confidence == 'high' else 'likely'
                findings.append(Vulnerability(
                    source='custom-sensitive-file-check',
                    title=self._title_for(path),
                    description=self._description_for(path),
                    severity=self._severity_for(path),
                    target=response.url,
                    evidence=f'GET {response.url} devolvió {response.status_code}; validación={reason}; vista previa={self._preview(preview)}',
                    cwe=['CWE-200'],
                    tags=['file', 'exposure'],
                    template_id=f"custom-sensitive-file-{path.strip('/') or 'root'}",
                    matched_at=response.url,
                    host=host,
                    port=port,
                    scheme=scheme,
                    type='http',
                    category=category,
                    confidence=confidence,
                    needs_manual_validation=confidence != 'high',
                    verification_status=verification,
                ))
        return findings

    def _classify(self, path: str, response, preview: str) -> tuple[bool, str, str]:
        content_type = (response.headers.get('Content-Type') or '').lower()
        if path == '/.git/HEAD':
            ok = preview.startswith('ref: refs/')
            return ok, 'high' if ok else 'low', 'git HEAD marker'
        if path == '/.env':
            key_matches = len(re.findall(r'[a-z0-9_]{1,30}=.{1,80}', preview))
            strong = any(token in preview for token in ('app_key=', 'secret_key=', 'database_url=', 'api_key=', 'token='))
            ok = key_matches >= 2 and strong
            return ok, 'high' if ok else 'low', 'env-like key=value patterns'
        if path == '/application.properties':
            ok = any(token in preview for token in ('spring.', 'server.port', 'datasource.', 'management.', 'security.', 'password='))
            return ok, 'medium' if ok else 'low', 'application.properties markers'
        if path == '/application.yml':
            ok = any(token in preview for token in ('spring:', 'datasource:', 'management:', 'security:', 'database:', 'password:'))
            return ok, 'medium' if ok else 'low', 'application.yml markers'
        if path == '/docker-compose.yml':
            ok = 'services:' in preview and any(token in preview for token in ('image:', 'build:', 'ports:', 'environment:'))
            return ok, 'medium' if ok else 'low', 'docker-compose markers'
        if path == '/robots.txt':
            ok = 'disallow:' in preview or 'user-agent:' in preview
            return ok, 'medium' if ok else 'low', 'robots syntax'
        if path == '/sitemap.xml':
            ok = '<urlset' in preview or '<sitemapindex' in preview
            return ok, 'medium' if ok else 'low', 'xml sitemap markers'
        if path == '/backup.zip':
            raw = response.content[:4]
            ok = raw.startswith(b'PK\x03\x04')
            reason = 'zip signature' if ok else f'content-type only ({content_type or "absent"})'
            return ok, 'high' if ok else 'low', reason
        if path == '/db.sql':
            ok = any(token in preview for token in ('create table', 'insert into', 'sql dump', '-- phpmyadmin'))
            return ok, 'high' if ok else 'low', 'sql dump markers'
        if path == '/.DS_Store':
            raw = response.content[:8]
            ok = raw.startswith(bytes.fromhex('0000000142756431'))
            reason = 'ds_store signature' if ok else f'content-type only ({content_type or "absent"})'
            return ok, 'medium' if ok else 'low', reason
        return bool(preview.strip()), 'low', 'generic non-empty response'

    @staticmethod
    def _severity_for(path: str) -> str:
        if path in {'/.env', '/.git/HEAD', '/db.sql', '/backup.zip'}:
            return 'high'
        if path in {'/robots.txt', '/sitemap.xml'}:
            return 'low'
        return 'medium'

    @staticmethod
    def _title_for(path: str) -> str:
        mapping = {
            '/robots.txt': 'robots.txt Exposed',
            '/sitemap.xml': 'sitemap.xml Exposed',
            '/.env': 'Environment File Exposed',
            '/db.sql': 'SQL Dump Exposed',
            '/backup.zip': 'Backup Archive Exposed',
            '/.git/HEAD': 'Git Metadata Exposed',
        }
        return mapping.get(path, f'Exposed Sensitive File: {path}')

    @staticmethod
    def _description_for(path: str) -> str:
        if path == '/robots.txt':
            return 'El fichero robots.txt es público y puede revelar rutas o áreas interesantes para enumeración.'
        if path == '/sitemap.xml':
            return 'El sitemap expuesto puede revelar estructura interna o rutas no enlazadas directamente.'
        return f'Se ha detectado exposición de un recurso sensible o potencialmente sensible: {path}.'

    @staticmethod
    def _preview(value: str, max_length: int = 120) -> str:
        value = ' '.join(value.split())
        return value if len(value) <= max_length else value[:max_length] + '...[truncated]'
