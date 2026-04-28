from __future__ import annotations

from urllib.parse import urlparse

from attack_surface_mapper.cms.detector import DetectedCMS
from attack_surface_mapper.core import ScanContext
from attack_surface_mapper.models.vulnerability import Vulnerability


class WordPressModule:
    name = 'wordpress'

    def supports(self, detection: DetectedCMS) -> bool:
        return detection.name.lower() == 'wordpress'

    def run(self, context: ScanContext, detection: DetectedCMS) -> list[Vulnerability]:
        findings = [self._cms_detected_finding(context, detection)]
        findings.extend(self._surface_findings(context, detection))
        findings.extend(self._component_findings(context, detection))
        return findings

    def _cms_detected_finding(self, context: ScanContext, detection: DetectedCMS) -> Vulnerability:
        parsed = urlparse(context.target)
        evidence = '; '.join(detection.evidence) or 'WordPress markers observed in crawled content'
        return Vulnerability(
            source='cms-wordpress',
            title='CMS Detected (WordPress)',
            description='Se ha identificado WordPress a partir de contenido y rutas observadas durante el reconocimiento.',
            severity='low',
            target=context.target,
            evidence=evidence,
            cwe=['CWE-200'],
            tags=['cms', 'wordpress', 'discovery'],
            template_id='cms-wordpress-detected',
            matched_at=context.target,
            host=parsed.hostname,
            port=str(parsed.port) if parsed.port else None,
            scheme=parsed.scheme,
            type='http',
            category='discovery',
            confidence=detection.confidence,
            verification_status='confirmed' if detection.confidence == 'high' else 'likely',
            needs_manual_validation=False,
            raw={'cms': detection.name, 'signals': detection.signals},
        )

    def _surface_findings(self, context: ScanContext, detection: DetectedCMS) -> list[Vulnerability]:
        findings: list[Vulnerability] = []
        for url in detection.signals.get('paths', []):
            lower_path = (urlparse(url).path or '').lower()
            if '/wp-json' in lower_path:
                findings.append(self._surface_finding(
                    context,
                    title='WordPress REST API Surface Observed',
                    matched_at=url,
                    evidence=f'Ruta WordPress observada: {url}',
                    severity='low',
                    category='api',
                    tags=['cms', 'wordpress', 'api', 'discovery'],
                ))
            elif lower_path == '/wp-login.php':
                findings.append(self._surface_finding(
                    context,
                    title='WordPress Login Surface Observed',
                    matched_at=url,
                    evidence=f'Ruta WordPress observada: {url}',
                    severity='low',
                    category='discovery',
                    tags=['cms', 'wordpress', 'login', 'discovery'],
                ))
            elif lower_path == '/xmlrpc.php':
                findings.append(self._surface_finding(
                    context,
                    title='WordPress XML-RPC Surface Observed',
                    matched_at=url,
                    evidence=f'Ruta WordPress observada: {url}',
                    severity='medium',
                    category='panel-exposure',
                    tags=['cms', 'wordpress', 'xmlrpc', 'discovery'],
                ))
            elif lower_path == '/wp-admin/install.php':
                findings.append(self._surface_finding(
                    context,
                    title='WordPress Installer Exposed',
                    matched_at=url,
                    evidence=f'Instalador WordPress observado: {url}',
                    severity='medium',
                    category='configuration',
                    tags=['cms', 'wordpress', 'installer', 'setup', 'misconfig'],
                    description='El instalador inicial de WordPress esta accesible. Si el sitio no esta instalado, un tercero podria completar la configuracion inicial.',
                    needs_manual_validation=True,
                    verification_status='likely',
                ))
        return self._dedupe_findings(findings)

    def _component_findings(self, context: ScanContext, detection: DetectedCMS) -> list[Vulnerability]:
        findings: list[Vulnerability] = []
        plugins = detection.signals.get('plugins', [])
        themes = detection.signals.get('themes', [])
        if plugins:
            findings.append(self._surface_finding(
                context,
                title=f'WordPress Plugins Observed ({len(plugins)})',
                matched_at=context.target,
                evidence=f"Plugins observados: {', '.join(plugins[:20])}",
                severity='low',
                category='discovery',
                tags=['cms', 'wordpress', 'plugins', 'discovery'],
            ))
        if themes:
            findings.append(self._surface_finding(
                context,
                title=f'WordPress Themes Observed ({len(themes)})',
                matched_at=context.target,
                evidence=f"Temas observados: {', '.join(themes[:20])}",
                severity='low',
                category='discovery',
                tags=['cms', 'wordpress', 'themes', 'discovery'],
            ))
        return findings

    @staticmethod
    def _surface_finding(
        context: ScanContext,
        *,
        title: str,
        matched_at: str,
        evidence: str,
        severity: str,
        category: str,
        tags: list[str],
        description: str = 'Superficie especifica de WordPress observada durante el reconocimiento del objetivo.',
        needs_manual_validation: bool = False,
        verification_status: str = 'confirmed',
    ) -> Vulnerability:
        parsed = urlparse(matched_at if '://' in matched_at else context.target)
        return Vulnerability(
            source='cms-wordpress',
            title=title,
            description=description,
            severity=severity,
            target=context.target,
            evidence=evidence,
            cwe=['CWE-200'],
            tags=tags,
            template_id=f"cms-wordpress-{title.lower().replace(' ', '-').replace('(', '').replace(')', '')}",
            matched_at=matched_at,
            host=parsed.hostname,
            port=str(parsed.port) if parsed.port else None,
            scheme=parsed.scheme,
            type='http',
            category=category,
            confidence='medium',
            verification_status=verification_status,
            needs_manual_validation=needs_manual_validation,
        )

    @staticmethod
    def _dedupe_findings(findings: list[Vulnerability]) -> list[Vulnerability]:
        seen: set[tuple[str, str]] = set()
        out: list[Vulnerability] = []
        for finding in findings:
            key = WordPressModule._dedupe_key(finding)
            if key in seen:
                continue
            seen.add(key)
            out.append(finding)
        return out

    @staticmethod
    def _dedupe_key(finding: Vulnerability) -> tuple[str, str]:
        matched_at = finding.matched_at or finding.target
        parsed = urlparse(matched_at or '')
        path = (parsed.path or matched_at or '').lower()
        if finding.title == 'WordPress Installer Exposed':
            return finding.title, '/wp-admin/install.php'
        return finding.title, path
