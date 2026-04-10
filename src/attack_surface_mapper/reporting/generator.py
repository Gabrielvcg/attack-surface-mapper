from __future__ import annotations

import csv
import html
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean
from typing import Iterable

from attack_surface_mapper.models.vulnerability import FINDING_SCHEMA_VERSION, Vulnerability
from attack_surface_mapper.reporting.review_matrix import review_bucket_for_finding

SEVERITY_LABELS = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
PRIORITY_LABELS = ['critical', 'high', 'medium', 'low']
COMPARISON_KEYS = ('new_findings', 'resolved_findings', 'changed_findings')
OPTIONAL_COMPARISON_KEYS = ('promoted_findings', 'regressed_findings', 'updated_findings')
VERIFICATION_ORDER = {'confirmed': 0, 'likely': 1, 'needs_manual_validation': 2, 'heuristic': 3, 'discarded': 4}
CONFIDENCE_ORDER = {'high': 0, 'medium': 1, 'low': 2}
CATEGORY_ORDER = {
    'authentication': 0,
    'api': 1,
    'panel-exposure': 2,
    'sensitive-file': 3,
    'secret': 4,
    'tls': 5,
    'headers': 6,
    'discovery': 7,
}



NETWORK_DISCOVERY_CATEGORIES = {'network-service', 'database', 'remote-access', 'message-broker', 'admin-surface', 'web-service', 'file-transfer', 'search-service'}


def _stable_counts(counter: Counter, labels: list[str]) -> dict[str, int]:
    return {label: int(counter.get(label, 0)) for label in labels}


def _nonzero_count_items(counts: dict[str, int]) -> list[tuple[str, int]]:
    return [(name, count) for name, count in counts.items() if count > 0]


def _normalise_comparison(comparison: dict | None) -> dict[str, list[dict]]:
    payload = comparison or {}
    normalised = dict(payload)
    for key in COMPARISON_KEYS + OPTIONAL_COMPARISON_KEYS:
        normalised[key] = list(payload.get(key, []) or [])
    summary = dict(payload.get('summary') or {})
    summary.setdefault('new_findings', len(normalised['new_findings']))
    summary.setdefault('resolved_findings', len(normalised['resolved_findings']))
    summary.setdefault('changed_findings', len(normalised['changed_findings']))
    summary.setdefault('promoted_findings', len(normalised['promoted_findings']))
    summary.setdefault('regressed_findings', len(normalised['regressed_findings']))
    summary.setdefault('updated_findings', len(normalised['updated_findings']))
    summary.setdefault('unchanged_findings', 0)
    summary.setdefault('change_type_counts', {})
    normalised['summary'] = summary
    normalised.setdefault('schema_version', '1.0')
    return normalised


def _is_inventory_like(vulnerability: Vulnerability) -> bool:
    title = (vulnerability.title or '').lower()
    category = (vulnerability.category or '').lower()
    return (
        category == 'discovery'
        or title.startswith('multiple api endpoints exposed')
        or title.startswith('protected api surface discovered')
        or title.startswith('multiple client-side api references observed')
        or title == 'client-side api reference observed'
        or title.startswith('technology fingerprint detected')
    )


def _sort_bucket(vulnerability: Vulnerability) -> int:
    if _is_inventory_like(vulnerability):
        return 3
    if (vulnerability.category or '').lower() == 'headers':
        return 2
    if (vulnerability.verification_status or '').lower() == 'confirmed':
        return 0
    return 1


def _report_sort_key(vulnerability: Vulnerability) -> tuple:
    priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, None: 4}
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5, None: 6}
    return (
        priority_order.get(vulnerability.priority, 4),
        _sort_bucket(vulnerability),
        VERIFICATION_ORDER.get((vulnerability.verification_status or '').lower(), 5),
        CATEGORY_ORDER.get((vulnerability.category or '').lower(), 98),
        severity_order.get(vulnerability.severity, 6),
        CONFIDENCE_ORDER.get((vulnerability.confidence or '').lower(), 3),
        -(vulnerability.source_count or 1),
        (vulnerability.category or ''),
        vulnerability.title,
        vulnerability.target,
    )


def _is_hygiene_finding(vulnerability: Vulnerability) -> bool:
    category = (vulnerability.category or '').lower()
    return category in {'headers', 'tls'}


def _is_application_finding(vulnerability: Vulnerability) -> bool:
    category = (vulnerability.category or '').lower()
    return category not in NETWORK_DISCOVERY_CATEGORIES | {'discovery'} and not _is_hygiene_finding(vulnerability)


def _is_review_surface(vulnerability: Vulnerability) -> bool:
    if not _is_application_finding(vulnerability):
        return False
    return review_bucket_for_finding(vulnerability.to_summary_record()) == 'revisar'


def _is_discovery_like_surface(vulnerability: Vulnerability) -> bool:
    if not _is_application_finding(vulnerability):
        return False
    return review_bucket_for_finding(vulnerability.to_summary_record()) == 'descubrimiento'


def _split_report_groups(vulnerabilities: Iterable[Vulnerability]) -> tuple[list[Vulnerability], list[Vulnerability], list[Vulnerability], list[Vulnerability], list[Vulnerability]]:
    sorted_vulns = list(vulnerabilities)
    application = [v for v in sorted_vulns if _is_application_finding(v) and not _is_review_surface(v) and not _is_discovery_like_surface(v)]
    review_surface = [v for v in sorted_vulns if _is_review_surface(v)]
    hygiene = [v for v in sorted_vulns if _is_hygiene_finding(v)]
    network = [v for v in sorted_vulns if (v.category or '').lower() in NETWORK_DISCOVERY_CATEGORIES]
    discovery = [v for v in sorted_vulns if (v.category or '').lower() == 'discovery' or _is_discovery_like_surface(v)]
    return application, review_surface, hygiene, network, discovery


def _headline_risk_findings(vulnerabilities: Iterable[Vulnerability]) -> list[Vulnerability]:
    items = list(vulnerabilities)
    prioritised = [
        vuln
        for vuln in items
        if review_bucket_for_finding({
            'title': vuln.title,
            'kind': vuln.kind,
            'category': vuln.category,
            'verification_status': vuln.verification_status,
            'confidence': vuln.confidence,
            'priority': vuln.priority,
        }) == 'priorizar'
    ]
    if prioritised:
        return prioritised
    preferred = [
        vuln
        for vuln in items
        if (vuln.priority or '').lower() in {'critical', 'high', 'medium'}
        or (vuln.verification_status or '').lower() == 'confirmed'
    ]
    return preferred or items

@dataclass(slots=True)
class ReportPaths:
    markdown: str | None = None
    html: str | None = None
    csv: str | None = None
    summary_json: str | None = None
    comparison_json: str | None = None


@dataclass(slots=True)
class ReportStats:
    total_findings: int
    severity_counts: dict[str, int]
    priority_counts: dict[str, int]
    category_counts: dict[str, int]
    source_counts: dict[str, int]
    average_cvss: float | None
    unique_cves: list[str]
    unique_cwes: list[str]
    needs_manual_validation: int
    confirmed_high_or_critical: int
    application_findings: int
    review_surface_findings: int
    hygiene_findings: int
    discovery_findings: int


class ReportGenerator:
    def __init__(self, title: str = 'Informe de vulnerabilidades y misconfiguraciones') -> None:
        self.title = title

    @staticmethod
    def sort_vulnerabilities(vulnerabilities: Iterable[Vulnerability]) -> list[Vulnerability]:
        return sorted(vulnerabilities, key=_report_sort_key)

    @staticmethod
    def compute_stats(vulnerabilities: Iterable[Vulnerability]) -> ReportStats:
        vulns = list(vulnerabilities)
        application_findings, review_surface_findings, hygiene_findings, _, discovery_findings = _split_report_groups(vulns)
        severity_counter = Counter((v.severity or 'unknown').lower() for v in vulns)
        priority_counter = Counter((v.priority or 'low').lower() for v in vulns)
        category_counter = Counter(v.category or 'uncategorised' for v in vulns)
        source_counter = Counter(v.source for v in vulns)
        cvss_values = [v.cvss_score for v in vulns if v.cvss_score is not None]
        unique_cves = sorted({item for v in vulns for item in v.cve if item})
        unique_cwes = sorted({item for v in vulns for item in v.cwe if item})
        return ReportStats(
            total_findings=len(vulns),
            severity_counts=_stable_counts(severity_counter, SEVERITY_LABELS),
            priority_counts=_stable_counts(priority_counter, PRIORITY_LABELS),
            category_counts=dict(sorted(category_counter.items(), key=lambda item: (-item[1], item[0]))),
            source_counts=dict(sorted(source_counter.items(), key=lambda item: (-item[1], item[0]))),
            average_cvss=round(mean(cvss_values), 2) if cvss_values else None,
            unique_cves=unique_cves,
            unique_cwes=unique_cwes,
            needs_manual_validation=sum(
                1
                for v in vulns
                if v.needs_manual_validation or (v.verification_status or '').lower() == 'needs_manual_validation'
            ),
            confirmed_high_or_critical=sum(
                1
                for v in vulns
                if (v.verification_status or '').lower() == 'confirmed'
                and (v.priority or v.severity or '').lower() in {'critical', 'high'}
            ),
            application_findings=len(application_findings),
            review_surface_findings=len(review_surface_findings),
            hygiene_findings=len(hygiene_findings),
            discovery_findings=len(discovery_findings),
        )

    @staticmethod
    def executive_summary(stats: ReportStats) -> str:
        if stats.total_findings == 0:
            return 'No se detectaron hallazgos durante la ejecución actual.'
        priorities = ', '.join(f'{count} {name}' for name, count in _nonzero_count_items(stats.priority_counts)) or 'sin prioridades clasificadas'
        severities = ', '.join(f'{count} {name}' for name, count in _nonzero_count_items(stats.severity_counts)) or 'sin severidades clasificadas'
        high_or_critical = stats.priority_counts.get('critical', 0) + stats.priority_counts.get('high', 0)
        if stats.confirmed_high_or_critical:
            impact_note = f'Se observaron {stats.confirmed_high_or_critical} hallazgos confirmados de prioridad alta o crítica.'
        elif high_or_critical:
            impact_note = 'No se observaron hallazgos confirmados de prioridad alta o crítica; los hallazgos de mayor prioridad requieren revisión manual.'
        else:
            impact_note = 'No se observaron hallazgos de prioridad alta o crítica en esta ejecución.'
        return (
            f'Se identificaron {stats.total_findings} hallazgos correlacionados. '
            f'Riesgo accionable: {stats.application_findings}; superficie a revisar: {stats.review_surface_findings}; higiene/endurecimiento: {stats.hygiene_findings}; descubrimiento: {stats.discovery_findings}. '
            f'Prioridades: {priorities}. Severidades: {severities}. '
            f'Hallazgos que requieren validación manual: {stats.needs_manual_validation}. '
            f'{impact_note}'
        )

    @staticmethod
    def _write(path: str | Path, content: str) -> str:
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding='utf-8')
        return str(file_path)

    @staticmethod
    def _serialize_top_finding(vulnerability: Vulnerability) -> dict:
        return vulnerability.to_summary_record()

    def build_summary_payload(self, vulnerabilities: Iterable[Vulnerability], target: str, comparison: dict | None = None) -> dict:
        sorted_vulns = self.sort_vulnerabilities(vulnerabilities)
        stats = self.compute_stats(sorted_vulns)
        application_findings, review_surface_findings, hygiene_findings, _, discovery_findings = _split_report_groups(sorted_vulns)
        headline_risk_findings = _headline_risk_findings(application_findings)
        if not headline_risk_findings:
            headline_risk_findings = _headline_risk_findings(review_surface_findings)
        comparison_payload = _normalise_comparison(comparison)
        return {
            'schema_version': FINDING_SCHEMA_VERSION,
            'finding_contract': Vulnerability.contract_metadata(),
            'title': self.title,
            'target': target,
            'executive_summary': self.executive_summary(stats),
            'stats': asdict(stats),
            'comparison': comparison_payload,
            'comparison_summary': dict(comparison_payload.get('summary') or {}),
            'top_finding_count': min(len(sorted_vulns), 10),
            'top_findings': [self._serialize_top_finding(v) for v in sorted_vulns[:10]],
            'top_risk_finding_count': min(len(headline_risk_findings), 5),
            'top_risk_findings': [self._serialize_top_finding(v) for v in headline_risk_findings[:5]],
            'top_review_finding_count': min(len(review_surface_findings), 5),
            'top_review_findings': [self._serialize_top_finding(v) for v in review_surface_findings[:5]],
            'top_hygiene_finding_count': min(len(hygiene_findings), 5),
            'top_hygiene_findings': [self._serialize_top_finding(v) for v in hygiene_findings[:5]],
            'top_discovery_finding_count': min(len(discovery_findings), 5),
            'top_discovery_findings': [self._serialize_top_finding(v) for v in discovery_findings[:5]],
        }

    def generate_summary_json(self, vulnerabilities: Iterable[Vulnerability], target: str, output_path: str, comparison: dict | None = None) -> str:
        payload = self.build_summary_payload(vulnerabilities, target, comparison=comparison)
        return self._write(output_path, json.dumps(payload, indent=2, ensure_ascii=False))

    def generate_comparison_json(self, comparison: dict, output_path: str) -> str:
        return self._write(output_path, json.dumps(_normalise_comparison(comparison), indent=2, ensure_ascii=False))

    def generate_csv(self, vulnerabilities: Iterable[Vulnerability], output_path: str) -> str:
        file_path = Path(output_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        sorted_vulns = self.sort_vulnerabilities(vulnerabilities)
        with file_path.open('w', encoding='utf-8', newline='') as handle:
            writer = csv.writer(handle)
            writer.writerow([
                'finding_id', 'correlation_id', 'source', 'severity', 'priority', 'priority_reason', 'category', 'kind', 'confidence', 'verification_status', 'title', 'target', 'target_host_original', 'asset_host', 'asset_host_resolved', 'asset_port', 'description',
                'evidence_summary', 'cve', 'cwe', 'cvss_score', 'source_count', 'related_sources', 'recommendation'
            ])
            for vuln in sorted_vulns:
                writer.writerow([
                    vuln.finding_id or '', vuln.correlation_id or '', vuln.source, vuln.severity, vuln.priority or '', vuln.priority_reason or '', vuln.category or '', vuln.kind or '', vuln.confidence or '', vuln.verification_status or '',
                    vuln.title, vuln.target, vuln.target_host_original or '', vuln.asset_host or '', vuln.asset_host_resolved or '', vuln.asset_port or '', vuln.description, vuln.evidence_summary or '',
                    ', '.join(vuln.cve), ', '.join(vuln.cwe), vuln.cvss_score if vuln.cvss_score is not None else '',
                    vuln.source_count, ', '.join(vuln.related_sources), vuln.recommendation or ''
                ])
        return str(file_path)

    def _append_markdown_finding(self, lines: list[str], vuln: Vulnerability, label: str) -> None:
        lines += [
            f'### [{label}] {vuln.title}',
            '',
            f'- **Prioridad:** {vuln.priority or "N/A"}',
            f'- **Motivo de prioridad:** {vuln.priority_reason or "N/A"}',
            f'- **Severidad:** {vuln.severity}',
            f'- **Categoría:** {vuln.category or "N/A"}',
            f'- **Confianza:** {vuln.confidence or "N/A"}',
            f'- **Estado de verificación:** {vuln.verification_status or "N/A"}',
            f'- **Fuentes relacionadas:** {", ".join(vuln.related_sources) if vuln.related_sources else vuln.source}',
            f'- **Target:** `{vuln.target}`',
            f'- **Descripción:** {vuln.description}',
        ]
        if vuln.evidence_summary:
            lines.append(f'- **Evidencia resumida:** `{vuln.evidence_summary}`')
        if vuln.cve:
            lines.append(f'- **CVE:** {", ".join(vuln.cve)}')
        if vuln.cwe:
            lines.append(f'- **CWE:** {", ".join(vuln.cwe)}')
        if vuln.cvss_score is not None:
            lines.append(f'- **CVSS:** {vuln.cvss_score}')
        if vuln.needs_manual_validation:
            lines.append('- **Validación manual recomendada:** sí')
        lines.append(f'- **Recomendación:** {vuln.recommendation or "N/A"}')
        lines.append('')

    def generate_markdown(self, vulnerabilities: Iterable[Vulnerability], target: str, output_path: str, comparison: dict | None = None) -> str:
        sorted_vulns = self.sort_vulnerabilities(vulnerabilities)
        stats = self.compute_stats(sorted_vulns)
        comparison_payload = _normalise_comparison(comparison) if comparison else {}
        application_findings, review_surface_findings, hygiene_findings, network_services, discovery_like = _split_report_groups(sorted_vulns)
        confirmed = [v for v in application_findings if (v.verification_status or '').lower() == 'confirmed']
        plausible = [v for v in application_findings if (v.verification_status or '').lower() != 'confirmed']
        review_confirmed = [v for v in review_surface_findings if (v.verification_status or '').lower() == 'confirmed']
        review_plausible = [v for v in review_surface_findings if (v.verification_status or '').lower() != 'confirmed']
        hygiene_confirmed = [v for v in hygiene_findings if (v.verification_status or '').lower() == 'confirmed']
        hygiene_plausible = [v for v in hygiene_findings if (v.verification_status or '').lower() != 'confirmed']

        lines = [
            f'# {self.title}',
            '',
            f'- **Target:** `{target}`',
            f'- **Total de hallazgos correlacionados:** {stats.total_findings}',
            f'- **Resumen ejecutivo:** {self.executive_summary(stats)}',
            '',
            '## Prioridades',
            '',
        ]
        for name, count in _nonzero_count_items(stats.priority_counts):
            lines.append(f'- **{name}**: {count}')
        lines += ['', '## Severidades', '']
        for name, count in _nonzero_count_items(stats.severity_counts):
            lines.append(f'- **{name}**: {count}')
        lines += ['', '## Categorías', '']
        for name, count in stats.category_counts.items():
            lines.append(f'- **{name}**: {count}')
        if comparison_payload:
            lines += ['', '## Comparación con baseline', '']
            summary = comparison_payload.get('summary', {})
            lines.append(f"- **Nuevos hallazgos:** {summary.get('new_findings', len(comparison_payload.get('new_findings', [])))}")
            lines.append(f"- **Hallazgos resueltos:** {summary.get('resolved_findings', len(comparison_payload.get('resolved_findings', [])))}")
            lines.append(f"- **Hallazgos modificados:** {summary.get('changed_findings', len(comparison_payload.get('changed_findings', [])))}")
            lines.append(f"- **Promovidos en riesgo/confianza:** {summary.get('promoted_findings', len(comparison_payload.get('promoted_findings', [])))}")
            lines.append(f"- **Regresados o debilitados:** {summary.get('regressed_findings', len(comparison_payload.get('regressed_findings', [])))}")

        lines += ['', '## Hallazgos confirmados de aplicación', '']
        if not confirmed:
            lines.append('No se detectaron hallazgos confirmados de aplicación en esta ejecución.')
        for idx, vuln in enumerate(confirmed, 1):
            self._append_markdown_finding(lines, vuln, str(idx))

        lines += ['', '## Hallazgos plausibles o pendientes de validación (aplicación)', '']
        if not plausible:
            lines.append('No se detectaron hallazgos plausibles adicionales de aplicación.')
        for idx, vuln in enumerate(plausible, 1):
            self._append_markdown_finding(lines, vuln, f'P{idx}')

        lines += ['', '## Superficie pública a revisar', '']
        if not review_surface_findings:
            lines.append('No se detectó superficie pública relevante pendiente de revisión manual.')
        for idx, vuln in enumerate(review_confirmed, 1):
            self._append_markdown_finding(lines, vuln, f'R{idx}')
        for idx, vuln in enumerate(review_plausible, 1):
            self._append_markdown_finding(lines, vuln, f'RP{idx}')

        lines += ['', '## Hallazgos de higiene y endurecimiento', '']
        if not hygiene_findings:
            lines.append('No se detectaron hallazgos adicionales de higiene o endurecimiento.')
        for idx, vuln in enumerate(hygiene_confirmed, 1):
            self._append_markdown_finding(lines, vuln, f'H{idx}')
        for idx, vuln in enumerate(hygiene_plausible, 1):
            self._append_markdown_finding(lines, vuln, f'HP{idx}')

        lines += ['', '## Servicios y puertos descubiertos', '']
        if not network_services:
            lines.append('No se detectaron servicios o puertos relevantes mediante descubrimiento de red.')
        for idx, vuln in enumerate(network_services, 1):
            self._append_markdown_finding(lines, vuln, f'N{idx}')

        lines += ['', '## Superficie descubierta o protegida', '']
        if not discovery_like:
            lines.append('No se detectó superficie protegida o de descubrimiento relevante.')
        for idx, vuln in enumerate(discovery_like, 1):
            self._append_markdown_finding(lines, vuln, f'D{idx}')

        return self._write(output_path, '\n'.join(lines).rstrip() + '\n')

    def generate_html(self, vulnerabilities: Iterable[Vulnerability], target: str, output_path: str, comparison: dict | None = None) -> str:
        sorted_vulns = self.sort_vulnerabilities(vulnerabilities)
        stats = self.compute_stats(sorted_vulns)
        comparison_payload = _normalise_comparison(comparison) if comparison else {}
        findings = []
        for vuln in sorted_vulns:
            findings.append(
                f"<section class='finding'><h3>{html.escape(vuln.title)}</h3>"
                f"<p><strong>Prioridad:</strong> {html.escape(vuln.priority or 'N/A')} | <strong>Severidad:</strong> {html.escape(vuln.severity)}</p>"
                f"<p><strong>Motivo de prioridad:</strong> {html.escape(vuln.priority_reason or 'N/A')}</p>"
                f"<p><strong>Categoría:</strong> {html.escape(vuln.category or 'N/A')} | <strong>Confianza:</strong> {html.escape(vuln.confidence or 'N/A')} | <strong>Verificación:</strong> {html.escape(vuln.verification_status or 'N/A')}</p>"
                f"<p><strong>Target:</strong> <code>{html.escape(vuln.target)}</code></p>"
                f"<p>{html.escape(vuln.description)}</p>"
                f"<p><strong>Evidencia:</strong> <code>{html.escape(vuln.evidence_summary or '')}</code></p>"
                f"<p><strong>Recomendación:</strong> {html.escape(vuln.recommendation or '')}</p></section>"
            )
        comparison_html = ''
        if comparison_payload:
            comparison_html = (
                f"<section><h2>Comparación con baseline</h2><ul>"
                f"<li>Nuevos hallazgos: {comparison_payload.get('summary', {}).get('new_findings', len(comparison_payload.get('new_findings', [])))}</li>"
                f"<li>Hallazgos resueltos: {comparison_payload.get('summary', {}).get('resolved_findings', len(comparison_payload.get('resolved_findings', [])))}</li>"
                f"<li>Hallazgos modificados: {comparison_payload.get('summary', {}).get('changed_findings', len(comparison_payload.get('changed_findings', [])))}</li>"
                f"<li>Promovidos en riesgo/confianza: {comparison_payload.get('summary', {}).get('promoted_findings', len(comparison_payload.get('promoted_findings', [])))}</li>"
                f"<li>Regresados o debilitados: {comparison_payload.get('summary', {}).get('regressed_findings', len(comparison_payload.get('regressed_findings', [])))}</li>"
                f"</ul></section>"
            )
        content = f"""<!doctype html>
<html lang='es'>
<head>
<meta charset='utf-8'>
<title>{html.escape(self.title)}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 2rem; line-height: 1.5; }}
.finding {{ border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }}
code {{ background: #f4f4f4; padding: 0.1rem 0.3rem; }}
</style>
</head>
<body>
<h1>{html.escape(self.title)}</h1>
<p><strong>Target:</strong> <code>{html.escape(target)}</code></p>
<p>{html.escape(self.executive_summary(stats))}</p>
<section><h2>Resumen</h2>
<ul>{''.join(f'<li>{html.escape(k)}: {v}</li>' for k, v in _nonzero_count_items(stats.priority_counts))}</ul>
</section>
{comparison_html}
<section><h2>Hallazgos</h2>{''.join(findings) if findings else '<p>Sin hallazgos.</p>'}</section>
</body></html>"""
        return self._write(output_path, content)

    def generate_all(
        self,
        vulnerabilities: Iterable[Vulnerability],
        target: str,
        markdown_path: str | None = None,
        html_path: str | None = None,
        csv_path: str | None = None,
        summary_json_path: str | None = None,
        comparison_json_path: str | None = None,
        comparison: dict | None = None,
    ) -> ReportPaths:
        report_paths = ReportPaths()
        if markdown_path:
            report_paths.markdown = self.generate_markdown(vulnerabilities, target, markdown_path, comparison=comparison)
        if html_path:
            report_paths.html = self.generate_html(vulnerabilities, target, html_path, comparison=comparison)
        if csv_path:
            report_paths.csv = self.generate_csv(vulnerabilities, csv_path)
        if summary_json_path:
            report_paths.summary_json = self.generate_summary_json(vulnerabilities, target, summary_json_path, comparison=comparison)
        if comparison_json_path and comparison is not None:
            report_paths.comparison_json = self.generate_comparison_json(comparison, comparison_json_path)
        return report_paths
