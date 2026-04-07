from __future__ import annotations

import csv
import json
import re
from collections import Counter
from pathlib import Path
from typing import Iterable

from attack_surface_mapper.orchestrator import ScanResult


NETWORK_DISCOVERY_CATEGORIES = {'network-service', 'database', 'remote-access', 'message-broker', 'admin-surface', 'web-service', 'file-transfer', 'search-service'}
_PRIORITY_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
_IPV4_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')


def _best_priority(current: str | None, candidate: str | None) -> str | None:
    current_score = _PRIORITY_ORDER.get((current or '').lower(), 0)
    candidate_score = _PRIORITY_ORDER.get((candidate or '').lower(), 0)
    return candidate if candidate_score > current_score else current


def _best_severity(current: str | None, candidate: str | None) -> str | None:
    return _best_priority(current, candidate)


def _is_ipv4(value: str | None) -> bool:
    return bool(value and _IPV4_RE.match(value))


def _derive_target_asset_hosts(results: Iterable[ScanResult]) -> dict[str, str | None]:
    mapping: dict[str, str | None] = {}
    for result in results:
        ips = sorted({v.host for v in result.vulnerabilities if _is_ipv4(v.host)})
        mapping[result.target] = ips[0] if len(ips) == 1 else None
    return mapping


def _canonical_asset_host(result_target: str, vuln, target_asset_hosts: dict[str, str | None]) -> str:
    if _is_ipv4(vuln.host):
        return str(vuln.host)
    resolved = target_asset_hosts.get(result_target)
    if resolved:
        return resolved
    location = str(vuln.matched_at or vuln.target or '')
    if ':' in location:
        candidate = location.rsplit(':', 1)[0]
        if _is_ipv4(candidate):
            return candidate
    return str(vuln.host or location).lower()


def _network_title_key(vuln) -> str:
    title = (vuln.title or '').lower()
    category = (vuln.category or 'uncategorised').lower()
    if category in NETWORK_DISCOVERY_CATEGORIES:
        # For network discoveries, port/category are the stable identifiers.
        return category
    return title


def _aggregate_key(result_target: str, vuln, target_asset_hosts: dict[str, str | None]) -> tuple[str, str, str, str]:
    category = (vuln.category or 'uncategorised').lower()
    title = vuln.title or 'Unknown finding'
    if category in NETWORK_DISCOVERY_CATEGORIES:
        asset_host = _canonical_asset_host(result_target, vuln, target_asset_hosts)
        return ('network', asset_host.lower(), str(vuln.port or ''), _network_title_key(vuln))
    return ('target', result_target.lower(), str(vuln.matched_at or vuln.target or '').lower(), title.lower())


def _build_finding_record(result_target: str, vuln, target_asset_hosts: dict[str, str | None]) -> dict:
    canonical_host = _canonical_asset_host(result_target, vuln, target_asset_hosts)
    location = vuln.matched_at or vuln.target
    if (vuln.category or '').lower() in NETWORK_DISCOVERY_CATEGORIES and canonical_host and vuln.port:
        location = f'{canonical_host}:{vuln.port}'
    return {
        'target': result_target,
        'location': location,
        'title': vuln.title,
        'priority': vuln.priority,
        'severity': vuln.severity,
        'category': vuln.category,
        'verification_status': vuln.verification_status,
        'recommendation': vuln.recommendation,
        'targets': [result_target],
        'asset_host': canonical_host,
        'asset_port': vuln.port,
        'asset_hosts': [canonical_host] if canonical_host else [],
        'scope': 'target-specific',
    }


def build_aggregate_payload(results: Iterable[ScanResult]) -> dict:
    result_list = list(results)
    target_asset_hosts = _derive_target_asset_hosts(result_list)
    total_targets = len(result_list)
    raw_total_findings = sum(len(r.vulnerabilities) for r in result_list)
    priority_counter = Counter()
    category_counter = Counter()
    per_target: list[dict] = []
    aggregated_findings: dict[tuple[str, str, str, str], dict] = {}

    for result in result_list:
        for vuln in result.vulnerabilities:
            priority_counter[(vuln.priority or vuln.severity).lower()] += 1
            category_counter[(vuln.category or 'uncategorised').lower()] += 1
            key = _aggregate_key(result.target, vuln, target_asset_hosts)
            if key not in aggregated_findings:
                aggregated_findings[key] = _build_finding_record(result.target, vuln, target_asset_hosts)
                continue
            record = aggregated_findings[key]
            if result.target not in record['targets']:
                record['targets'].append(result.target)
            host = _canonical_asset_host(result.target, vuln, target_asset_hosts)
            if host and host not in record['asset_hosts']:
                record['asset_hosts'].append(host)
            prior_priority = record.get('priority')
            record['priority'] = _best_priority(prior_priority, vuln.priority)
            record['severity'] = _best_severity(record.get('severity'), vuln.severity)
            candidate_score = _PRIORITY_ORDER.get((vuln.priority or '').lower(), 0)
            record_score = _PRIORITY_ORDER.get((prior_priority or '').lower(), 0)
            if candidate_score >= record_score:
                record['verification_status'] = vuln.verification_status
                record['recommendation'] = vuln.recommendation
                # Prefer more descriptive titles when merging the same asset view.
                if len(vuln.title or '') > len(record.get('title') or ''):
                    record['title'] = vuln.title

        per_target.append({
            'target': result.target,
            'findings': len(result.vulnerabilities),
            'priorities': result.summary,
            'reports': {
                'markdown': result.report_paths.markdown,
                'html': result.report_paths.html,
                'csv': result.report_paths.csv,
                'summary_json': result.report_paths.summary_json,
            },
        })

    top_findings = list(aggregated_findings.values())
    for finding in top_findings:
        finding['targets'].sort()
        finding['target_count'] = len(finding['targets'])
        finding['target_labels'] = ', '.join(finding['targets'])
        finding['asset_host_count'] = len([host for host in finding.get('asset_hosts', []) if host])
        if finding['target_count'] > 1:
            finding['scope'] = 'shared-host'
        else:
            finding['scope'] = 'target-specific'

    top_findings.sort(
        key=lambda item: (
            _PRIORITY_ORDER.get((item.get('priority') or '').lower(), 0),
            item.get('target_count', 1),
            item['title'],
        ),
        reverse=True,
    )

    shared_asset_findings = [f for f in top_findings if f.get('scope') == 'shared-host']
    target_specific_findings = [f for f in top_findings if f.get('scope') != 'shared-host']
    return {
        'total_targets': total_targets,
        'raw_total_findings': raw_total_findings,
        'total_findings': len(top_findings),
        'priority_counts': dict(priority_counter),
        'category_counts': dict(category_counter),
        'per_target': per_target,
        'shared_asset_findings': shared_asset_findings[:50],
        'target_specific_findings': target_specific_findings[:50],
        'top_findings': top_findings[:50],
        'target_asset_hosts': target_asset_hosts,
    }



def write_aggregate_reports(results: Iterable[ScanResult], output_dir: str) -> dict[str, str]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    payload = build_aggregate_payload(results)

    summary_json = output / 'aggregate_summary.json'
    summary_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')

    md = output / 'aggregate_report.md'
    lines = [
        '# Informe agregado de batch scan',
        '',
        f"- **Targets analizados:** {payload['total_targets']}",
        f"- **Hallazgos totales (correlacionados):** {payload['total_findings']}",
        f"- **Hallazgos crudos antes de agrupar por activo:** {payload['raw_total_findings']}",
        f"- **Prioridades:** {payload['priority_counts']}",
        f"- **Categorías:** {payload['category_counts']}",
        '',
        '## Resumen por target',
        '',
    ]
    for item in payload['per_target']:
        lines.append(f"- **{item['target']}**: {item['findings']} hallazgos, prioridades {item['priorities']}")

    vuln_findings = [f for f in payload['target_specific_findings'] if f.get('category') not in NETWORK_DISCOVERY_CATEGORIES and f.get('category') != 'discovery']
    network_findings = [f for f in payload['target_specific_findings'] if f.get('category') in NETWORK_DISCOVERY_CATEGORIES]
    discovery_findings = [f for f in payload['target_specific_findings'] if f.get('category') == 'discovery']
    shared_assets = [f for f in payload['shared_asset_findings'] if f.get('category') in NETWORK_DISCOVERY_CATEGORIES]

    lines += ['', '## Vulnerabilidades y misconfiguraciones más relevantes', '']
    if not vuln_findings:
        lines.append('- No se detectaron vulnerabilidades o misconfiguraciones relevantes en el agregado.')
    for finding in vuln_findings:
        suffix = f" | targets: {finding['target_labels']}" if finding.get('target_labels') else ''
        lines.append(f"- **{finding['priority'] or finding['severity']}** | `{finding['location']}` | {finding['title']} ({finding['category']}){suffix}")

    lines += ['', '## Activos compartidos entre targets', '']
    if not shared_assets:
        lines.append('- No se detectaron activos compartidos relevantes en el agregado.')
    for finding in shared_assets:
        lines.append(
            f"- **{finding['priority'] or finding['severity']}** | `{finding['location']}` | {finding['title']} ({finding['category']})"
            f" | expuesto a través de {finding['target_count']} targets: {finding['target_labels']}"
        )

    lines += ['', '## Servicios y puertos específicos por target', '']
    if not network_findings:
        lines.append('- No se detectaron servicios o puertos específicos adicionales mediante descubrimiento de red.')
    for finding in network_findings:
        suffix = f" | target: {finding['target_labels']}" if finding.get('target_labels') else ''
        lines.append(f"- **{finding['priority'] or finding['severity']}** | `{finding['location']}` | {finding['title']} ({finding['category']}){suffix}")

    lines += ['', '## Superficie descubierta o protegida', '']
    if not discovery_findings:
        lines.append('- No se detectó superficie protegida o de descubrimiento relevante en el agregado.')
    for finding in discovery_findings:
        suffix = f" | target: {finding['target_labels']}" if finding.get('target_labels') else ''
        lines.append(f"- **{finding['priority'] or finding['severity']}** | `{finding['location']}` | {finding['title']} ({finding['category']}){suffix}")
    md.write_text('\n'.join(lines).rstrip() + '\n', encoding='utf-8')

    csv_path = output / 'aggregate_findings.csv'
    with csv_path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(['scope', 'targets', 'target_count', 'location', 'asset_host', 'asset_port', 'title', 'priority', 'severity', 'category', 'verification_status', 'recommendation'])
        for finding in payload['top_findings']:
            writer.writerow([
                finding.get('scope', ''),
                finding.get('target_labels', ''),
                finding.get('target_count', 1),
                finding.get('location', ''),
                finding.get('asset_host', ''),
                finding.get('asset_port', ''),
                finding['title'],
                finding['priority'],
                finding['severity'],
                finding['category'],
                finding.get('verification_status', ''),
                finding['recommendation'],
            ])

    return {'summary_json': str(summary_json), 'markdown': str(md), 'csv': str(csv_path)}
