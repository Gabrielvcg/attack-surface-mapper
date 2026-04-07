from __future__ import annotations

import json
from pathlib import Path

from attack_surface_mapper.models.vulnerability import Vulnerability


def load_previous_scan(path: str | None) -> list[Vulnerability]:
    if not path:
        return []
    file_path = Path(path)
    if not file_path.exists():
        return []
    payload = json.loads(file_path.read_text(encoding='utf-8'))
    if isinstance(payload, dict):
        payload = payload.get('vulnerabilities', [])
    vulnerabilities: list[Vulnerability] = []
    for item in payload:
        if isinstance(item, dict):
            vulnerabilities.append(Vulnerability(**item))
    return vulnerabilities


def _index(vulnerabilities: list[Vulnerability]) -> dict[tuple[str, str, str], Vulnerability]:
    return {v.correlation_key(): v for v in vulnerabilities}


def compare_scans(current: list[Vulnerability], previous: list[Vulnerability]) -> dict[str, list[dict[str, str]]]:
    current_index = _index(current)
    previous_index = _index(previous)

    new_findings: list[dict[str, str]] = []
    resolved_findings: list[dict[str, str]] = []
    changed_findings: list[dict[str, str]] = []

    for key, vulnerability in current_index.items():
        if key not in previous_index:
            new_findings.append({'title': vulnerability.title, 'target': vulnerability.target, 'priority': vulnerability.priority or ''})
            continue
        old = previous_index[key]
        if (old.priority or '') != (vulnerability.priority or '') or (old.severity or '') != (vulnerability.severity or ''):
            changed_findings.append(
                {
                    'title': vulnerability.title,
                    'target': vulnerability.target,
                    'previous_priority': old.priority or '',
                    'current_priority': vulnerability.priority or '',
                    'previous_severity': old.severity or '',
                    'current_severity': vulnerability.severity or '',
                }
            )

    for key, vulnerability in previous_index.items():
        if key not in current_index:
            resolved_findings.append({'title': vulnerability.title, 'target': vulnerability.target, 'priority': vulnerability.priority or ''})

    return {
        'new_findings': sorted(new_findings, key=lambda item: (item['title'], item['target'])),
        'resolved_findings': sorted(resolved_findings, key=lambda item: (item['title'], item['target'])),
        'changed_findings': sorted(changed_findings, key=lambda item: (item['title'], item['target'])),
    }
