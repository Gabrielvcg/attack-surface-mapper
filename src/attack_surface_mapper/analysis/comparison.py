from __future__ import annotations

import json
from pathlib import Path

from attack_surface_mapper.models.vulnerability import Vulnerability

PRIORITY_SCORE = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
SEVERITY_SCORE = {'info': 1, 'low': 2, 'medium': 3, 'high': 4, 'critical': 5, 'unknown': 0}
CONFIDENCE_SCORE = {'low': 1, 'medium': 2, 'high': 3}
VERIFICATION_SCORE = {'discarded': 0, 'heuristic': 1, 'needs_manual_validation': 2, 'likely': 3, 'confirmed': 4}
FINDING_ROLE_SCORE = {'discovery': 0, 'candidate': 1, 'validated': 2}


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


def _serialise_finding(vulnerability: Vulnerability) -> dict[str, str]:
    return {
        'title': vulnerability.title,
        'target': vulnerability.target,
        'priority': vulnerability.priority or '',
        'severity': vulnerability.severity or '',
        'confidence': vulnerability.confidence or '',
        'verification_status': vulnerability.verification_status or '',
        'kind': vulnerability.kind or '',
        'finding_role': vulnerability.finding_role or '',
        'validated': str(bool(vulnerability.validated)).lower(),
        'validation_basis': vulnerability.validation_basis or '',
        'category': vulnerability.category or '',
        'finding_id': vulnerability.finding_id or '',
        'correlation_id': vulnerability.correlation_id or '',
    }


def _change_direction(previous: Vulnerability, current: Vulnerability) -> str:
    priority_delta = PRIORITY_SCORE.get((current.priority or '').lower(), 0) - PRIORITY_SCORE.get((previous.priority or '').lower(), 0)
    severity_delta = SEVERITY_SCORE.get((current.severity or '').lower(), 0) - SEVERITY_SCORE.get((previous.severity or '').lower(), 0)
    confidence_delta = CONFIDENCE_SCORE.get((current.confidence or '').lower(), 0) - CONFIDENCE_SCORE.get((previous.confidence or '').lower(), 0)
    verification_delta = VERIFICATION_SCORE.get((current.verification_status or '').lower(), 0) - VERIFICATION_SCORE.get((previous.verification_status or '').lower(), 0)
    role_delta = FINDING_ROLE_SCORE.get((current.finding_role or '').lower(), 0) - FINDING_ROLE_SCORE.get((previous.finding_role or '').lower(), 0)
    combined_delta = priority_delta + severity_delta + confidence_delta + verification_delta + role_delta
    if combined_delta > 0:
        return 'promoted'
    if combined_delta < 0:
        return 'regressed'
    return 'updated'


def compare_scans(current: list[Vulnerability], previous: list[Vulnerability]) -> dict:
    current_index = _index(current)
    previous_index = _index(previous)

    new_findings: list[dict[str, str]] = []
    resolved_findings: list[dict[str, str]] = []
    changed_findings: list[dict[str, str | list[str]]] = []
    promoted_findings: list[dict[str, str | list[str]]] = []
    regressed_findings: list[dict[str, str | list[str]]] = []
    updated_findings: list[dict[str, str | list[str]]] = []
    unchanged_count = 0
    change_type_counts = {
        'priority': 0,
        'severity': 0,
        'confidence': 0,
        'verification_status': 0,
        'finding_role': 0,
    }

    for key, vulnerability in current_index.items():
        if key not in previous_index:
            new_findings.append(_serialise_finding(vulnerability))
            continue
        old = previous_index[key]
        change_types: list[str] = []
        if (old.priority or '') != (vulnerability.priority or ''):
            change_types.append('priority')
            change_type_counts['priority'] += 1
        if (old.severity or '') != (vulnerability.severity or ''):
            change_types.append('severity')
            change_type_counts['severity'] += 1
        if (old.confidence or '') != (vulnerability.confidence or ''):
            change_types.append('confidence')
            change_type_counts['confidence'] += 1
        if (old.verification_status or '') != (vulnerability.verification_status or ''):
            change_types.append('verification_status')
            change_type_counts['verification_status'] += 1
        if (old.finding_role or '') != (vulnerability.finding_role or ''):
            change_types.append('finding_role')
            change_type_counts['finding_role'] += 1
        if not change_types:
            unchanged_count += 1
            continue
        direction = _change_direction(old, vulnerability)
        change_record = {
            'title': vulnerability.title,
            'target': vulnerability.target,
            'previous_priority': old.priority or '',
            'current_priority': vulnerability.priority or '',
            'previous_severity': old.severity or '',
            'current_severity': vulnerability.severity or '',
            'previous_confidence': old.confidence or '',
            'current_confidence': vulnerability.confidence or '',
            'previous_verification_status': old.verification_status or '',
            'current_verification_status': vulnerability.verification_status or '',
            'previous_finding_role': old.finding_role or '',
            'current_finding_role': vulnerability.finding_role or '',
            'kind': vulnerability.kind or old.kind or '',
            'category': vulnerability.category or old.category or '',
            'change_types': change_types,
            'change_direction': direction,
        }
        changed_findings.append(change_record)
        if direction == 'promoted':
            promoted_findings.append(change_record)
        elif direction == 'regressed':
            regressed_findings.append(change_record)
        else:
            updated_findings.append(change_record)

    for key, vulnerability in previous_index.items():
        if key not in current_index:
            resolved_findings.append(_serialise_finding(vulnerability))

    return {
        'schema_version': '1.0',
        'summary': {
            'new_findings': len(new_findings),
            'resolved_findings': len(resolved_findings),
            'changed_findings': len(changed_findings),
            'promoted_findings': len(promoted_findings),
            'regressed_findings': len(regressed_findings),
            'updated_findings': len(updated_findings),
            'unchanged_findings': unchanged_count,
            'change_type_counts': change_type_counts,
        },
        'new_findings': sorted(new_findings, key=lambda item: (item['title'], item['target'])),
        'resolved_findings': sorted(resolved_findings, key=lambda item: (item['title'], item['target'])),
        'changed_findings': sorted(changed_findings, key=lambda item: (item['title'], item['target'])),
        'promoted_findings': sorted(promoted_findings, key=lambda item: (item['title'], item['target'])),
        'regressed_findings': sorted(regressed_findings, key=lambda item: (item['title'], item['target'])),
        'updated_findings': sorted(updated_findings, key=lambda item: (item['title'], item['target'])),
    }
