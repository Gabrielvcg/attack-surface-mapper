from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable


def review_bucket_for_finding(finding: dict) -> str:
    title = str(finding.get('title') or '').lower()
    kind = str(finding.get('kind') or '').lower()
    category = str(finding.get('category') or '').lower()
    verification = str(finding.get('verification_status') or '').lower()
    confidence = str(finding.get('confidence') or '').lower()
    priority = str(finding.get('priority') or '').lower()

    documentation_like = title in {
        'swagger ui exposed',
        'openapi specification exposed',
        'api surface exposed',
    }
    surface_like = title in {
        'graphql surface exposed',
        'broad cors policy observed',
    }
    inventory_like = (
        kind == 'discovery'
        or category == 'discovery'
        or title.startswith('multiple api endpoints exposed')
        or title.startswith('protected api surface discovered')
        or title.startswith('multiple client-side api references observed')
        or title == 'client-side api reference observed'
        or title.startswith('technology fingerprint detected')
    )
    if inventory_like:
        return 'descubrimiento'
    if documentation_like:
        return 'revisar'
    if surface_like:
        return 'revisar'
    if category == 'headers':
        return 'revisar'
    if verification == 'confirmed' and confidence == 'high' and priority in {'medium', 'high', 'critical'}:
        return 'priorizar'
    if verification in {'confirmed', 'likely', 'needs_manual_validation'}:
        return 'revisar'
    return 'triage'


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding='utf-8'))


def load_review_matrix(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open(encoding='utf-8', newline='') as handle:
        return list(csv.DictReader(handle))


def load_review_golden_set(path: str | Path) -> list[dict[str, str]]:
    payload = _load_json(Path(path))
    return [dict(item) for item in payload or []]


def evaluate_review_rows_against_golden_set(rows: Iterable[dict[str, str]], golden_set: Iterable[dict[str, str]]) -> dict[str, object]:
    indexed = {
        (
            str(row.get('run_name') or ''),
            str(row.get('title') or ''),
        ): row
        for row in rows
    }
    checked = 0
    mismatches: list[dict[str, str]] = []
    missing: list[dict[str, str]] = []
    for expected in golden_set:
        checked += 1
        key = (str(expected.get('run_name') or ''), str(expected.get('title') or ''))
        row = indexed.get(key)
        if row is None:
            missing.append({'run_name': key[0], 'title': key[1]})
            continue
        for field_name, expected_value in expected.items():
            if field_name in {'run_name', 'title'}:
                continue
            actual_value = str(row.get(field_name) or '')
            if actual_value != str(expected_value):
                mismatches.append({
                    'run_name': key[0],
                    'title': key[1],
                    'field': field_name,
                    'expected': str(expected_value),
                    'actual': actual_value,
                })
    return {
        'checked': checked,
        'missing': missing,
        'mismatches': mismatches,
        'ok': not missing and not mismatches,
    }


def _iter_vulnerability_files(run_dir: Path) -> Iterable[tuple[str, str, Path]]:
    manifest_path = run_dir / 'run_manifest.json'
    if not manifest_path.exists():
        return []
    manifest = _load_json(manifest_path)
    profile = str(((manifest or {}).get('effective_config') or {}).get('profile') or (manifest or {}).get('profile') or '')
    rows = []
    for target_info in (manifest.get('per_target') or []):
        target = str(target_info.get('target') or '')
        report_summary = (((target_info.get('reports') or {}).get('summary_json')) or '')
        if report_summary:
            target_dir = Path(report_summary).parents[1]
            vulnerabilities_path = target_dir / 'findings' / 'vulnerabilities.json'
        else:
            target_dir = None
            vulnerabilities_path = None
        if vulnerabilities_path and vulnerabilities_path.exists():
            rows.append((profile, target, vulnerabilities_path))
    return rows


def build_review_rows(run_dirs: Iterable[str | Path]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for run_dir in (Path(item) for item in run_dirs):
        for profile, target, vulnerabilities_path in _iter_vulnerability_files(run_dir):
            findings = _load_json(vulnerabilities_path)
            for finding in findings:
                row = {
                    'run_name': run_dir.name,
                    'profile': profile,
                    'target': target,
                    'finding_id': str(finding.get('finding_id') or ''),
                    'correlation_id': str(finding.get('correlation_id') or ''),
                    'title': str(finding.get('title') or ''),
                    'category': str(finding.get('category') or ''),
                    'kind': str(finding.get('kind') or ''),
                    'priority': str(finding.get('priority') or ''),
                    'severity': str(finding.get('severity') or ''),
                    'confidence': str(finding.get('confidence') or ''),
                    'verification_status': str(finding.get('verification_status') or ''),
                    'needs_manual_validation': 'true' if bool(finding.get('needs_manual_validation')) else 'false',
                    'source_count': str(finding.get('source_count') or ''),
                    'asset_host': str(finding.get('asset_host') or ''),
                    'asset_port': str(finding.get('asset_port') or ''),
                    'evidence_summary': str(finding.get('evidence_summary') or ''),
                    'bucket_revision': review_bucket_for_finding(finding),
                    'etiqueta_analista': '',
                    'notas': '',
                }
                rows.append(row)
    rows.sort(key=lambda item: (item['run_name'], item['target'], item['priority'], item['title']))
    return rows


def write_review_matrix(rows: Iterable[dict[str, str]], output_path: str | Path) -> str:
    fieldnames = [
        'run_name',
        'profile',
        'target',
        'finding_id',
        'correlation_id',
        'title',
        'category',
        'kind',
        'priority',
        'severity',
        'confidence',
        'verification_status',
        'needs_manual_validation',
        'source_count',
        'asset_host',
        'asset_port',
        'evidence_summary',
        'bucket_revision',
        'etiqueta_analista',
        'notas',
    ]
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, '') for key in fieldnames})
    return str(destination)
