from __future__ import annotations

import csv
import json
from pathlib import Path

from attack_surface_mapper.reporting.review_matrix import build_review_rows, review_bucket_for_finding, write_review_matrix


def test_review_bucket_prefers_discovery_and_confirmed_validation() -> None:
    assert review_bucket_for_finding({'kind': 'discovery', 'verification_status': 'confirmed', 'confidence': 'high'}) == 'descubrimiento'
    assert review_bucket_for_finding({'kind': 'validation', 'verification_status': 'confirmed', 'confidence': 'high', 'priority': 'high'}) == 'priorizar'
    assert review_bucket_for_finding({'kind': 'validation', 'verification_status': 'confirmed', 'confidence': 'high', 'priority': 'low'}) == 'revisar'
    assert review_bucket_for_finding({'kind': 'validation', 'verification_status': 'likely', 'confidence': 'medium'}) == 'revisar'


def test_build_review_rows_reads_run_manifest_and_vulnerabilities(tmp_path: Path) -> None:
    run_dir = tmp_path / 'lab_demo'
    target_dir = run_dir / 'targets' / 'http_example'
    findings_dir = target_dir / 'findings'
    reports_dir = target_dir / 'reports'
    findings_dir.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    (findings_dir / 'vulnerabilities.json').write_text(
        json.dumps([
            {
                'title': 'GraphQL Surface Exposed',
                'target': 'https://target.example/graphql',
                'priority': 'high',
                'severity': 'high',
                'confidence': 'high',
                'verification_status': 'confirmed',
                'category': 'api',
                'kind': 'validation',
                'finding_id': 'finding-1',
                'correlation_id': 'corr-1',
                'needs_manual_validation': False,
                'source_count': 2,
                'asset_host': 'target.example',
                'asset_port': '443',
                'evidence_summary': 'graphql marker',
            }
        ]),
        encoding='utf-8',
    )
    (run_dir / 'run_manifest.json').write_text(
        json.dumps({
            'profile': 'passive-recon-safe',
            'effective_config': {'profile': 'passive-recon-safe'},
            'per_target': [
                {
                    'target': 'https://target.example',
                    'reports': {
                        'summary_json': str(reports_dir / 'report.summary.json'),
                    },
                }
            ],
        }),
        encoding='utf-8',
    )

    rows = build_review_rows([run_dir])

    assert len(rows) == 1
    assert rows[0]['run_name'] == 'lab_demo'
    assert rows[0]['profile'] == 'passive-recon-safe'
    assert rows[0]['finding_id'] == 'finding-1'
    assert rows[0]['bucket_revision'] == 'priorizar'
    assert rows[0]['etiqueta_analista'] == ''


def test_write_review_matrix_creates_csv_with_expected_columns(tmp_path: Path) -> None:
    output_path = tmp_path / 'review.csv'
    write_review_matrix([
        {
            'run_name': 'lab_demo',
            'profile': 'passive-recon-safe',
            'target': 'https://target.example',
            'finding_id': 'finding-1',
            'correlation_id': 'corr-1',
            'title': 'GraphQL Surface Exposed',
            'category': 'api',
            'kind': 'validation',
            'priority': 'high',
            'severity': 'high',
            'confidence': 'high',
            'verification_status': 'confirmed',
            'needs_manual_validation': 'false',
            'source_count': '2',
            'asset_host': 'target.example',
            'asset_port': '443',
            'evidence_summary': 'graphql marker',
            'bucket_revision': 'priorizar',
            'etiqueta_analista': '',
            'notas': '',
        }
    ], output_path)

    with output_path.open(encoding='utf-8', newline='') as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    assert rows[0]['run_name'] == 'lab_demo'
    assert rows[0]['bucket_revision'] == 'priorizar'
    assert rows[0]['etiqueta_analista'] == ''
