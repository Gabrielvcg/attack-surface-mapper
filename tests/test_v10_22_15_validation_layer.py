from __future__ import annotations

import json
from pathlib import Path

from attack_surface_mapper.analysis import compare_scans, enrich_vulnerabilities
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.reporting import ReportGenerator
from attack_surface_mapper.reporting.review_matrix import build_review_rows, review_bucket_for_finding


def test_enrichment_assigns_explicit_validation_roles() -> None:
    findings = enrich_vulnerabilities([
        Vulnerability(
            source='custom-auth-check',
            title='Metrics Endpoint Accessible Without Authentication',
            description='d',
            severity='high',
            target='https://target.example/metrics',
            category='authentication',
            confidence='high',
            verification_status='confirmed',
        ),
        Vulnerability(
            source='custom-api-check',
            title='GraphQL Surface Exposed',
            description='d',
            severity='medium',
            target='https://target.example/graphql',
            category='api',
            confidence='medium',
            verification_status='likely',
            needs_manual_validation=True,
        ),
        Vulnerability(
            source='custom-api-check',
            title='Multiple API Endpoints Exposed (10)',
            description='d',
            severity='medium',
            target='https://target.example/api',
            category='api',
            confidence='medium',
            verification_status='likely',
        ),
    ])

    validated, candidate, discovery = findings

    assert validated.finding_role == 'validated'
    assert validated.validated is True
    assert validated.validation_basis == 'response-evidence'

    assert candidate.finding_role == 'candidate'
    assert candidate.validated is False
    assert candidate.validation_basis == 'heuristic-evidence'
    assert candidate.needs_manual_validation is True

    assert discovery.finding_role == 'discovery'
    assert discovery.validated is False
    assert discovery.validation_basis == 'context-only'
    assert discovery.needs_manual_validation is False


def test_summary_payload_exposes_validation_layer_counts() -> None:
    findings = enrich_vulnerabilities([
        Vulnerability(
            source='custom-auth-check',
            title='Metrics Endpoint Accessible Without Authentication',
            description='d',
            severity='high',
            target='https://target.example/metrics',
            category='authentication',
            confidence='high',
            verification_status='confirmed',
        ),
        Vulnerability(
            source='custom-api-check',
            title='Swagger UI Exposed',
            description='d',
            severity='medium',
            target='https://target.example/swagger',
            category='api',
            confidence='medium',
            verification_status='likely',
            needs_manual_validation=True,
        ),
        Vulnerability(
            source='custom-api-check',
            title='Multiple API Endpoints Exposed (10)',
            description='d',
            severity='medium',
            target='https://target.example/api',
            category='api',
            confidence='medium',
            verification_status='likely',
        ),
    ])

    payload = ReportGenerator().build_summary_payload(findings, 'https://target.example')

    assert payload['stats']['validated_findings'] == 1
    assert payload['stats']['candidate_findings'] == 1
    assert payload['stats']['discovery_findings'] == 1
    assert payload['top_risk_findings'][0]['finding_role'] == 'validated'
    assert payload['top_review_findings'][0]['finding_role'] == 'candidate'
    assert payload['top_discovery_findings'][0]['finding_role'] == 'discovery'


def test_review_matrix_rows_include_validation_layer_fields(tmp_path: Path) -> None:
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
                'priority': 'medium',
                'severity': 'medium',
                'confidence': 'medium',
                'verification_status': 'likely',
                'category': 'api',
                'kind': 'validation',
                'finding_role': 'candidate',
                'validated': False,
                'validation_basis': 'heuristic-evidence',
                'finding_id': 'finding-1',
                'correlation_id': 'corr-1',
                'needs_manual_validation': True,
                'source_count': 1,
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

    assert rows[0]['finding_role'] == 'candidate'
    assert rows[0]['validated'] == 'false'
    assert rows[0]['validation_basis'] == 'heuristic-evidence'
    assert rows[0]['bucket_revision'] == 'revisar'


def test_review_bucket_prefers_explicit_finding_role() -> None:
    assert review_bucket_for_finding({
        'finding_role': 'discovery',
        'verification_status': 'confirmed',
        'confidence': 'high',
    }) == 'descubrimiento'
    assert review_bucket_for_finding({
        'finding_role': 'candidate',
        'verification_status': 'confirmed',
        'confidence': 'high',
        'priority': 'high',
    }) == 'revisar'
    assert review_bucket_for_finding({
        'finding_role': 'validated',
        'validated': True,
        'verification_status': 'confirmed',
        'confidence': 'high',
        'priority': 'high',
    }) == 'priorizar'


def test_compare_scans_tracks_finding_role_changes() -> None:
    previous = enrich_vulnerabilities([
        Vulnerability(
            source='custom-api-check',
            title='GraphQL Surface Exposed',
            description='d',
            severity='medium',
            target='https://target.example/graphql',
            matched_at='https://target.example/graphql',
            category='api',
            confidence='medium',
            verification_status='likely',
        )
    ])
    current = enrich_vulnerabilities([
        Vulnerability(
            source='custom-api-check',
            title='GraphQL Surface Exposed',
            description='d',
            severity='medium',
            target='https://target.example/graphql',
            matched_at='https://target.example/graphql',
            category='api',
            confidence='high',
            verification_status='confirmed',
        )
    ])

    comparison = compare_scans(current, previous)

    assert comparison['summary']['change_type_counts']['finding_role'] == 1
    assert comparison['changed_findings'][0]['previous_finding_role'] == 'candidate'
    assert comparison['changed_findings'][0]['current_finding_role'] == 'validated'
