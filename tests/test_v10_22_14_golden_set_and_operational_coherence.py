from __future__ import annotations

import json
from pathlib import Path

from attack_surface_mapper.batch.aggregate import build_aggregate_payload
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.orchestrator import ScanResult
from attack_surface_mapper.reporting import (
    ReportGenerator,
    ReportPaths,
    evaluate_review_rows_against_golden_set,
    load_review_golden_set,
)


def test_management_and_actuator_share_operational_correlation_bucket() -> None:
    actuator = Vulnerability(
        source='custom-auth-check',
        title='Actuator Endpoint Accessible Without Authentication',
        description='d',
        severity='medium',
        target='https://target.example/actuator',
        matched_at='https://target.example/actuator',
        category='authentication',
    )
    management = Vulnerability(
        source='custom-panel-check',
        title='Exposed Management Endpoint',
        description='d',
        severity='medium',
        target='https://target.example/management',
        matched_at='https://target.example/management',
        category='panel-exposure',
    )

    assert actuator.correlation_key() == management.correlation_key()


def test_summary_payload_separates_review_surface_from_actionable_risk() -> None:
    findings = [
        Vulnerability(
            source='custom-auth-check',
            title='Metrics Endpoint Accessible Without Authentication',
            description='d',
            severity='high',
            priority='critical',
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
            priority='medium',
            target='https://target.example/swagger',
            category='api',
            confidence='high',
            verification_status='likely',
        ),
        Vulnerability(
            source='custom-header-check',
            title='Missing Content-Security-Policy Header',
            description='d',
            severity='medium',
            priority='medium',
            target='https://target.example',
            category='headers',
            confidence='high',
            verification_status='confirmed',
        ),
    ]

    payload = ReportGenerator().build_summary_payload(findings, 'https://target.example')

    assert payload['stats']['application_findings'] == 1
    assert payload['stats']['review_surface_findings'] == 1
    assert payload['stats']['hygiene_findings'] == 1
    assert [item['title'] for item in payload['top_risk_findings']] == ['Metrics Endpoint Accessible Without Authentication']
    assert [item['title'] for item in payload['top_review_findings']] == ['Swagger UI Exposed']


def test_aggregate_payload_exposes_finding_contract_and_keeps_review_surface_in_top_findings() -> None:
    findings = [
        Vulnerability(
            source='custom-auth-check',
            title='Metrics Endpoint Accessible Without Authentication',
            description='d',
            severity='high',
            priority='critical',
            target='https://target.example/metrics',
            category='authentication',
            confidence='high',
            verification_status='confirmed',
            kind='validation',
        ),
        Vulnerability(
            source='custom-api-check',
            title='GraphQL Surface Exposed',
            description='d',
            severity='medium',
            priority='medium',
            target='https://target.example/graphql',
            category='api',
            confidence='medium',
            verification_status='likely',
            kind='validation',
        ),
    ]
    result = ScanResult(
        target='https://target.example',
        vulnerabilities=findings,
        command=[],
        return_code=0,
        stdout='',
        stderr='',
        raw_findings_count=len(findings),
        output_json_path=None,
        raw_output_path=None,
        summary={'critical': 1, 'medium': 1},
        report_paths=ReportPaths(),
    )

    payload = build_aggregate_payload([result])

    assert payload['finding_contract']['schema_version'] == '1.0'
    assert payload['summary']['actionable_risk_findings'] == 1
    assert payload['summary']['review_surface_findings'] == 1
    assert payload['top_findings'][0]['title'] == 'Metrics Endpoint Accessible Without Authentication'
    assert any(item['title'] == 'GraphQL Surface Exposed' for item in payload['top_findings'])


def test_review_golden_set_matches_expected_rows() -> None:
    rows = [
        {
            'run_name': 'lab_juice_shop_passive_recon_enum',
            'title': 'Metrics Endpoint Accessible Without Authentication',
            'bucket_revision': 'priorizar',
            'priority': 'critical',
            'verification_status': 'confirmed',
        },
        {
            'run_name': 'lab_juice_shop_passive_recon_enum',
            'title': 'Swagger UI Exposed',
            'bucket_revision': 'revisar',
            'priority': 'medium',
            'verification_status': 'likely',
        },
        {
            'run_name': 'lab_juice_shop_passive_recon_enum',
            'title': 'GraphQL Surface Exposed',
            'bucket_revision': 'revisar',
            'priority': 'medium',
            'verification_status': 'likely',
        },
        {
            'run_name': 'lab_juice_shop_passive_recon_enum',
            'title': 'Multiple API Endpoints Exposed (10)',
            'bucket_revision': 'descubrimiento',
            'priority': 'medium',
            'verification_status': 'likely',
        },
        {
            'run_name': 'lab_juice_shop_passive_recon_enum',
            'title': 'Broad CORS Policy Observed',
            'bucket_revision': 'revisar',
            'priority': 'low',
            'verification_status': 'likely',
        },
        {
            'run_name': 'lab_dvwa_passive_recon_safe',
            'title': 'Missing Content-Security-Policy Header',
            'bucket_revision': 'revisar',
            'priority': 'medium',
            'verification_status': 'confirmed',
        },
    ]

    golden = load_review_golden_set(Path('tests/data/lab_review_golden_set.json'))
    evaluation = evaluate_review_rows_against_golden_set(rows, golden)

    assert evaluation['ok'] is True
    assert evaluation['checked'] == len(golden)
