from __future__ import annotations

from attack_surface_mapper.analysis import enrich_vulnerabilities
from attack_surface_mapper.batch.aggregate import build_aggregate_payload
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.orchestrator import ScanResult
from attack_surface_mapper.reporting.generator import ReportGenerator, ReportPaths


def test_scoring_orders_validated_candidate_and_discovery_findings() -> None:
    findings = enrich_vulnerabilities([
        Vulnerability(
            source='custom-auth-check',
            title='Metrics Endpoint Accessible Without Authentication',
            description='d',
            severity='high',
            target='https://target.example/metrics',
            matched_at='https://target.example/metrics',
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
            matched_at='https://target.example/swagger',
            category='api',
            confidence='high',
            verification_status='likely',
            needs_manual_validation=True,
        ),
        Vulnerability(
            source='custom-api-check',
            title='Multiple API Endpoints Exposed (10)',
            description='d',
            severity='medium',
            target='https://target.example/api',
            matched_at='https://target.example/api',
            category='api',
            confidence='medium',
            verification_status='likely',
            source_count=10,
        ),
    ])

    validated, candidate, discovery = findings

    assert validated.priority_score > candidate.priority_score > discovery.priority_score
    assert validated.priority == 'critical'
    assert candidate.priority == 'medium'
    assert discovery.priority == 'medium'
    assert validated.scoring_version == '1.0'


def test_summary_payload_exposes_scoring_metadata() -> None:
    findings = enrich_vulnerabilities([
        Vulnerability(
            source='custom-header-check',
            title='Missing Content-Security-Policy Header',
            description='d',
            severity='medium',
            target='https://target.example',
            category='headers',
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
    ])

    payload = ReportGenerator().build_summary_payload(findings, 'https://target.example')

    assert payload['scoring_version'] == '1.0'
    assert payload['stats']['average_priority_score'] is not None
    assert payload['top_findings'][0]['priority_score'] >= payload['top_findings'][1]['priority_score']


def test_aggregate_payload_keeps_numeric_priority_score() -> None:
    findings = enrich_vulnerabilities([
        Vulnerability(
            source='custom-auth-check',
            title='Metrics Endpoint Accessible Without Authentication',
            description='d',
            severity='high',
            target='https://target.example/metrics',
            matched_at='https://target.example/metrics',
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
            matched_at='https://target.example/graphql',
            category='api',
            confidence='medium',
            verification_status='likely',
            needs_manual_validation=True,
        ),
    ])

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

    assert payload['scoring_version'] == '1.0'
    assert payload['average_priority_score'] is not None
    assert payload['top_findings'][0]['priority_score'] >= payload['top_findings'][1]['priority_score']
