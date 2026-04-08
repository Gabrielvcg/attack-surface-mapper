from __future__ import annotations

from attack_surface_mapper.analysis.comparison import compare_scans
from attack_surface_mapper.analysis.enrichment import enrich_vulnerabilities
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.reporting.generator import ReportGenerator


def test_compare_scans_reports_promotions_regressions_and_change_types() -> None:
    previous = [
        Vulnerability(
            source='custom-api-check',
            title='GraphQL Surface Exposed',
            description='d',
            severity='medium',
            priority='medium',
            confidence='medium',
            verification_status='likely',
            target='https://target.example/graphql',
            matched_at='https://target.example/graphql',
            category='api',
            kind='validation',
        ),
        Vulnerability(
            source='custom-api-check',
            title='Swagger UI Exposed',
            description='d',
            severity='high',
            priority='high',
            confidence='high',
            verification_status='confirmed',
            target='https://target.example/swagger',
            matched_at='https://target.example/swagger',
            category='api',
            kind='validation',
        ),
    ]
    current = [
        Vulnerability(
            source='custom-api-check',
            title='GraphQL Surface Exposed',
            description='d',
            severity='high',
            priority='high',
            confidence='high',
            verification_status='confirmed',
            target='https://target.example/graphql',
            matched_at='https://target.example/graphql',
            category='api',
            kind='validation',
        ),
        Vulnerability(
            source='custom-api-check',
            title='Swagger UI Exposed',
            description='d',
            severity='medium',
            priority='medium',
            confidence='medium',
            verification_status='likely',
            target='https://target.example/swagger',
            matched_at='https://target.example/swagger',
            category='api',
            kind='validation',
        ),
        Vulnerability(
            source='custom-auth-check',
            title='Admin Panel Accessible Without Authentication',
            description='d',
            severity='high',
            priority='high',
            confidence='high',
            verification_status='confirmed',
            target='https://target.example/admin',
            matched_at='https://target.example/admin',
            category='authentication',
            kind='validation',
        ),
    ]

    comparison = compare_scans(current, previous)

    assert comparison['schema_version'] == '1.0'
    assert comparison['summary']['new_findings'] == 1
    assert comparison['summary']['changed_findings'] == 2
    assert comparison['summary']['promoted_findings'] == 1
    assert comparison['summary']['regressed_findings'] == 1
    assert comparison['summary']['change_type_counts']['priority'] == 2
    assert comparison['summary']['change_type_counts']['verification_status'] == 2
    assert comparison['promoted_findings'][0]['title'] == 'GraphQL Surface Exposed'
    assert comparison['regressed_findings'][0]['title'] == 'Swagger UI Exposed'
    assert 'confidence' in comparison['promoted_findings'][0]['change_types']


def test_report_summary_and_markdown_surface_comparison_summary(tmp_path) -> None:
    vuln = Vulnerability(
        source='custom-api-check',
        title='GraphQL Surface Exposed',
        description='d',
        severity='high',
        priority='high',
        confidence='high',
        verification_status='confirmed',
        target='https://target.example/graphql',
        category='api',
    )
    comparison = {
        'schema_version': '1.0',
        'summary': {
            'new_findings': 1,
            'resolved_findings': 0,
            'changed_findings': 2,
            'promoted_findings': 1,
            'regressed_findings': 1,
            'updated_findings': 0,
            'unchanged_findings': 3,
            'change_type_counts': {'priority': 2},
        },
        'new_findings': [{'title': 'x', 'target': 'y'}],
        'resolved_findings': [],
        'changed_findings': [{'title': 'z', 'target': 'y'}],
        'promoted_findings': [{'title': 'x', 'target': 'y'}],
        'regressed_findings': [{'title': 'z', 'target': 'y'}],
        'updated_findings': [],
    }

    generator = ReportGenerator()
    payload = generator.build_summary_payload([vuln], 'https://target.example', comparison=comparison)
    markdown = generator.generate_markdown([vuln], 'https://target.example', str(tmp_path / 'asm_compare_report.md'), comparison=comparison)

    assert payload['comparison_summary']['promoted_findings'] == 1
    assert payload['comparison']['promoted_findings'][0]['title'] == 'x'
    content = open(markdown, encoding='utf-8').read()
    assert 'Promovidos en riesgo/confianza' in content
    assert 'Regresados o debilitados' in content


def test_confirmed_application_findings_do_not_force_manual_validation() -> None:
    vuln = Vulnerability(
        source='custom-auth-check',
        title='Cookie Without HttpOnly Flag',
        description='d',
        severity='medium',
        target='https://target.example',
        category='authentication',
        confidence='high',
        verification_status='confirmed',
    )

    enrich_vulnerabilities([vuln])

    assert vuln.needs_manual_validation is False
    assert vuln.verification_status == 'confirmed'


def test_likely_application_findings_still_require_manual_validation() -> None:
    vuln = Vulnerability(
        source='custom-api-check',
        title='Swagger UI Exposed',
        description='d',
        severity='medium',
        target='https://target.example/swagger',
        category='api',
        confidence='medium',
        verification_status='likely',
    )

    enrich_vulnerabilities([vuln])

    assert vuln.needs_manual_validation is True
    assert vuln.priority in {'low', 'medium', 'high'}
