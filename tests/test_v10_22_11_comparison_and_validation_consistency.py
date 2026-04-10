from __future__ import annotations

from attack_surface_mapper.analysis.correlation import correlate_vulnerabilities
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


def test_correlation_prefers_confirmed_primary_over_likely_nuclei_match() -> None:
    items = [
        Vulnerability(
            source='nuclei',
            title='GraphQL Surface Exposed',
            description='d',
            severity='high',
            target='https://target.example/graphql',
            matched_at='https://target.example/graphql',
            category='api',
            confidence='medium',
            verification_status='likely',
            evidence='heuristic graphql match',
        ),
        Vulnerability(
            source='custom-auth-check',
            title='GraphQL Endpoint Accessible Without Authentication',
            description='d',
            severity='medium',
            target='https://target.example/graphql',
            matched_at='https://target.example/graphql',
            category='authentication',
            confidence='high',
            verification_status='confirmed',
            evidence='GET /graphql devolvió 200 con marcadores graphql',
        ),
    ]

    correlated = correlate_vulnerabilities(items)

    assert len(correlated) == 1
    assert correlated[0].title == 'GraphQL Endpoint Accessible Without Authentication'
    assert correlated[0].verification_status == 'confirmed'
    assert correlated[0].source_count == 2


def test_unique_confirmed_finding_keeps_higher_priority_than_multi_source_likely() -> None:
    confirmed = Vulnerability(
        source='custom-auth-check',
        title='GraphQL Endpoint Accessible Without Authentication',
        description='d',
        severity='medium',
        target='http://localhost:3000/graphql',
        matched_at='http://localhost:3000/graphql',
        category='authentication',
        confidence='high',
        verification_status='confirmed',
    )
    multi_source_likely = Vulnerability(
        source='custom-api-check',
        title='Multiple API Endpoints Exposed (3)',
        description='d',
        severity='medium',
        target='http://localhost:3000/api',
        matched_at='http://localhost:3000/api',
        category='api',
        confidence='high',
        verification_status='likely',
        source_count=3,
        needs_manual_validation=True,
    )

    enrich_vulnerabilities([confirmed, multi_source_likely])
    rank = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

    assert rank[confirmed.priority] >= rank[multi_source_likely.priority]


def test_confirmed_medium_header_does_not_escalate_to_high_priority_by_default() -> None:
    vuln = Vulnerability(
        source='custom-header-check',
        title='Missing Content-Security-Policy Header',
        description='d',
        severity='medium',
        target='https://target.example',
        category='headers',
        confidence='high',
        verification_status='confirmed',
    )

    enrich_vulnerabilities([vuln])

    assert vuln.priority == 'medium'


def test_confirmed_swagger_documentation_does_not_escalate_to_critical_priority() -> None:
    vuln = Vulnerability(
        source='custom-api-check',
        title='Swagger UI Exposed',
        description='d',
        severity='medium',
        target='https://target.example/swagger',
        category='api',
        confidence='high',
        verification_status='confirmed',
    )

    enrich_vulnerabilities([vuln])

    assert vuln.priority == 'medium'


def test_likely_graphql_without_auth_stays_below_high_priority() -> None:
    vuln = Vulnerability(
        source='custom-auth-check',
        title='GraphQL Endpoint Accessible Without Authentication',
        description='d',
        severity='medium',
        target='https://target.example/graphql',
        category='authentication',
        confidence='medium',
        verification_status='likely',
        needs_manual_validation=True,
    )

    enrich_vulnerabilities([vuln])

    assert vuln.priority == 'medium'


def test_multiple_api_endpoints_inventory_priority_stays_medium() -> None:
    vuln = Vulnerability(
        source='custom-api-check',
        title='Multiple API Endpoints Exposed (10)',
        description='d',
        severity='medium',
        target='https://target.example/api',
        category='api',
        confidence='high',
        verification_status='likely',
        source_count=10,
        needs_manual_validation=True,
    )

    enrich_vulnerabilities([vuln])

    assert vuln.priority == 'medium'
