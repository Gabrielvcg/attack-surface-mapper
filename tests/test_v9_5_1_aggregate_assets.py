from attack_surface_mapper.batch.aggregate import build_aggregate_payload
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.orchestrator import ScanResult
from attack_surface_mapper.reporting import ReportPaths


def make_result(target: str, vulns: list[Vulnerability]) -> ScanResult:
    return ScanResult(
        target=target,
        vulnerabilities=vulns,
        command=[],
        return_code=0,
        stdout='',
        stderr='',
        raw_findings_count=len(vulns),
        output_json_path=None,
        raw_output_path=None,
        summary={},
        report_paths=ReportPaths(),
    )


def test_aggregate_deduplicates_shared_network_assets_and_keeps_targets():
    v1 = Vulnerability(
        source='nmap',
        title='Exposed MariaDB Service',
        description='desc',
        severity='medium',
        target='152.228.147.181:3306',
        matched_at='152.228.147.181:3306',
        host='152.228.147.181',
        port='3306',
        category='database',
        priority='high',
        verification_status='confirmed',
        recommendation='rec',
    )
    v2 = Vulnerability(
        source='nmap',
        title='Exposed MariaDB Service',
        description='desc',
        severity='medium',
        target='152.228.147.181:3306',
        matched_at='152.228.147.181:3306',
        host='152.228.147.181',
        port='3306',
        category='database',
        priority='high',
        verification_status='confirmed',
        recommendation='rec',
    )
    payload = build_aggregate_payload([
        make_result('http://members-api-dev.test.dinamicarea.es', [v1]),
        make_result('http://qapi-api-dev.test.dinamicarea.es', [v2]),
    ])
    assert payload['raw_total_findings'] == 2
    assert payload['total_findings'] == 1
    finding = payload['top_findings'][0]
    assert finding['target_count'] == 2
    assert 'http://members-api-dev.test.dinamicarea.es' in finding['targets']
    assert 'http://qapi-api-dev.test.dinamicarea.es' in finding['targets']
