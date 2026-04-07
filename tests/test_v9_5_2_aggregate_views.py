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


def test_aggregate_groups_network_findings_by_shared_asset_and_keeps_target_views():
    members_db = Vulnerability(
        source='nmap', title='Exposed MariaDB Service', description='desc', severity='medium',
        target='152.228.147.181:3306', matched_at='152.228.147.181:3306', host='152.228.147.181', port='3306',
        category='database', priority='high', verification_status='confirmed', recommendation='rec',
    )
    qapi_epmd = Vulnerability(
        source='nuclei', title='Erlang Port Mapper Daemon', description='desc', severity='low',
        target='qapi-api-dev.test.dinamicarea.es:4369', matched_at='qapi-api-dev.test.dinamicarea.es:4369',
        host='qapi-api-dev.test.dinamicarea.es', port='4369', category='message-broker', priority='medium',
        verification_status='likely', recommendation='rec', needs_manual_validation=True,
    )
    qapi_db = Vulnerability(
        source='nmap', title='Exposed MariaDB Service', description='desc', severity='medium',
        target='152.228.147.181:3306', matched_at='152.228.147.181:3306', host='152.228.147.181', port='3306',
        category='database', priority='high', verification_status='confirmed', recommendation='rec',
    )
    members_epmd = Vulnerability(
        source='nuclei', title='Erlang Port Mapper Daemon', description='desc', severity='low',
        target='members-api-dev.test.dinamicarea.es:4369', matched_at='members-api-dev.test.dinamicarea.es:4369',
        host='members-api-dev.test.dinamicarea.es', port='4369', category='message-broker', priority='medium',
        verification_status='likely', recommendation='rec', needs_manual_validation=True,
    )
    discovery = Vulnerability(
        source='custom-auth-check', title='Protected Management Endpoint Discovered', description='desc', severity='low',
        target='http://members-api-dev.test.dinamicarea.es/management', matched_at='http://members-api-dev.test.dinamicarea.es/management',
        host='members-api-dev.test.dinamicarea.es', category='discovery', priority='low', verification_status='confirmed', recommendation='rec',
    )
    payload = build_aggregate_payload([
        make_result('http://members-api-dev.test.dinamicarea.es', [members_db, members_epmd, discovery]),
        make_result('http://qapi-api-dev.test.dinamicarea.es', [qapi_db, qapi_epmd]),
    ])
    shared = payload['shared_asset_findings']
    assert any(f['location'] == '152.228.147.181:3306' and f['target_count'] == 2 for f in shared)
    # EPMD should now also group by the resolved shared IP from the target's network findings.
    assert any(f['location'] == '152.228.147.181:4369' and f['target_count'] == 2 for f in shared)
    specific = payload['target_specific_findings']
    assert any(f['category'] == 'discovery' and f['target_labels'] == 'http://members-api-dev.test.dinamicarea.es' for f in specific)
