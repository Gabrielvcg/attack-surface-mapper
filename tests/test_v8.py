from __future__ import annotations

import json
from pathlib import Path

from attack_surface_mapper.batch.aggregate import build_aggregate_payload, write_aggregate_reports
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.orchestrator import ScanResult
from attack_surface_mapper.reporting import ReportPaths
from attack_surface_mapper.utils.config import load_yaml_config


def build_scan_result(target: str, priority: str = 'high') -> ScanResult:
    vuln = Vulnerability(
        source='nuclei',
        title='Prometheus Metrics - Detect',
        description='desc',
        severity='medium',
        priority=priority,
        target=f'{target}/metrics',
        category='panel-exposure',
        recommendation='Fix it',
    )
    return ScanResult(
        target=target,
        vulnerabilities=[vuln],
        command=['nuclei'],
        return_code=0,
        stdout='',
        stderr='',
        raw_findings_count=1,
        output_json_path='out.json',
        raw_output_path='raw.jsonl',
        summary={priority: 1},
        report_paths=ReportPaths(markdown='a.md'),
    )


def test_load_yaml_config(tmp_path: Path) -> None:
    cfg = tmp_path / 'config.yml'
    cfg.write_text('profile: deep\ntargets:\n  - https://a\n  - https://b\nmodules:\n  headers: true\n', encoding='utf-8')
    data = load_yaml_config(str(cfg))
    assert data['profile'] == 'deep'
    assert data['targets'][1] == 'https://b'


def test_build_aggregate_payload_and_reports(tmp_path: Path) -> None:
    results = [build_scan_result('https://a', 'high'), build_scan_result('https://b', 'medium')]
    payload = build_aggregate_payload(results)
    assert payload['total_targets'] == 2
    assert payload['total_findings'] == 2
    paths = write_aggregate_reports(results, str(tmp_path))
    assert Path(paths['summary_json']).exists()
    summary = json.loads(Path(paths['summary_json']).read_text(encoding='utf-8'))
    assert summary['priority_counts']['high'] == 1
    assert summary['priority_counts']['medium'] == 1
