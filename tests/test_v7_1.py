from __future__ import annotations

import json
from pathlib import Path

from attack_surface_mapper.analysis.comparison import compare_scans, load_previous_scan
from attack_surface_mapper.analysis.correlation import correlate_vulnerabilities
from attack_surface_mapper.analysis.enrichment import enrich_vulnerabilities
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.parsers.nuclei_parser import NucleiParser
from attack_surface_mapper.reporting import ReportGenerator


def test_parser_infers_category_and_keeps_compact_raw() -> None:
    raw = '{"template-id":"prometheus-metrics","matched-at":"http://localhost:3000/metrics","info":{"name":"Prometheus Metrics - Detect","description":"desc","severity":"medium","tags":["exposure","prometheus"],"classification":{"cwe-id":["cwe-200"],"cvss-score":5.3}}}'
    findings = NucleiParser.parse_jsonl(raw)
    vulns = NucleiParser.to_vulnerabilities(findings, include_raw=True)
    assert len(vulns) == 1
    assert vulns[0].category == 'panel-exposure'
    assert vulns[0].raw['template-id'] == 'prometheus-metrics'


def test_enrichment_adds_priority_recommendation_and_summary() -> None:
    vuln = Vulnerability(source='nuclei', title='Prometheus Metrics - Detect', description='desc', severity='medium', target='http://example.com/metrics', category='panel-exposure', evidence='curl ...')
    enrich_vulnerabilities([vuln])
    assert vuln.priority in {'high', 'critical'}
    assert vuln.recommendation
    assert vuln.evidence_summary


def test_correlation_merges_multiple_sources() -> None:
    base = dict(description='desc', severity='medium', target='http://example.com/metrics', category='panel-exposure')
    a = Vulnerability(source='nuclei', title='Prometheus Metrics - Detect', evidence='curl a', **base)
    b = Vulnerability(source='panels', title='Exposed panel', evidence='curl b', **base)
    merged = correlate_vulnerabilities(enrich_vulnerabilities([a, b]))
    assert len(merged) == 1
    assert merged[0].source_count == 2
    assert set(merged[0].related_sources) == {'nuclei', 'panels'}


def test_compare_scans_detects_new_and_changed(tmp_path: Path) -> None:
    old = [Vulnerability(source='nuclei', title='Old', description='d', severity='low', target='http://a', priority='low')]
    new = [Vulnerability(source='nuclei', title='Old', description='d', severity='high', target='http://a', priority='high'), Vulnerability(source='nuclei', title='New', description='d', severity='low', target='http://b', priority='low')]
    diff = compare_scans(new, old)
    assert len(diff['new_findings']) == 1
    assert len(diff['changed_findings']) == 1

    previous_path = tmp_path / 'prev.json'
    previous_path.write_text(json.dumps([v.to_dict() for v in old]), encoding='utf-8')
    loaded = load_previous_scan(str(previous_path))
    assert len(loaded) == 1
    assert loaded[0].title == 'Old'


def test_reporting_includes_comparison(tmp_path: Path) -> None:
    vuln = Vulnerability(source='nuclei', title='Prometheus Metrics - Detect', description='desc', severity='medium', target='http://example.com/metrics', category='panel-exposure', priority='high', confidence='high', recommendation='Fix it', evidence_summary='snippet')
    report = ReportGenerator(title='Test report')
    md = tmp_path / 'report.md'
    summary = tmp_path / 'summary.json'
    comparison = {'new_findings': [{'title': 'x', 'target': 'y', 'priority': 'high'}], 'resolved_findings': [], 'changed_findings': []}
    report.generate_markdown([vuln], 'http://example.com', str(md), comparison=comparison)
    report.generate_summary_json([vuln], 'http://example.com', str(summary), comparison=comparison)
    assert 'Comparación con baseline' in md.read_text(encoding='utf-8')
    payload = json.loads(summary.read_text(encoding='utf-8'))
    assert payload['comparison']['new_findings'][0]['title'] == 'x'
