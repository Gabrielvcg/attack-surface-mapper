from __future__ import annotations

import json
from pathlib import Path

from attack_surface_mapper.reporting import export_elasticsearch_bundle


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')


def _bulk_documents(path: Path) -> list[dict]:
    lines = path.read_text(encoding='utf-8').splitlines()
    assert len(lines) % 2 == 0
    documents: list[dict] = []
    for index in range(1, len(lines), 2):
        documents.append(json.loads(lines[index]))
    return documents


def test_export_elasticsearch_bundle_writes_expected_files(tmp_path: Path) -> None:
    run_dir = tmp_path / 'lab_export_demo'
    target_dir = run_dir / 'targets' / 'http_example'

    _write_json(
        target_dir / 'findings' / 'vulnerabilities.json',
        [
            {
                'finding_id': 'finding-1',
                'correlation_id': 'corr-1',
                'source': 'custom-auth-check',
                'title': 'Metrics Endpoint Accessible Without Authentication',
                'target': 'https://target.example/metrics',
                'matched_at': 'https://target.example/metrics',
                'target_host_original': 'target.example',
                'asset_host': 'target.example',
                'asset_host_resolved': '203.0.113.10',
                'asset_port': '443',
                'scheme': 'https',
                'category': 'authentication',
                'severity': 'high',
                'priority': 'critical',
                'priority_score': 100,
                'scoring_version': '1.0',
                'confidence': 'high',
                'verification_status': 'confirmed',
                'finding_role': 'validated',
                'validated': True,
                'validation_basis': 'response-evidence',
                'kind': 'validation',
                'needs_manual_validation': False,
                'source_count': 1,
                'recommendation': 'Proteger /metrics.',
                'evidence_summary': '200 + metrics markers',
                'priority_reason': 'scoring details',
                'description': 'Exposición de métricas',
                'tags': ['auth'],
                'cwe': ['CWE-306'],
                'related_sources': ['custom-auth-check'],
                'raw': {'ignored': True},
            }
        ],
    )
    _write_json(
        target_dir / 'reports' / 'report.summary.json',
        {
            'schema_version': '1.0',
            'scoring_version': '1.0',
            'title': 'Informe target',
            'target': 'https://target.example',
            'executive_summary': 'Resumen corto',
            'stats': {
                'total_findings': 1,
                'average_priority_score': 100.0,
                'validated_findings': 1,
                'candidate_findings': 0,
                'application_findings': 1,
                'review_surface_findings': 0,
                'hygiene_findings': 0,
                'discovery_findings': 0,
                'needs_manual_validation': 0,
                'confirmed_high_or_critical': 1,
                'priority_counts': {'critical': 1},
                'severity_counts': {'high': 1},
                'category_counts': {'authentication': 1},
                'source_counts': {'custom-auth-check': 1},
            },
            'comparison_summary': {'new_findings': 1},
            'finding_contract': {'schema_version': '1.0'},
        },
    )
    _write_json(
        run_dir / 'reports' / 'aggregate_summary.json',
        {
            'schema_version': '1.0',
            'scoring_version': '1.0',
            'finding_contract': {'schema_version': '1.0'},
            'summary': {
                'total_findings': 1,
                'average_priority_score': 100.0,
                'validated_findings': 1,
                'candidate_findings': 0,
                'actionable_risk_findings': 1,
                'review_surface_findings': 0,
                'hygiene_findings': 0,
                'discovery_findings': 0,
                'priority_counts': {'critical': 1},
                'severity_counts': {'high': 1},
                'category_counts': {'authentication': 1},
            },
        },
    )
    _write_json(
        run_dir / 'run_manifest.json',
        {
            'schema_version': '1.0',
            'profile': 'passive-recon-safe',
            'run_dir': str(run_dir),
            'requested_targets': ['https://target.example'],
            'targets': ['https://target.example'],
            'errors': [],
            'pipeline': {'stages': ['browser_discovery', 'passive_validation']},
            'effective_config': {'profile': 'passive-recon-safe'},
            'results_summary': {'successful_targets': 1},
            'aggregate_reports': {'summary_json': str(run_dir / 'reports' / 'aggregate_summary.json')},
        },
    )

    manifest = export_elasticsearch_bundle(run_dir, index_prefix='asm-test')
    output_dir = run_dir / 'elasticsearch'

    assert manifest['documents'] == {'findings': 1, 'summaries': 2, 'runs': 1}
    assert (output_dir / 'findings_mapping.json').exists()
    assert (output_dir / 'summaries_mapping.json').exists()
    assert (output_dir / 'runs_mapping.json').exists()
    assert (output_dir / 'findings_bulk.ndjson').exists()
    assert (output_dir / 'summaries_bulk.ndjson').exists()
    assert (output_dir / 'runs_bulk.ndjson').exists()
    assert (output_dir / 'manual_kibana_devtools.md').exists()
    assert (output_dir / 'ingest_with_curl.sh').exists()
    assert (output_dir / 'ingest_with_python.py').exists()
    assert (output_dir / 'export_manifest.json').exists()

    finding_docs = _bulk_documents(output_dir / 'findings_bulk.ndjson')
    assert finding_docs[0]['finding_id'] == 'finding-1'
    assert finding_docs[0]['finding_role'] == 'validated'
    assert finding_docs[0]['validated'] is True
    assert finding_docs[0]['validation_basis'] == 'response-evidence'
    assert finding_docs[0]['priority_score'] == 100
    assert finding_docs[0]['scoring_version'] == '1.0'
    assert 'raw' not in finding_docs[0]

    summaries_docs = _bulk_documents(output_dir / 'summaries_bulk.ndjson')
    assert {doc['document_type'] for doc in summaries_docs} == {'target_summary', 'aggregate_summary'}
    assert any(doc.get('target_slug') == 'http_example' for doc in summaries_docs)

    runs_docs = _bulk_documents(output_dir / 'runs_bulk.ndjson')
    assert runs_docs[0]['document_type'] == 'run_manifest'
    assert runs_docs[0]['run_name'] == 'lab_export_demo'

    curl_script = (output_dir / 'ingest_with_curl.sh').read_text(encoding='utf-8')
    assert 'findings_bulk.ndjson' in curl_script
    assert 'asm-test-findings' in curl_script

    python_script = (output_dir / 'ingest_with_python.py').read_text(encoding='utf-8')
    assert 'summaries_mapping.json' in python_script
    assert 'asm-test-runs' in python_script

    manual_helper = (output_dir / 'manual_kibana_devtools.md').read_text(encoding='utf-8')
    assert 'findings_mapping.json' in manual_helper
    assert 'runs_bulk.ndjson' in manual_helper


def test_export_elasticsearch_bundle_uses_stable_bulk_ids(tmp_path: Path) -> None:
    run_dir = tmp_path / 'lab_export_ids'
    target_dir = run_dir / 'targets' / 'http_example'

    _write_json(
        target_dir / 'findings' / 'vulnerabilities.json',
        [
            {
                'finding_id': 'finding-alpha',
                'correlation_id': 'corr-alpha',
                'title': 'GraphQL Surface Exposed',
                'target': 'https://target.example/graphql',
                'asset_host': 'target.example',
                'asset_host_resolved': '203.0.113.11',
                'asset_port': '443',
                'category': 'api',
                'severity': 'medium',
                'priority': 'medium',
                'priority_score': 41,
                'scoring_version': '1.0',
                'confidence': 'medium',
                'verification_status': 'likely',
                'finding_role': 'candidate',
                'validated': False,
                'validation_basis': 'heuristic-evidence',
                'kind': 'validation',
                'source_count': 1,
            }
        ],
    )
    _write_json(
        target_dir / 'reports' / 'report.summary.json',
        {
            'schema_version': '1.0',
            'scoring_version': '1.0',
            'title': 'Informe target',
            'target': 'https://target.example',
            'stats': {'total_findings': 1},
        },
    )
    _write_json(run_dir / 'reports' / 'aggregate_summary.json', {'summary': {'total_findings': 1}})
    _write_json(run_dir / 'run_manifest.json', {'targets': ['https://target.example'], 'errors': []})

    export_elasticsearch_bundle(run_dir, index_prefix='asm-id')
    output_dir = run_dir / 'elasticsearch'

    findings_lines = (output_dir / 'findings_bulk.ndjson').read_text(encoding='utf-8').splitlines()
    summaries_lines = (output_dir / 'summaries_bulk.ndjson').read_text(encoding='utf-8').splitlines()
    runs_lines = (output_dir / 'runs_bulk.ndjson').read_text(encoding='utf-8').splitlines()

    assert json.loads(findings_lines[0])['index']['_id'] == 'finding-alpha'
    assert json.loads(summaries_lines[0])['index']['_id'] == 'summary::lab_export_ids::http_example'
    assert json.loads(summaries_lines[2])['index']['_id'] == 'aggregate::lab_export_ids'
    assert json.loads(runs_lines[0])['index']['_id'] == 'run::lab_export_ids'
