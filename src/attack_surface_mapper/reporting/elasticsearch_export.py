from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def _write_text(path: Path, content: str) -> None:
    path.write_text(content.rstrip() + '\n', encoding='utf-8')


def _keyword_text_field() -> dict[str, Any]:
    return {
        'type': 'text',
        'fields': {
            'keyword': {
                'type': 'keyword',
                'ignore_above': 1024,
            }
        },
    }


def findings_mapping() -> dict[str, Any]:
    return {
        'mappings': {
            'dynamic': False,
            'properties': {
                'document_type': {'type': 'keyword'},
                'run_name': {'type': 'keyword'},
                'exported_at': {'type': 'date'},
                'finding_id': {'type': 'keyword'},
                'correlation_id': {'type': 'keyword'},
                'source': {'type': 'keyword'},
                'title': _keyword_text_field(),
                'target': {'type': 'keyword'},
                'matched_at': {'type': 'keyword'},
                'target_host_original': {'type': 'keyword'},
                'asset_host': {'type': 'keyword'},
                'asset_host_resolved': {'type': 'keyword'},
                'asset_port': {'type': 'integer'},
                'scheme': {'type': 'keyword'},
                'category': {'type': 'keyword'},
                'severity': {'type': 'keyword'},
                'priority': {'type': 'keyword'},
                'priority_score': {'type': 'integer'},
                'scoring_version': {'type': 'keyword'},
                'confidence': {'type': 'keyword'},
                'verification_status': {'type': 'keyword'},
                'finding_role': {'type': 'keyword'},
                'validated': {'type': 'boolean'},
                'validation_basis': {'type': 'keyword'},
                'kind': {'type': 'keyword'},
                'needs_manual_validation': {'type': 'boolean'},
                'source_count': {'type': 'integer'},
                'title_family': {'type': 'keyword'},
                'recommendation': _keyword_text_field(),
                'evidence_summary': _keyword_text_field(),
                'priority_reason': _keyword_text_field(),
                'description': _keyword_text_field(),
                'cve': {'type': 'keyword'},
                'cwe': {'type': 'keyword'},
                'tags': {'type': 'keyword'},
                'references': {'type': 'keyword'},
                'related_sources': {'type': 'keyword'},
                'related_titles': {'type': 'keyword'},
                'related_targets': {'type': 'keyword'},
                'related_evidence': {'type': 'keyword'},
            },
        }
    }


def summaries_mapping() -> dict[str, Any]:
    counts_object = {
        'type': 'object',
        'dynamic': True,
    }
    return {
        'mappings': {
            'dynamic': False,
            'properties': {
                'document_type': {'type': 'keyword'},
                'run_name': {'type': 'keyword'},
                'exported_at': {'type': 'date'},
                'schema_version': {'type': 'keyword'},
                'scoring_version': {'type': 'keyword'},
                'target': {'type': 'keyword'},
                'target_slug': {'type': 'keyword'},
                'source_report': {'type': 'keyword'},
                'title': _keyword_text_field(),
                'executive_summary': _keyword_text_field(),
                'total_findings': {'type': 'integer'},
                'average_priority_score': {'type': 'float'},
                'validated_findings': {'type': 'integer'},
                'candidate_findings': {'type': 'integer'},
                'application_findings': {'type': 'integer'},
                'review_surface_findings': {'type': 'integer'},
                'hygiene_findings': {'type': 'integer'},
                'discovery_findings': {'type': 'integer'},
                'needs_manual_validation': {'type': 'integer'},
                'confirmed_high_or_critical': {'type': 'integer'},
                'priority_counts': counts_object,
                'severity_counts': counts_object,
                'category_counts': counts_object,
                'source_counts': counts_object,
                'comparison_summary': {'type': 'flattened'},
                'finding_contract': {'type': 'flattened'},
            },
        }
    }


def runs_mapping() -> dict[str, Any]:
    return {
        'mappings': {
            'dynamic': False,
            'properties': {
                'document_type': {'type': 'keyword'},
                'run_name': {'type': 'keyword'},
                'exported_at': {'type': 'date'},
                'schema_version': {'type': 'keyword'},
                'profile': {'type': 'keyword'},
                'run_dir': {'type': 'keyword'},
                'requested_targets': {'type': 'keyword'},
                'targets': {'type': 'keyword'},
                'error_count': {'type': 'integer'},
                'errors': _keyword_text_field(),
                'pipeline': {'type': 'flattened'},
                'effective_config': {'type': 'flattened'},
                'results_summary': {'type': 'flattened'},
                'aggregate_reports': {'type': 'flattened'},
            },
        }
    }


def _to_int(value: Any) -> int | None:
    if value in (None, ''):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _title_family(title: str | None) -> str:
    if not title:
        return 'unknown'
    lowered = title.lower()
    if lowered.startswith('multiple api endpoints exposed'):
        return 'multiple-api-endpoints-exposed'
    if lowered.startswith('protected api surface discovered'):
        return 'protected-api-surface-discovered'
    if lowered.startswith('multiple client-side api references observed'):
        return 'multiple-client-side-api-references-observed'
    if lowered.startswith('technology fingerprint detected'):
        return 'technology-fingerprint-detected'
    return lowered


def _build_finding_document(item: dict[str, Any], *, run_name: str, exported_at: str) -> dict[str, Any]:
    return {
        'document_type': 'finding',
        'run_name': run_name,
        'exported_at': exported_at,
        'finding_id': item.get('finding_id'),
        'correlation_id': item.get('correlation_id'),
        'source': item.get('source'),
        'title': item.get('title'),
        'title_family': _title_family(item.get('title')),
        'target': item.get('target'),
        'matched_at': item.get('matched_at'),
        'target_host_original': item.get('target_host_original'),
        'asset_host': item.get('asset_host'),
        'asset_host_resolved': item.get('asset_host_resolved'),
        'asset_port': _to_int(item.get('asset_port')),
        'scheme': item.get('scheme'),
        'category': item.get('category'),
        'severity': item.get('severity'),
        'priority': item.get('priority'),
        'priority_score': _to_int(item.get('priority_score')),
        'scoring_version': item.get('scoring_version'),
        'confidence': item.get('confidence'),
        'verification_status': item.get('verification_status'),
        'finding_role': item.get('finding_role'),
        'validated': bool(item.get('validated')),
        'validation_basis': item.get('validation_basis'),
        'kind': item.get('kind'),
        'needs_manual_validation': bool(item.get('needs_manual_validation')),
        'source_count': _to_int(item.get('source_count')) or 0,
        'recommendation': item.get('recommendation'),
        'evidence_summary': item.get('evidence_summary'),
        'priority_reason': item.get('priority_reason'),
        'description': item.get('description'),
        'cve': item.get('cve') or [],
        'cwe': item.get('cwe') or [],
        'tags': item.get('tags') or [],
        'references': item.get('references') or [],
        'related_sources': item.get('related_sources') or [],
        'related_titles': item.get('related_titles') or [],
        'related_targets': item.get('related_targets') or [],
        'related_evidence': item.get('related_evidence') or [],
    }


def _build_target_summary_document(
    payload: dict[str, Any],
    *,
    run_name: str,
    target_slug: str,
    source_report: str,
    exported_at: str,
) -> dict[str, Any]:
    stats = payload.get('stats') or {}
    return {
        'document_type': 'target_summary',
        'run_name': run_name,
        'exported_at': exported_at,
        'schema_version': payload.get('schema_version'),
        'scoring_version': payload.get('scoring_version'),
        'target': payload.get('target'),
        'target_slug': target_slug,
        'source_report': source_report,
        'title': payload.get('title'),
        'executive_summary': payload.get('executive_summary'),
        'total_findings': _to_int(stats.get('total_findings')) or 0,
        'average_priority_score': stats.get('average_priority_score'),
        'validated_findings': _to_int(stats.get('validated_findings')) or 0,
        'candidate_findings': _to_int(stats.get('candidate_findings')) or 0,
        'application_findings': _to_int(stats.get('application_findings')) or 0,
        'review_surface_findings': _to_int(stats.get('review_surface_findings')) or 0,
        'hygiene_findings': _to_int(stats.get('hygiene_findings')) or 0,
        'discovery_findings': _to_int(stats.get('discovery_findings')) or 0,
        'needs_manual_validation': _to_int(stats.get('needs_manual_validation')) or 0,
        'confirmed_high_or_critical': _to_int(stats.get('confirmed_high_or_critical')) or 0,
        'priority_counts': stats.get('priority_counts') or {},
        'severity_counts': stats.get('severity_counts') or {},
        'category_counts': stats.get('category_counts') or {},
        'source_counts': stats.get('source_counts') or {},
        'comparison_summary': payload.get('comparison_summary') or {},
        'finding_contract': payload.get('finding_contract') or {},
    }


def _build_aggregate_summary_document(
    payload: dict[str, Any],
    *,
    run_name: str,
    source_report: str,
    exported_at: str,
) -> dict[str, Any]:
    summary = payload.get('summary') or {}
    return {
        'document_type': 'aggregate_summary',
        'run_name': run_name,
        'exported_at': exported_at,
        'schema_version': payload.get('schema_version'),
        'scoring_version': payload.get('scoring_version'),
        'target': None,
        'target_slug': None,
        'source_report': source_report,
        'title': 'Resumen agregado del run',
        'executive_summary': None,
        'total_findings': _to_int(summary.get('total_findings')) or 0,
        'average_priority_score': summary.get('average_priority_score'),
        'validated_findings': _to_int(summary.get('validated_findings')) or 0,
        'candidate_findings': _to_int(summary.get('candidate_findings')) or 0,
        'application_findings': _to_int(summary.get('actionable_risk_findings')) or 0,
        'review_surface_findings': _to_int(summary.get('review_surface_findings')) or 0,
        'hygiene_findings': _to_int(summary.get('hygiene_findings')) or 0,
        'discovery_findings': _to_int(summary.get('discovery_findings')) or 0,
        'needs_manual_validation': 0,
        'confirmed_high_or_critical': 0,
        'priority_counts': summary.get('priority_counts') or {},
        'severity_counts': summary.get('severity_counts') or {},
        'category_counts': summary.get('category_counts') or {},
        'source_counts': {},
        'comparison_summary': {},
        'finding_contract': payload.get('finding_contract') or {},
    }


def _build_run_document(payload: dict[str, Any], *, run_name: str, exported_at: str) -> dict[str, Any]:
    errors = payload.get('errors') or []
    return {
        'document_type': 'run_manifest',
        'run_name': run_name,
        'exported_at': exported_at,
        'schema_version': payload.get('schema_version'),
        'profile': payload.get('profile'),
        'run_dir': payload.get('run_dir'),
        'requested_targets': payload.get('requested_targets') or [],
        'targets': payload.get('targets') or [],
        'error_count': len(errors),
        'errors': [str(item) for item in errors],
        'pipeline': payload.get('pipeline') or {},
        'effective_config': payload.get('effective_config') or {},
        'results_summary': payload.get('results_summary') or {},
        'aggregate_reports': payload.get('aggregate_reports') or {},
    }


def _bundle_manifest(
    *,
    run_name: str,
    run_dir: Path,
    output_dir: Path,
    index_prefix: str,
    exported_at: str,
    findings_count: int,
    summaries_count: int,
    runs_count: int,
    warnings: list[str],
) -> dict[str, Any]:
    return {
        'run_name': run_name,
        'run_dir': str(run_dir),
        'output_dir': str(output_dir),
        'index_prefix': index_prefix,
        'exported_at': exported_at,
        'documents': {
            'findings': findings_count,
            'summaries': summaries_count,
            'runs': runs_count,
        },
        'indices': {
            'findings': f'{index_prefix}-findings',
            'summaries': f'{index_prefix}-summaries',
            'runs': f'{index_prefix}-runs',
        },
        'artifacts': {
            'findings_mapping': 'findings_mapping.json',
            'summaries_mapping': 'summaries_mapping.json',
            'runs_mapping': 'runs_mapping.json',
            'findings_bulk': 'findings_bulk.ndjson',
            'summaries_bulk': 'summaries_bulk.ndjson',
            'runs_bulk': 'runs_bulk.ndjson',
            'manual_helper': 'manual_kibana_devtools.md',
            'curl_helper': 'ingest_with_curl.sh',
            'python_helper': 'ingest_with_python.py',
        },
        'warnings': warnings,
    }


def _write_bulk(
    path: Path,
    *,
    index_name: str,
    documents: list[dict[str, Any]],
    id_getter,
) -> None:
    lines: list[str] = []
    for document in documents:
        doc_id = str(id_getter(document) or '')
        lines.append(json.dumps({'index': {'_index': index_name, '_id': doc_id}}, ensure_ascii=False))
        lines.append(json.dumps(document, ensure_ascii=False))
    path.write_text('\n'.join(lines).rstrip() + '\n', encoding='utf-8')


def _write_manual_kibana(
    output_path: Path,
    *,
    output_dir: Path,
    run_name: str,
    index_prefix: str,
) -> None:
    lines = [
        '# Ingesta manual en Kibana Dev Tools',
        '',
        f'Run exportado: `{run_name}`',
        f'Bundle local: `{output_dir}`',
        '',
        '## 1. Crear índices con el mapping exportado',
        '',
        'Abre los archivos de mapping del bundle y pega su contenido en Dev Tools:',
        '',
        f'- `PUT /{index_prefix}-findings` con el contenido de `findings_mapping.json`',
        f'- `PUT /{index_prefix}-summaries` con el contenido de `summaries_mapping.json`',
        f'- `PUT /{index_prefix}-runs` con el contenido de `runs_mapping.json`',
        '',
        '## 2. Cargar los NDJSON',
        '',
        'En Dev Tools no se puede referenciar directamente un archivo local, así que abre cada `*_bulk.ndjson`',
        'y pega su contenido completo en una petición `_bulk` separada:',
        '',
        f'- `POST /{index_prefix}-findings/_bulk` con `findings_bulk.ndjson`',
        f'- `POST /{index_prefix}-summaries/_bulk` con `summaries_bulk.ndjson`',
        f'- `POST /{index_prefix}-runs/_bulk` con `runs_bulk.ndjson`',
        '',
        '## 3. Verificación rápida',
        '',
        '```http',
        f'GET /{index_prefix}-findings/_count',
        '',
        f'GET /{index_prefix}-summaries/_search?q=document_type:aggregate_summary',
        '',
        f'GET /{index_prefix}-findings/_search',
        '{',
        '  "size": 5,',
        '  "query": {',
        '    "term": {',
        '      "finding_role": "validated"',
        '    }',
        '  },',
        '  "sort": [',
        '    { "priority_score": "desc" }',
        '  ]',
        '}',
        '```',
    ]
    _write_text(output_path, '\n'.join(lines))


def _write_curl_helper(
    output_path: Path,
    *,
    index_prefix: str,
) -> None:
    content = f"""#!/usr/bin/env sh
set -eu

ES_URL="${{ES_URL:-http://localhost:9200}}"

curl -sS -X PUT "$ES_URL/{index_prefix}-findings" -H 'Content-Type: application/json' --data-binary @findings_mapping.json
curl -sS -X PUT "$ES_URL/{index_prefix}-summaries" -H 'Content-Type: application/json' --data-binary @summaries_mapping.json
curl -sS -X PUT "$ES_URL/{index_prefix}-runs" -H 'Content-Type: application/json' --data-binary @runs_mapping.json

curl -sS -X POST "$ES_URL/{index_prefix}-findings/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @findings_bulk.ndjson
curl -sS -X POST "$ES_URL/{index_prefix}-summaries/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @summaries_bulk.ndjson
curl -sS -X POST "$ES_URL/{index_prefix}-runs/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @runs_bulk.ndjson

curl -sS "$ES_URL/{index_prefix}-findings/_count"
curl -sS "$ES_URL/{index_prefix}-findings/_search?q=finding_role:validated&sort=priority_score:desc&size=5"
"""
    _write_text(output_path, content)


def _write_python_helper(
    output_path: Path,
    *,
    index_prefix: str,
) -> None:
    content = f"""from __future__ import annotations

import json
from pathlib import Path

import requests


ES_URL = 'http://localhost:9200'
BASE_DIR = Path(__file__).resolve().parent


def put_json(index_name: str, filename: str) -> None:
    payload = json.loads((BASE_DIR / filename).read_text(encoding='utf-8'))
    response = requests.put(
        f'{{ES_URL}}/{{index_name}}',
        headers={{'Content-Type': 'application/json'}},
        json=payload,
        timeout=30,
    )
    response.raise_for_status()


def post_bulk(index_name: str, filename: str) -> None:
    payload = (BASE_DIR / filename).read_text(encoding='utf-8')
    response = requests.post(
        f'{{ES_URL}}/{{index_name}}/_bulk',
        headers={{'Content-Type': 'application/x-ndjson'}},
        data=payload.encode('utf-8'),
        timeout=60,
    )
    response.raise_for_status()


put_json('{index_prefix}-findings', 'findings_mapping.json')
put_json('{index_prefix}-summaries', 'summaries_mapping.json')
put_json('{index_prefix}-runs', 'runs_mapping.json')

post_bulk('{index_prefix}-findings', 'findings_bulk.ndjson')
post_bulk('{index_prefix}-summaries', 'summaries_bulk.ndjson')
post_bulk('{index_prefix}-runs', 'runs_bulk.ndjson')

response = requests.get(
    f'{{ES_URL}}/{index_prefix}-findings/_search',
    params={{'q': 'finding_role:validated', 'sort': 'priority_score:desc', 'size': 5}},
    timeout=30,
)
response.raise_for_status()
print(response.text)
"""
    _write_text(output_path, content)


def export_elasticsearch_bundle(run_dir: str | Path, *, index_prefix: str = 'attack-surface-mapper') -> dict[str, Any]:
    run_path = Path(run_dir)
    if not run_path.exists() or not run_path.is_dir():
        raise FileNotFoundError(f'No existe el directorio de run: {run_path}')
    output_dir = run_path / 'elasticsearch'
    output_dir.mkdir(parents=True, exist_ok=True)

    run_name = run_path.name
    exported_at = _utc_timestamp()
    warnings: list[str] = []

    findings_docs: list[dict[str, Any]] = []
    for findings_path in sorted(run_path.glob('targets/*/findings/vulnerabilities.json')):
        for item in _load_json(findings_path):
            findings_docs.append(_build_finding_document(item, run_name=run_name, exported_at=exported_at))
    if not findings_docs:
        warnings.append('No se encontraron findings en targets/*/findings/vulnerabilities.json')

    summaries_docs: list[dict[str, Any]] = []
    for summary_path in sorted(run_path.glob('targets/*/reports/report.summary.json')):
        payload = _load_json(summary_path)
        target_slug = summary_path.parents[1].name
        summaries_docs.append(_build_target_summary_document(
            payload,
            run_name=run_name,
            target_slug=target_slug,
            source_report=str(summary_path),
            exported_at=exported_at,
        ))
    aggregate_summary_path = run_path / 'reports' / 'aggregate_summary.json'
    if aggregate_summary_path.exists():
        summaries_docs.append(_build_aggregate_summary_document(
            _load_json(aggregate_summary_path),
            run_name=run_name,
            source_report=str(aggregate_summary_path),
            exported_at=exported_at,
        ))
    else:
        warnings.append('No se encontró reports/aggregate_summary.json')
    if not summaries_docs:
        warnings.append('No se encontraron summaries exportables')

    run_docs: list[dict[str, Any]] = []
    run_manifest_path = run_path / 'run_manifest.json'
    if run_manifest_path.exists():
        run_docs.append(_build_run_document(_load_json(run_manifest_path), run_name=run_name, exported_at=exported_at))
    else:
        warnings.append('No se encontró run_manifest.json')

    _write_json(output_dir / 'findings_mapping.json', findings_mapping())
    _write_json(output_dir / 'summaries_mapping.json', summaries_mapping())
    _write_json(output_dir / 'runs_mapping.json', runs_mapping())

    _write_bulk(
        output_dir / 'findings_bulk.ndjson',
        index_name=f'{index_prefix}-findings',
        documents=findings_docs,
        id_getter=lambda document: document.get('finding_id'),
    )
    _write_bulk(
        output_dir / 'summaries_bulk.ndjson',
        index_name=f'{index_prefix}-summaries',
        documents=summaries_docs,
        id_getter=lambda document: (
            f'aggregate::{run_name}'
            if document.get('document_type') == 'aggregate_summary'
            else f"summary::{run_name}::{document.get('target_slug')}"
        ),
    )
    _write_bulk(
        output_dir / 'runs_bulk.ndjson',
        index_name=f'{index_prefix}-runs',
        documents=run_docs,
        id_getter=lambda _document: f'run::{run_name}',
    )

    _write_manual_kibana(output_dir / 'manual_kibana_devtools.md', output_dir=output_dir, run_name=run_name, index_prefix=index_prefix)
    _write_curl_helper(output_dir / 'ingest_with_curl.sh', index_prefix=index_prefix)
    _write_python_helper(output_dir / 'ingest_with_python.py', index_prefix=index_prefix)

    bundle_manifest = _bundle_manifest(
        run_name=run_name,
        run_dir=run_path,
        output_dir=output_dir,
        index_prefix=index_prefix,
        exported_at=exported_at,
        findings_count=len(findings_docs),
        summaries_count=len(summaries_docs),
        runs_count=len(run_docs),
        warnings=warnings,
    )
    _write_json(output_dir / 'export_manifest.json', bundle_manifest)
    return bundle_manifest
