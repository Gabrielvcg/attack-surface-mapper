from __future__ import annotations

import json
import re
from typing import Any

from attack_surface_mapper.models.vulnerability import Vulnerability


class NucleiParser:
    @staticmethod
    def parse_jsonl(raw_stdout: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return findings

    @staticmethod
    def build_compact_raw(item: dict[str, Any]) -> dict[str, Any]:
        response = item.get('response')
        compact_response = None
        if isinstance(response, str):
            compact_response = re.sub(r'([A-Za-z0-9_\-]{16,})', '[redacted]', response[:400])
            if len(response) > 400:
                compact_response += '...[truncated]'
        return {
            'template-id': item.get('template-id'),
            'matched-at': item.get('matched-at'),
            'host': item.get('host'),
            'port': item.get('port'),
            'scheme': item.get('scheme'),
            'url': item.get('url'),
            'curl-command': item.get('curl-command'),
            'response_preview': compact_response,
        }

    @staticmethod
    def infer_category(tags: list[str], template_id: str | None, matched_at: str | None) -> str | None:
        lowered = {tag.lower() for tag in tags}
        joined = ' '.join(sorted(lowered)) + ' ' + (template_id or '').lower() + ' ' + (matched_at or '').lower()
        if any(token in joined for token in ('header', 'csp', 'hsts', 'x-frame-options')):
            return 'headers'
        if any(token in joined for token in ('tls', 'ssl', 'certificate')):
            return 'tls'
        if any(token in joined for token in ('epmd', 'erlang', 'rabbit')):
            return 'message-broker'
        if any(token in joined for token in ('swagger', 'graphql', 'openapi', 'api')):
            return 'api'
        if any(token in joined for token in ('prometheus', '/metrics', 'exposure', 'exposed-panel')):
            return 'panel-exposure'
        if 'secret' in joined:
            return 'secret'
        if 'misconfig' in joined or 'config' in joined:
            return 'misconfiguration'
        if 'exposure' in joined:
            return 'exposure'
        return None

    @staticmethod
    def to_vulnerabilities(raw_findings: list[dict[str, Any]], *, include_raw: bool = False) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []
        for item in raw_findings:
            info = item.get('info', {}) or {}
            classification = info.get('classification', {}) or {}
            cve = classification.get('cve-id') or []
            cwe = classification.get('cwe-id') or []
            references = info.get('reference') or []
            tags = info.get('tags') or []
            if isinstance(cve, str):
                cve = [cve]
            if isinstance(cwe, str):
                cwe = [cwe]
            if isinstance(references, str):
                references = [references]
            if isinstance(tags, str):
                tags = [tags]
            target = item.get('matched-at') or item.get('host') or item.get('url') or ''
            evidence = item.get('extracted-results', None) and ' | '.join(item.get('extracted-results', [])) or item.get('matcher-name') or item.get('curl-command') or None
            vulnerabilities.append(
                Vulnerability(
                    source='nuclei',
                    title=info.get('name', 'Unknown finding'),
                    description=info.get('description', ''),
                    severity=info.get('severity', 'unknown'),
                    target=target,
                    evidence=evidence,
                    cve=cve,
                    cwe=cwe,
                    cvss_score=classification.get('cvss-score'),
                    references=references,
                    tags=tags,
                    template_id=item.get('template-id'),
                    matcher_name=item.get('matcher-name'),
                    matched_at=item.get('matched-at'),
                    host=item.get('host'),
                    port=item.get('port'),
                    scheme=item.get('scheme'),
                    type=item.get('type'),
                    category=NucleiParser.infer_category(tags, item.get('template-id'), item.get('matched-at')),
                    raw=NucleiParser.build_compact_raw(item) if include_raw else {},
                )
            )
        return vulnerabilities
