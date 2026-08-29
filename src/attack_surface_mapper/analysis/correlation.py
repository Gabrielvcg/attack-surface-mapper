from __future__ import annotations

from collections import defaultdict

from attack_surface_mapper.analysis.enrichment import enrich_vulnerabilities
from attack_surface_mapper.models.vulnerability import Vulnerability

SEVERITY_SCORE = {
    'info': 1,
    'low': 2,
    'medium': 3,
    'high': 4,
    'critical': 5,
    'unknown': 0,
}
CONFIDENCE_SCORE = {
    'low': 1,
    'medium': 2,
    'high': 3,
}
VERIFICATION_SCORE = {
    'discarded': 0,
    'heuristic': 1,
    'needs_manual_validation': 2,
    'likely': 3,
    'confirmed': 4,
}


def _pick_primary(vulnerabilities: list[Vulnerability]) -> Vulnerability:
    return max(
        vulnerabilities,
        key=lambda v: (
            VERIFICATION_SCORE.get((v.verification_status or '').lower(), 0),
            CONFIDENCE_SCORE.get((v.confidence or '').lower(), 0),
            SEVERITY_SCORE.get((v.severity or 'unknown').lower(), 0),
            1 if v.source == 'nuclei' else 0,
            len(v.evidence or ''),
        ),
    )




def _customise_merged(primary: Vulnerability, merged: Vulnerability, items: list[Vulnerability]) -> None:
    locations = sorted({item.matched_at or item.target for item in items if (item.matched_at or item.target)})
    sample_locations = ', '.join(filter(None, locations[:5]))
    if primary.title == 'API Surface Exposed':
        merged.title = f'Multiple API Endpoints Exposed ({len(items)})'
        merged.description = 'Se han detectado múltiples endpoints de API expuestos que amplían la superficie accesible del servicio.'
        merged.category = 'api'
        merged.matched_at = primary.target
        merged.target = primary.target
        merged.evidence_summary = f'Endpoints expuestos: {sample_locations}'
        merged.evidence = merged.evidence_summary
    elif primary.title.startswith('Protected API Surface Discovered'):
        merged.title = f'Protected API Surface Discovered ({len(items)} endpoints)'
        merged.description = 'Se han identificado múltiples endpoints de API protegidos; son útiles para inventario y validación posterior de control de acceso.'
        merged.category = 'discovery'
        merged.matched_at = primary.target
        merged.target = primary.target
        merged.evidence_summary = f'Endpoints protegidos: {sample_locations}'
        merged.evidence = merged.evidence_summary
    elif primary.title == 'Client-Side API Reference Observed':
        merged.title = f'Multiple Client-Side API References Observed ({len(items)})'
        merged.description = 'El contenido cliente revela múltiples referencias a API útiles para inventario pasivo y priorización de superficie.'
        merged.category = 'discovery'
        merged.matched_at = primary.target
        merged.target = primary.target
        merged.evidence_summary = f'Referencias cliente observadas: {sample_locations}'
        merged.evidence = merged.evidence_summary

def correlate_vulnerabilities(vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
    buckets: dict[tuple[str, str, str], list[Vulnerability]] = defaultdict(list)
    for vulnerability in vulnerabilities:
        buckets[vulnerability.correlation_key()].append(vulnerability)

    correlated: list[Vulnerability] = []
    for items in buckets.values():
        if len(items) == 1:
            correlated.append(items[0])
            continue

        primary = _pick_primary(items)
        merged = Vulnerability(**primary.to_dict())
        merged.source_count = len(items)
        merged.related_sources = sorted({item.source for item in items})
        merged.related_titles = sorted({item.title for item in items if item.title != primary.title})
        merged.related_targets = sorted({item.target for item in items if item.target != primary.target})
        merged.related_evidence = [item.evidence_summary or item.evidence or '' for item in items if (item.evidence_summary or item.evidence)]
        merged.references = sorted({ref for item in items for ref in item.references})
        merged.cve = sorted({cve for item in items for cve in item.cve})
        merged.cwe = sorted({cwe for item in items for cwe in item.cwe})
        merged.tags = sorted({tag for item in items for tag in item.tags})
        merged.description = primary.description or 'Hallazgo correlacionado desde múltiples fuentes de detección.'
        merged.evidence_summary = '; '.join(filter(None, merged.related_evidence[:3])) or primary.evidence_summary
        merged.evidence = merged.evidence_summary
        merged.raw = {'correlated_from': [item.source for item in items]}
        _customise_merged(primary, merged, items)
        correlated.append(merged)

    return enrich_vulnerabilities(correlated)
