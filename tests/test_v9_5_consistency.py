from attack_surface_mapper.analysis.enrichment import enrich_vulnerabilities
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.reporting.generator import ReportGenerator


def test_likely_findings_count_for_manual_validation_and_report_wording():
    v = Vulnerability(
        source="nuclei",
        title="Erlang Port Mapper Daemon",
        description="desc",
        severity="low",
        target="example.com:4369",
        category="message-broker",
        verification_status="likely",
    )
    enrich_vulnerabilities([v])
    assert v.needs_manual_validation is True
    md = ReportGenerator().generate_markdown([v], "http://example.com", "/tmp/v95_report.md")
    content = open(md, encoding="utf-8").read()
    assert "Hallazgos confirmados de aplicación" in content
    assert "No se detectaron hallazgos confirmados de aplicación" in content
    assert "Hallazgos plausibles o pendientes de validación (aplicación)" in content
