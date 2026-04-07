from attack_surface_mapper.analysis.enrichment import enrich_vulnerabilities
from attack_surface_mapper.batch.aggregate import build_aggregate_payload, write_aggregate_reports
from attack_surface_mapper.models.vulnerability import Vulnerability
from attack_surface_mapper.reporting.generator import ReportGenerator
from attack_surface_mapper.reporting.generator import ReportPaths
from attack_surface_mapper.orchestrator import ScanResult


def test_discovery_priority_downgraded_to_low():
    vuln = Vulnerability(
        source="custom-auth-check",
        title="Protected Management Endpoint Discovered",
        description="desc",
        severity="low",
        target="http://example.com/management",
        matched_at="http://example.com/management",
        category="discovery",
        confidence="medium",
        verification_status="confirmed",
    )
    enrich_vulnerabilities([vuln])
    assert vuln.priority == "low"


def test_aggregate_uses_location_and_separates_discovery(tmp_path):
    vuln = Vulnerability(
        source="custom-auth-check",
        title="Protected API Documentation Discovered",
        description="desc",
        severity="low",
        target="http://example.com/api-docs",
        matched_at="http://example.com/api-docs",
        category="discovery",
        confidence="medium",
        verification_status="confirmed",
        priority="low",
    )
    result = ScanResult(target="http://example.com", vulnerabilities=[vuln], command=[], return_code=0, stdout="", stderr="", raw_findings_count=0, output_json_path=None, raw_output_path=None, summary={"low": 1}, report_paths=ReportPaths())
    payload = build_aggregate_payload([result])
    assert payload["top_findings"][0]["location"] == "http://example.com/api-docs"
    paths = write_aggregate_reports([result], str(tmp_path))
    md = open(paths["markdown"], encoding="utf-8").read()
    assert "Superficie descubierta o protegida" in md
    assert "http://example.com/api-docs" in md


def test_target_report_has_discovery_section(tmp_path):
    vuln = Vulnerability(
        source="custom-auth-check",
        title="Protected Management Endpoint Discovered",
        description="desc",
        severity="low",
        target="http://example.com/management",
        matched_at="http://example.com/management",
        category="discovery",
        confidence="medium",
        verification_status="confirmed",
        priority="low",
    )
    generator = ReportGenerator()
    path = generator.generate_markdown([vuln], "http://example.com", str(tmp_path / "report.md"))
    md = open(path, encoding="utf-8").read()
    assert "## Superficie descubierta o protegida" in md
    assert "Protected Management Endpoint Discovered" in md
