from attack_surface_mapper.runners.nmap_runner import NmapRunner
from attack_surface_mapper.analysis.enrichment import enrich_vulnerabilities
from attack_surface_mapper.parsers.nmap_parser import NmapParser
from attack_surface_mapper.models.vulnerability import Vulnerability

SAMPLE_XML = """<?xml version='1.0'?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="4369">
        <state state="open"/>
        <service name="epmd" product="Erlang Port Mapper" version="1.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_parser_creates_vulnerabilities():
    parser = NmapParser()
    vulns = parser.to_vulnerabilities("example.com", SAMPLE_XML)
    assert len(vulns) == 2
    assert any(v.title == "Exposed Erlang Port Mapper Service" for v in vulns)
    assert any(v.category == "remote-access" for v in vulns)


def test_nmap_enrichment_keeps_reasonable_priority():
    parser = NmapParser()
    vulns = parser.to_vulnerabilities("example.com", SAMPLE_XML)
    enrich_vulnerabilities(vulns)
    epmd = next(v for v in vulns if v.title == "Exposed Erlang Port Mapper Service")
    ssh = next(v for v in vulns if v.port == "22")
    assert epmd.priority in {"low", "medium"}
    assert ssh.priority in {"low", "medium"}


def test_network_service_recommendation_exists():
    vuln = Vulnerability(
        source="nmap",
        title="Exposed Redis Service",
        description="desc",
        severity="medium",
        target="10.0.0.1:6379",
        category="database",
    )
    enrich_vulnerabilities([vuln])
    assert vuln.recommendation
    assert "base de datos" in vuln.recommendation.lower() or "restringir" in vuln.recommendation.lower()


def test_nmap_normalizes_url_target_to_hostname():
    host, port = NmapRunner.normalize_target_for_nmap("http://members-api-dev.test.dinamicarea.es")
    assert host == "members-api-dev.test.dinamicarea.es"
    assert port is None


def test_nmap_normalizes_url_target_with_port():
    host, port = NmapRunner.normalize_target_for_nmap("https://example.com:8443/path")
    assert host == "example.com"
    assert port == "8443"
