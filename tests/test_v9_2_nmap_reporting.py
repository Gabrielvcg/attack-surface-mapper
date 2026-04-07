from attack_surface_mapper.parsers.nmap_parser import NmapParser
from attack_surface_mapper.reporting.generator import ReportGenerator


NMAP_XML = """<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.22.1"/></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MariaDB" version="10.11"/></port>
</ports></host></nmaprun>"""


def test_nmap_priorities_distinguish_standard_web_and_database():
    vulns = NmapParser().to_vulnerabilities('example.com', NMAP_XML)
    web = next(v for v in vulns if v.port == '80')
    db = next(v for v in vulns if v.port == '3306')
    assert web.priority == 'low'
    assert web.category == 'web-service'
    assert db.priority == 'high'
    assert db.category == 'database'


def test_reporting_has_network_services_section(tmp_path):
    vulns = NmapParser().to_vulnerabilities('example.com', NMAP_XML)
    path = tmp_path / 'report.md'
    ReportGenerator().generate_markdown(vulns, 'example.com', str(path))
    content = path.read_text()
    assert '## Servicios y puertos descubiertos' in content
