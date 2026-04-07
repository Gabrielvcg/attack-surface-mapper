from attack_surface_mapper.parsers.nmap_parser import NmapParser
from attack_surface_mapper.validators.discovery import analyse_documents, findings_from_analysis


def test_discovery_handles_unquoted_form_attributes_and_flags_auth_surface():
    documents = {
        'http://localhost:8080/login.php': (
            '<html><body>'
            '<form action=/login.php method=post>'
            '<input name=username type=text>'
            '<input type=password name=password>'
            '<input name=user_token value=abc123>'
            '</form>'
            '</body></html>'
        )
    }

    analysis = analyse_documents('http://localhost:8080', documents)
    findings = findings_from_analysis('http://localhost:8080', analysis)

    assert '/login.php' in analysis.auth_paths
    titles = {item.title for item in findings}
    assert 'Login Form Discovered Via Crawl' in titles
    assert 'Login Form Without Visible CSRF Token' not in titles


def test_nmap_parser_skips_probable_non_http_false_positive_on_http_target_port():
    xml_text = '''
    <nmaprun>
      <host>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="3000">
            <state state="open"/>
            <service name="ppp"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    '''

    vulns = NmapParser().to_vulnerabilities('http://localhost:3000', xml_text)

    assert vulns == []
