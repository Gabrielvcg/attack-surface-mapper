from attack_surface_mapper.analysis.correlation import correlate_vulnerabilities
from attack_surface_mapper.collectors.crawling.browser_discovery import BrowserDiscoveryCollector
from attack_surface_mapper.models.vulnerability import Vulnerability


def test_client_side_api_reference_group_title():
    items = [
        Vulnerability(
            source='custom-discovery-check',
            title='Client-Side API Reference Observed',
            description='d',
            severity='low',
            target='http://localhost:3000',
            matched_at='/api/one',
            category='discovery',
        ),
        Vulnerability(
            source='custom-discovery-check',
            title='Client-Side API Reference Observed',
            description='d',
            severity='low',
            target='http://localhost:3000',
            matched_at='/api/two',
            category='discovery',
        ),
    ]
    out = correlate_vulnerabilities(items)
    assert len(out) == 1
    assert out[0].title == 'Multiple Client-Side API References Observed (2)'


def test_browser_discovery_keeps_js_api_hints_out_of_observed_urls(monkeypatch):
    docs = {
        'http://localhost:3000/': '<html><body><script src="/main.js"></script></body></html>',
        'http://localhost:3000/main.js': 'fetch("/api/Users"); fetch("/rest/user/login")',
    }

    class DummyCrawler:
        def crawl(self, target):
            return docs

    collector = BrowserDiscoveryCollector(backend='requests')
    collector.crawler = DummyCrawler()
    result = collector.collect('http://localhost:3000')
    assert 'http://localhost:3000/api/Users' in result.observed_api_calls
    assert 'http://localhost:3000/rest/user/login' in result.observed_api_calls
    assert 'http://localhost:3000/api/Users' not in result.observed_urls
    assert 'http://localhost:3000/rest/user/login' not in result.observed_urls
