from attack_surface_mapper.http_client import RequestError, get_debug_trace, reset_debug_trace, set_debug_trace_enabled
from attack_surface_mapper.validators.crawler import SimpleCrawler
from attack_surface_mapper.validators.discovery import analyse_documents, findings_from_analysis


class _Response:
    def __init__(self, url: str, body: str, content_type: str = 'text/html; charset=utf-8'):
        self.status_code = 200
        self.url = url
        self.headers = {'Content-Type': content_type}
        self.text = body
        self.content = body.encode('utf-8')


class FailingSession:
    def get(self, url, timeout=None, allow_redirects=True):
        raise RequestError('curl: (52) Empty reply from server')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None


class RequestsSession:
    def get(self, url, timeout=None, allow_redirects=True):
        return _Response(
            'http://localhost:3000/login.php',
            '<!DOCTYPE html><html><body><form action="/login.php" method="post">'
            '<input name="username"><input type="password" name="password"></form></body></html>',
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None


def test_crawler_falls_back_to_requests_when_scrapling_transport_fails(monkeypatch):
    def fake_build_http_session(**kwargs):
        backend = kwargs.get('backend')
        if backend == 'requests':
            return RequestsSession()
        return FailingSession()

    monkeypatch.setattr('attack_surface_mapper.validators.crawler.build_http_session', fake_build_http_session)
    set_debug_trace_enabled(True)
    reset_debug_trace()

    crawler = SimpleCrawler(timeout=6, max_pages=3, max_depth=0, backend='scrapling', scrapling_mode='fetcher')
    documents = crawler.crawl('http://localhost:3000')

    assert 'http://localhost:3000/login.php' in documents
    assert any(event.get('event') == 'fallback_to_requests' for event in get_debug_trace())


def test_discovery_analysis_extracts_forms_and_api_hints():
    documents = {
        'http://localhost:8080/login.php': (
            '<html><body>'
            '<form action="/login.php" method="post">'
            '<input name="username">'
            '<input type="password" name="password">'
            '</form>'
            '<script>fetch("/api/users");</script>'
            '</body></html>'
        )
    }

    analysis = analyse_documents('http://localhost:8080', documents)
    findings = findings_from_analysis('http://localhost:8080', analysis)

    assert '/login.php' in analysis.auth_paths
    assert '/api/users' in analysis.api_paths
    titles = {item.title for item in findings}
    assert 'Login Form Discovered Via Crawl' in titles
    assert 'Login Form Without Visible CSRF Token' in titles
    assert 'Client-Side API Reference Observed' in titles
