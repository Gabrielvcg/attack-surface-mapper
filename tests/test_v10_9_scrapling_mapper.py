from attack_surface_mapper.http_client import ScraplingHttpSession
from attack_surface_mapper.validators.crawler import SimpleCrawler


class FakeScraplingResponse:
    def __init__(self):
        self.status = 200
        self.url = 'http://localhost:8080/login.php'
        self.headers = {'content-type': 'text/html;charset=utf-8'}
        self.body = b'<!DOCTYPE html><html><body><a href="/admin.php">Admin</a></body></html>'
        self.encoding = 'utf-8'


class FakeScraplingResponseIso:
    def __init__(self):
        self.status = 200
        self.url = 'http://localhost:8080/login.php'
        self.headers = {'content-type': 'text/html; charset=iso-8859-1'}
        self.body = 'ol\xe1 login'.encode('iso-8859-1')
        self.encoding = None


class FakeSession:
    def __init__(self, response):
        self.response = response

    def get(self, url, timeout=None, allow_redirects=True):
        return ScraplingHttpSession._page_to_response(self.response, url)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None


def test_scrapling_mapper_uses_documented_body_and_headers():
    response = ScraplingHttpSession._page_to_response(FakeScraplingResponse(), 'http://localhost:8080')

    assert response.status_code == 200
    assert response.url == 'http://localhost:8080/login.php'
    assert response.headers['Content-Type'] == 'text/html;charset=utf-8'
    assert response.text.startswith('<!DOCTYPE html>')
    assert b'<html>' in response.content


def test_scrapling_mapper_infers_charset_from_content_type_when_needed():
    response = ScraplingHttpSession._page_to_response(FakeScraplingResponseIso(), 'http://localhost:8080')

    assert response.headers['Content-Type'] == 'text/html; charset=iso-8859-1'
    assert response.text == 'olá login'


def test_crawler_stores_html_when_scrapling_response_uses_lowercase_content_type(monkeypatch):
    fake_response = FakeScraplingResponse()

    def fake_build_http_session(**kwargs):
        return FakeSession(fake_response)

    monkeypatch.setattr('attack_surface_mapper.validators.crawler.build_http_session', fake_build_http_session)

    crawler = SimpleCrawler(timeout=6, max_pages=5, max_depth=1, backend='scrapling', mode='passive', scrapling_mode='fetcher')
    documents = crawler.crawl('http://localhost:8080')

    assert 'http://localhost:8080/login.php' in documents
    assert '/admin.php' in documents['http://localhost:8080/login.php']
