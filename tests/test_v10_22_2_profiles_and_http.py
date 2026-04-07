from pathlib import Path

from attack_surface_mapper.http_client import build_http_session
from attack_surface_mapper.validators.crawler import SimpleCrawler


def test_requests_session_used_for_passive_recon_safe_mode():
    session = build_http_session(backend="requests", mode="passive", timeout=3, user_agent="ua")
    try:
        assert session.__class__.__name__ == "RequestsHttpSession"
        assert getattr(session, "mode", None) == "passive"
    finally:
        session.close()


def test_new_profiles_exist():
    root = Path(__file__).resolve().parents[1]
    assert (root / "config" / "profiles" / "passive-recon-safe.yml").exists()
    assert (root / "config" / "profiles" / "passive-recon-enum.yml").exists()


def test_crawler_uses_requests_fallback_after_transport_errors(monkeypatch):
    crawler = SimpleCrawler(timeout=3, max_pages=1, max_depth=0, backend="scrapling", scrapling_mode="fetcher")

    class BoomSession:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return None
        def get(self, *args, **kwargs):
            from attack_surface_mapper.http_client import RequestError
            raise RequestError("Failed to perform, curl: (52) Empty reply from server")

    class OkResponse:
        status_code = 200
        url = "http://example.test/"
        headers = {"Content-Type": "text/html"}
        text = "<html><body>ok</body></html>"
        content = b"<html><body>ok</body></html>"

    class OkSession(BoomSession):
        def get(self, *args, **kwargs):
            return OkResponse()

    calls = {"count": 0}

    def fake_builder(**kwargs):
        calls["count"] += 1
        if kwargs.get("backend") == "requests":
            return OkSession()
        return BoomSession()

    monkeypatch.setattr("attack_surface_mapper.validators.crawler.build_http_session", fake_builder)
    docs = crawler.crawl("http://example.test")
    assert docs == {"http://example.test/": "<html><body>ok</body></html>"}
