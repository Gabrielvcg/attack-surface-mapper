from __future__ import annotations

from attack_surface_mapper.validators.crawler import SimpleCrawler


class CrawlerCollector(SimpleCrawler):
    """Compatibility wrapper exposing the crawler as a collector/provider."""
