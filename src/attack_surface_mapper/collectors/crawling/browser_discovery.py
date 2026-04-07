
from __future__ import annotations

from dataclasses import dataclass, field
import re
from html import unescape
from urllib.parse import urljoin, urlparse

from attack_surface_mapper.collectors.crawling.collector import CrawlerCollector
from attack_surface_mapper.http_client import HttpResponse
from attack_surface_mapper.validators.discovery import analyse_documents

BUTTON_RE = re.compile(r"<button\b(?P<attrs>[^>]*)>(?P<body>.*?)</button>", re.IGNORECASE | re.DOTALL)
ANCHOR_RE = re.compile(r"<a\b(?P<attrs>[^>]*)>(?P<body>.*?)</a>", re.IGNORECASE | re.DOTALL)
ATTR_RE = re.compile(r'''([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?''', re.DOTALL)
FETCH_HINT_RE = re.compile(r'''(?:(?:fetch|axios\.(?:get|post|put|delete)|XMLHttpRequest)\s*\(?\s*["\'])(/[^"\']+)''', re.IGNORECASE)

@dataclass(slots=True)
class BrowserDiscoveryResult:
    documents: dict[str, str] = field(default_factory=dict)
    observed_urls: list[str] = field(default_factory=list)
    observed_actions: list[dict] = field(default_factory=list)
    observed_api_calls: list[str] = field(default_factory=list)
    analysis: object | None = None
    entry_response: HttpResponse | None = None

def _parse_attrs(raw: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for key, dbl, sgl, bare in ATTR_RE.findall(raw or ''):
        attrs[key.lower()] = unescape((dbl or sgl or bare or '').strip())
    return attrs

def _same_host(candidate: str, page_url: str, target: str) -> str | None:
    if not candidate:
        return None
    absolute = urljoin(page_url, candidate)
    c = urlparse(absolute)
    t = urlparse(target)
    if c.scheme in {'http', 'https'} and c.netloc == t.netloc:
        return absolute
    return None



def _is_api_like(url: str) -> bool:
    path = (urlparse(url).path or '').lower()
    return any(token in path for token in ('/api/', '/rest/', '/graphql', 'swagger', 'openapi', 'api-docs', '/metrics'))


def _looks_like_spa(documents: dict[str, str], analysis) -> bool:
    if any('/rest/' in hint or '/api/' in hint for hint in getattr(analysis, 'js_hints', []) or []):
        return True
    for body in documents.values():
        lower = (body or '').lower()
        if 'ng-version' in lower or 'webpack' in lower or '<app-root' in lower or 'router-outlet' in lower:
            return True
    return False

class BrowserDiscoveryCollector:
    def __init__(self, *, timeout: int = 8, max_pages: int = 20, max_depth: int = 2, include_js: bool = True, user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36', backend: str = 'auto', mode: str = 'passive', scrapling_mode: str = 'auto', click_budget: int = 12) -> None:
        self.crawler = CrawlerCollector(timeout=timeout, max_pages=max_pages, max_depth=max_depth, include_js=include_js, user_agent=user_agent, backend=backend, mode=mode, scrapling_mode=scrapling_mode)
        self.click_budget = max(0, click_budget)

    def collect(self, target: str) -> BrowserDiscoveryResult:
        documents = self.crawler.crawl(target)
        analysis = analyse_documents(target, documents) if documents else analyse_documents(target, {})
        discovered = list(dict.fromkeys(analysis.discovered_urls))
        observed_urls = [u for u in discovered if not _is_api_like(u)]
        observed_actions: list[dict] = []
        observed_api_calls: list[str] = []
        is_spa = _looks_like_spa(documents, analysis)

        for hint in getattr(analysis, 'js_hints', []) or []:
            absolute = _same_host(hint, target, target)
            if not absolute:
                continue
            if _is_api_like(absolute):
                observed_api_calls.append(absolute)

        for page_url, html in documents.items():
            for match in ANCHOR_RE.finditer(html or ''):
                attrs = _parse_attrs(match.group('attrs'))
                href = _same_host(attrs.get('href', ''), page_url, target)
                text = re.sub(r'<[^>]+>', ' ', match.group('body') or '').strip()
                if href and len(observed_actions) < self.click_budget:
                    if (not is_spa) or any(token in href for token in ('/api/', '/rest/', '/graphql', '/login', '/admin', '/dashboard')):
                        observed_actions.append({'type': 'anchor', 'page_url': page_url, 'target_url': href, 'text': text[:120]})

            for match in BUTTON_RE.finditer(html or ''):
                attrs = _parse_attrs(match.group('attrs'))
                text = re.sub(r'<[^>]+>', ' ', match.group('body') or '').strip()
                target_url = _same_host(attrs.get('formaction', ''), page_url, target) or page_url
                if len(observed_actions) < self.click_budget:
                    observed_actions.append({'type': 'button', 'page_url': page_url, 'target_url': target_url, 'text': text[:120], 'name': attrs.get('name', ''), 'id': attrs.get('id', '')})

            for candidate in FETCH_HINT_RE.findall(html or ''):
                absolute = _same_host(candidate, page_url, target)
                if absolute:
                    observed_api_calls.append(absolute)

        for form in getattr(analysis, 'forms', []) or []:
            observed_actions.append({'type': 'form', 'page_url': form.page_url, 'target_url': form.action_url, 'method': form.method, 'has_password': form.has_password, 'has_file_input': form.has_file_input})
            if _is_api_like(form.action_url):
                observed_api_calls.append(form.action_url)
            else:
                observed_urls.append(form.action_url)

        observed_api_calls.extend([u for u in observed_urls if _is_api_like(u)])
        observed_urls = [u for u in observed_urls if not _is_api_like(u)]
        observed_urls = list(dict.fromkeys(observed_urls))
        observed_api_calls = list(dict.fromkeys(observed_api_calls))
        return BrowserDiscoveryResult(
            documents=documents,
            observed_urls=observed_urls,
            observed_actions=observed_actions[: self.click_budget],
            observed_api_calls=observed_api_calls,
            analysis=analysis,
            entry_response=getattr(self.crawler, 'entry_response', None),
        )
