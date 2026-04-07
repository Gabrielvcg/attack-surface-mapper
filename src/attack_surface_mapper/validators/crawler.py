from __future__ import annotations

import re
from collections import deque
from html import unescape
from urllib.parse import urljoin, urlparse

from attack_surface_mapper.http_client import HttpResponse, RequestError, add_debug_trace, build_http_session


class SimpleCrawler:
    HREF_RE = re.compile(r'''(?:href|src)=["']([^"'#>\s]+)''', re.IGNORECASE)
    STATIC_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.woff', '.woff2', '.ttf', '.eot', '.map', '.mp4', '.webm', '.pdf')

    def __init__(
        self,
        *,
        timeout: int = 8,
        max_pages: int = 20,
        max_depth: int = 2,
        include_js: bool = False,
        user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        backend: str = 'auto',
        mode: str = 'passive',
        scrapling_mode: str = 'auto',
    ) -> None:
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.include_js = include_js
        self.user_agent = user_agent
        self.backend = backend
        self.mode = mode
        self.scrapling_mode = scrapling_mode
        self.entry_response: HttpResponse | None = None

    def crawl(self, target: str) -> dict[str, str]:
        add_debug_trace({'component': 'crawler', 'event': 'start', 'target': target, 'backend': self.backend, 'mode': self.mode, 'include_js': self.include_js, 'max_pages': self.max_pages, 'max_depth': self.max_depth, 'scrapling_mode': self.scrapling_mode})
        parsed_target = urlparse(target)
        allowed_netloc = parsed_target.netloc
        queue: deque[tuple[str, int]] = deque([(target, 0)])
        seen: set[str] = set()
        documents: dict[str, str] = {}
        fallback_enabled = (self.backend or 'auto').lower() in {'auto', 'scrapling'}
        scrapling_failed = False
        transport_errors = 0
        with build_http_session(backend=self.backend, mode=self.mode, timeout=self.timeout, include_js=self.include_js, user_agent=self.user_agent, scrapling_mode=self.scrapling_mode) as session:
            with build_http_session(backend='requests', mode=self.mode, timeout=self.timeout, include_js=self.include_js, user_agent=self.user_agent, scrapling_mode='auto') as fallback_session:
                while queue and len(documents) < self.max_pages:
                    url, depth = queue.popleft()
                    if url in seen:
                        add_debug_trace({'component': 'crawler', 'event': 'skip_seen', 'url': url})
                        continue
                    seen.add(url)

                    try:
                        active_session = fallback_session if scrapling_failed else session
                        response = active_session.get(url, timeout=self.timeout, allow_redirects=True)
                    except RequestError as exc:
                        if fallback_enabled:
                            error_text = str(exc)
                            if 'Empty reply from server' in error_text or 'curl: (52)' in error_text:
                                transport_errors += 1
                            if transport_errors >= 2 and not scrapling_failed:
                                scrapling_failed = True
                                add_debug_trace({'component': 'crawler', 'event': 'switch_backend', 'backend': 'requests', 'reason': 'repeated_scrapling_transport_errors', 'target': target})
                            add_debug_trace({'component': 'crawler', 'event': 'fallback_to_requests', 'url': url, 'depth': depth, 'reason': error_text})
                            try:
                                response = fallback_session.get(url, timeout=self.timeout, allow_redirects=True)
                            except RequestError as fallback_exc:
                                add_debug_trace({'component': 'crawler', 'event': 'request_error', 'url': url, 'depth': depth, 'error': str(fallback_exc)})
                                continue
                        else:
                            add_debug_trace({'component': 'crawler', 'event': 'request_error', 'url': url, 'depth': depth, 'error': str(exc)})
                            continue

                    content_type = ''
                    for key, value in (response.headers or {}).items():
                        if str(key).lower() == 'content-type':
                            content_type = str(value).lower()
                            break
                    final_url = response.url
                    final_parsed = urlparse(final_url)
                    if final_parsed.netloc != allowed_netloc:
                        add_debug_trace({'component': 'crawler', 'event': 'skip_cross_host', 'url': url, 'final_url': final_url})
                        continue

                    text_preview = response.text or ''
                    is_html = 'text/html' in content_type or text_preview.lstrip().startswith('<!DOCTYPE html') or '<html' in text_preview[:500].lower() or '<form' in text_preview[:500].lower()
                    is_js = 'javascript' in content_type or final_url.lower().endswith('.js')
                    if not is_html and not is_js:
                        add_debug_trace({'component': 'crawler', 'event': 'skip_non_document', 'url': final_url, 'content_type': content_type})
                        continue
                    if is_js and not (self.include_js or '/assets/' in final_url or '/static/' in final_url or '<script' in text_preview[:200]):
                        add_debug_trace({'component': 'crawler', 'event': 'skip_js', 'url': final_url, 'reason': 'include_js_disabled'})
                        continue

                    documents[final_url] = text_preview
                    if self.entry_response is None and is_html:
                        self.entry_response = HttpResponse(
                            status_code=int(getattr(response, 'status_code', 0) or 0),
                            url=str(final_url),
                            headers={str(k): str(v) for k, v in (getattr(response, 'headers', {}) or {}).items()},
                            text=str(text_preview or ''),
                            content=bytes(getattr(response, 'content', b'') or b''),
                        )
                    add_debug_trace({'component': 'crawler', 'event': 'store_document', 'url': final_url, 'depth': depth, 'is_html': is_html, 'is_js': is_js, 'content_type': content_type, 'body_length': len(response.content or b'')})

                    if depth >= self.max_depth or not is_html:
                        continue

                    for link in self.extract_links(text_preview, final_url, include_static=self.include_js):
                        parsed_link = urlparse(link)
                        if parsed_link.scheme not in ('http', 'https'):
                            continue
                        if parsed_link.netloc != allowed_netloc:
                            continue
                        if link in seen:
                            add_debug_trace({'component': 'crawler', 'event': 'skip_seen_link', 'url': link, 'from_url': final_url})
                            continue
                        add_debug_trace({'component': 'crawler', 'event': 'enqueue', 'url': link, 'from_url': final_url, 'next_depth': depth + 1})
                        queue.append((link, depth + 1))

        add_debug_trace({'component': 'crawler', 'event': 'finish', 'target': target, 'documents': len(documents), 'seen': len(seen)})
        return documents

    @classmethod
    def extract_links(cls, html: str, base_url: str, *, include_static: bool = False) -> list[str]:
        priority_links: list[str] = []
        secondary_links: list[str] = []
        for match in cls.HREF_RE.findall(html):
            candidate = unescape(match.strip())
            if not candidate or candidate.startswith(('mailto:', 'javascript:', 'data:')):
                continue
            absolute = urljoin(base_url, candidate)
            lower = absolute.lower()
            is_static = lower.endswith(cls.STATIC_EXTENSIONS)
            is_high_value = any(token in lower for token in ('/login', '/admin', '/dashboard', '/upload', '/graphql', '/swagger', '/openapi', '/api-docs', '/api/', '/actuator', '/metrics', '.js'))
            if is_static and not include_static and not lower.endswith('.js'):
                continue
            if is_high_value:
                priority_links.append(absolute)
            else:
                secondary_links.append(absolute)
        deduped: list[str] = []
        seen: set[str] = set()
        for link in [*priority_links, *secondary_links]:
            if link in seen:
                continue
            seen.add(link)
            deduped.append(link)
        return deduped
