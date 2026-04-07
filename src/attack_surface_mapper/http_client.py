from __future__ import annotations

from dataclasses import dataclass
from threading import local
from typing import Any
import random
import time

import requests

RequestError = requests.RequestException

_TRACE = local()


def set_debug_trace_enabled(enabled: bool) -> None:
    _TRACE.enabled = bool(enabled)
    if enabled and not hasattr(_TRACE, 'events'):
        _TRACE.events = []


def reset_debug_trace() -> None:
    _TRACE.events = []


def add_debug_trace(event: dict[str, Any]) -> None:
    if not getattr(_TRACE, 'enabled', False):
        return
    if not hasattr(_TRACE, 'events'):
        _TRACE.events = []
    _TRACE.events.append(event)


def get_debug_trace() -> list[dict[str, Any]]:
    return list(getattr(_TRACE, 'events', []))


@dataclass(slots=True)
class HttpResponse:
    status_code: int
    url: str
    headers: dict[str, str]
    text: str
    content: bytes


def _normalize_headers(headers: Any) -> dict[str, str]:
    if not headers:
        return {}
    try:
        items = dict(headers).items()
    except Exception:
        try:
            items = headers.items()
        except Exception:
            return {}
    normalized: dict[str, str] = {}
    for raw_key, raw_value in items:
        key = str(raw_key)
        value = str(raw_value)
        normalized[key] = value
        lower_key = key.lower()
        if lower_key == 'content-type' and 'Content-Type' not in normalized:
            normalized['Content-Type'] = value
        elif lower_key == 'location' and 'Location' not in normalized:
            normalized['Location'] = value
    return normalized


def _get_header(headers: dict[str, str] | None, name: str, default: str = '') -> str:
    if not headers:
        return default
    if name in headers:
        return str(headers[name])
    lower_name = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lower_name:
            return str(value)
    return default


def _request_delay_for_mode(mode: str) -> tuple[float, float]:
    mode = (mode or 'passive').lower()
    if mode == 'active':
        return (0.0, 0.0)
    return (0.15, 0.45)


def _maybe_sleep(min_delay: float, max_delay: float) -> None:
    if max_delay <= 0:
        return
    time.sleep(random.uniform(max(0.0, min_delay), max_delay))


class RequestsHttpSession:
    def __init__(self, *, timeout: int = 8, user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36', mode: str = 'passive') -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.mode = (mode or 'passive').lower()
        self._min_delay, self._max_delay = _request_delay_for_mode(self.mode)
        self._session = requests.Session()
        add_debug_trace({'component': 'http_session', 'backend': 'requests', 'mode': 'passive', 'event': 'session_init', 'timeout': timeout, 'user_agent': user_agent})
        if not hasattr(self._session, 'headers') or self._session.headers is None:
            self._session.headers = {}
        self._session.headers.update({'User-Agent': user_agent})

    def get(self, url: str, *, headers: dict[str, str] | None = None, timeout: int | None = None, allow_redirects: bool = True) -> requests.Response:
        merged_headers = dict(getattr(self._session, 'headers', {}) or {})
        if headers:
            merged_headers.update(headers)
        _maybe_sleep(self._min_delay, self._max_delay)
        try:
            response = self._session.get(url, headers=merged_headers, timeout=timeout or self.timeout, allow_redirects=allow_redirects)
            response_headers = _normalize_headers(getattr(response, 'headers', None) or {})
            add_debug_trace({'component': 'http_request', 'backend': 'requests', 'event': 'response', 'url': url, 'final_url': getattr(response, 'url', url), 'status_code': getattr(response, 'status_code', None), 'allow_redirects': allow_redirects, 'timeout': timeout or self.timeout, 'content_type': _get_header(response_headers, 'Content-Type', '')})
            return response
        except TypeError:
            response = self._session.get(url, timeout=timeout or self.timeout, allow_redirects=allow_redirects)
            response_headers = _normalize_headers(getattr(response, 'headers', None) or {})
            add_debug_trace({'component': 'http_request', 'backend': 'requests', 'event': 'response', 'url': url, 'final_url': getattr(response, 'url', url), 'status_code': getattr(response, 'status_code', None), 'allow_redirects': allow_redirects, 'timeout': timeout or self.timeout, 'content_type': _get_header(response_headers, 'Content-Type', '')})
            return response

    def close(self) -> None:
        if hasattr(self._session, 'close'):
            self._session.close()

    def __enter__(self) -> 'RequestsHttpSession':
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class ScraplingHttpSession:
    def __init__(
        self,
        *,
        timeout: int = 8,
        user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        mode: str = 'passive',
        include_js: bool = False,
        network_idle: bool = True,
        scrapling_mode: str = 'auto',
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.mode = (mode or 'passive').lower()
        self.include_js = include_js
        self.network_idle = network_idle
        self.scrapling_mode = (scrapling_mode or 'auto').lower()
        self._session: Any = None
        self._dynamic = False
        self._variant = 'fetcher'
        self._init_session()
        add_debug_trace({'component': 'http_session', 'backend': 'scrapling', 'mode': self.mode, 'event': 'session_ready', 'timeout': timeout, 'user_agent': user_agent, 'include_js': include_js, 'network_idle': network_idle, 'scrapling_mode': self.scrapling_mode, 'variant': self._variant})

    def _resolved_variant(self) -> str:
        if self.scrapling_mode in {'fetcher', 'http', 'requests'}:
            return 'fetcher'
        if self.scrapling_mode in {'dynamic', 'browser'}:
            return 'dynamic'
        if self.scrapling_mode in {'stealthy', 'stealth'}:
            return 'stealthy'
        if self.include_js or self.mode == 'active':
            return 'dynamic'
        return 'fetcher'

    def _init_session(self) -> None:
        try:
            self._variant = self._resolved_variant()
            if self._variant == 'dynamic':
                from scrapling.fetchers import DynamicSession as session_cls
                init_event = 'init_dynamic'
                self._dynamic = True
                init_kwargs = {
                    'headless': True,
                    'network_idle': self.network_idle,
                    'timeout': self.timeout * 1000,
                }
            elif self._variant == 'stealthy':
                from scrapling.fetchers import StealthySession as session_cls
                init_event = 'init_stealthy'
                self._dynamic = False
                init_kwargs = {
                    'timeout': self.timeout,
                }
            else:
                from scrapling.fetchers import Fetcher as session_cls
                init_event = 'init_fetcher'
                self._dynamic = False
                init_kwargs = {}
            if self._variant == 'fetcher':
                self._session = session_cls
            else:
                self._session = session_cls(**init_kwargs)
                enter = getattr(self._session, '__enter__', None)
                if callable(enter):
                    enter()
            add_debug_trace({'component': 'http_session', 'backend': 'scrapling', 'event': init_event, 'mode': self.mode, 'variant': self._variant, 'session_class': session_cls.__name__})
        except Exception as exc:
            add_debug_trace({'component': 'http_session', 'backend': 'scrapling', 'event': 'init_error', 'mode': self.mode, 'variant': getattr(self, '_variant', 'unknown'), 'error': str(exc)})
            raise RequestError(f'No se pudo inicializar Scrapling: {exc}') from exc

    @staticmethod
    def _page_to_response(page: Any, fallback_url: str) -> HttpResponse:
        status_code = getattr(page, 'status', None)
        if status_code is None:
            status_code = getattr(page, 'status_code', 0)

        url = getattr(page, 'url', None) or getattr(page, 'final_url', None) or fallback_url
        headers = _normalize_headers(getattr(page, 'headers', None) or {})

        body = getattr(page, 'body', None)
        if callable(body):
            body = body()
        if body is None:
            content = getattr(page, 'content', None)
            if callable(content):
                content = content()
            body = content

        if isinstance(body, str):
            content_bytes = body.encode('utf-8', errors='replace')
        elif isinstance(body, bytes):
            content_bytes = body
        elif body is None:
            content_bytes = b''
        else:
            try:
                content_bytes = bytes(body)
            except Exception:
                content_bytes = str(body).encode('utf-8', errors='replace')

        encoding = getattr(page, 'encoding', None)
        if callable(encoding):
            encoding = encoding()
        if not encoding:
            declared_content_type = _get_header(headers, 'Content-Type', '')
            for part in declared_content_type.split(';')[1:]:
                part = part.strip()
                if part.lower().startswith('charset='):
                    encoding = part.split('=', 1)[1].strip()
                    break
        if not encoding:
            encoding = 'utf-8'

        text = ''
        if content_bytes:
            try:
                text = content_bytes.decode(str(encoding), errors='replace')
            except Exception:
                text = content_bytes.decode('utf-8', errors='replace')
        else:
            fallback_text = getattr(page, 'text', None)
            if fallback_text is None:
                fallback_text = getattr(page, 'html_content', None)
            if fallback_text is None:
                fallback_text = getattr(page, 'html', None)
            if callable(fallback_text):
                fallback_text = fallback_text()
            text = str(fallback_text or '')
            if text and not content_bytes:
                content_bytes = text.encode(str(encoding), errors='replace')

        return HttpResponse(
            status_code=int(status_code or 0),
            url=str(url),
            headers=headers,
            text=text,
            content=content_bytes,
        )


    def get(self, url: str, *, headers: dict[str, str] | None = None, timeout: int | None = None, allow_redirects: bool = True) -> HttpResponse:
        request_timeout = timeout or self.timeout
        request_headers = {'User-Agent': self.user_agent}
        if headers:
            request_headers.update(headers)
        _maybe_sleep(*_request_delay_for_mode(self.mode))
        add_debug_trace({'component': 'http_request', 'backend': 'scrapling', 'event': 'request_start', 'url': url, 'mode': self.mode, 'dynamic': self._dynamic, 'variant': self._variant, 'timeout': request_timeout, 'allow_redirects': allow_redirects})
        kwargs = {
            'headers': request_headers,
            'timeout': (request_timeout * 1000) if self._variant == 'dynamic' else request_timeout,
        }
        try:
            if self._variant == 'dynamic':
                kwargs['network_idle'] = self.network_idle
                kwargs['headless'] = True
                page = self._session.fetch(url, **kwargs)
            elif self._variant == 'fetcher':
                page = self._session.get(
                    url,
                    headers=request_headers,
                    follow_redirects=allow_redirects,
                    timeout=request_timeout,
                    stealthy_headers=False,
                    impersonate='chrome',
                    retries=1,
                    retry_delay=0,
                )
            else:
                kwargs['follow_redirects'] = allow_redirects
                page = self._session.get(url, **kwargs)
        except Exception as exc:
            add_debug_trace({'component': 'http_request', 'backend': 'scrapling', 'event': 'request_error', 'url': url, 'dynamic': self._dynamic, 'variant': self._variant, 'error': str(exc), 'session_class': type(self._session).__name__ if self._session is not None else None})
            raise RequestError(str(exc)) from exc
        response = self._page_to_response(page, url)
        add_debug_trace({'component': 'http_request', 'backend': 'scrapling', 'event': 'response', 'url': url, 'final_url': response.url, 'status_code': response.status_code, 'dynamic': self._dynamic, 'variant': self._variant, 'content_type': _get_header(response.headers, 'Content-Type', ''), 'body_length': len(response.content or b'')})
        if not allow_redirects and response.url != url:
            response.url = url
        return response

    def close(self) -> None:
        session = self._session
        self._session = None
        if session is None:
            return
        exit_method = getattr(session, '__exit__', None)
        if callable(exit_method):
            try:
                exit_method(None, None, None)
            except Exception:
                pass
        close_method = getattr(session, 'close', None)
        if callable(close_method):
            try:
                close_method()
            except Exception:
                pass

    def __enter__(self) -> 'ScraplingHttpSession':
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def build_http_session(
    *,
    backend: str = 'auto',
    mode: str = 'passive',
    timeout: int = 8,
    include_js: bool = False,
    user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    network_idle: bool = True,
    scrapling_mode: str = 'auto',
):
    selected = (backend or 'auto').lower()
    if selected in {'scrapling', 'auto'}:
        try:
            return ScraplingHttpSession(
                timeout=timeout,
                user_agent=user_agent,
                mode=mode,
                include_js=include_js,
                network_idle=network_idle,
                scrapling_mode=scrapling_mode,
            )
        except RequestError:
            if selected == 'scrapling':
                raise
    return RequestsHttpSession(timeout=timeout, user_agent=user_agent, mode=mode)


def http_get(
    url: str,
    *,
    backend: str = 'auto',
    mode: str = 'passive',
    timeout: int = 8,
    include_js: bool = False,
    user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    headers: dict[str, str] | None = None,
    allow_redirects: bool = True,
):
    with build_http_session(backend=backend, mode=mode, timeout=timeout, include_js=include_js, user_agent=user_agent, scrapling_mode='auto') as session:
        return session.get(url, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
