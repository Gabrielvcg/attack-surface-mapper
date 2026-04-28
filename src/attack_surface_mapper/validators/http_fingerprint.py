from __future__ import annotations

import uuid
from dataclasses import dataclass
from urllib.parse import urljoin

from attack_surface_mapper.http_client import RequestError


STATIC_PATH_SUFFIXES = (
    '.css',
    '.js',
    '.mjs',
    '.map',
    '.png',
    '.jpg',
    '.jpeg',
    '.gif',
    '.svg',
    '.ico',
    '.woff',
    '.woff2',
    '.ttf',
    '.eot',
)


@dataclass(slots=True)
class ResponseFingerprint:
    status_code: int
    content_type: str
    body_hash: int
    body_length: int
    title: str
    preview: str


def normalise_text(text: str, max_len: int = 2000) -> str:
    return ' '.join((text or '')[:max_len].split()).strip().lower()


def is_static_asset_path(path: str) -> bool:
    clean_path = (path or '').split('?', 1)[0].lower()
    return clean_path.endswith(STATIC_PATH_SUFFIXES)


def extract_title(text: str) -> str:
    lower = (text or '').lower()
    start = lower.find('<title>')
    end = lower.find('</title>')
    if start != -1 and end != -1 and end > start:
        return ' '.join(text[start + 7:end].split()).strip().lower()
    return ''


def fingerprint_response(response) -> ResponseFingerprint:
    body = response.text or ''
    preview = normalise_text(body)
    content_type = (response.headers.get('Content-Type') or '').split(';')[0].strip().lower()
    return ResponseFingerprint(
        status_code=response.status_code,
        content_type=content_type,
        body_hash=hash(preview),
        body_length=len(body),
        title=extract_title(body),
        preview=preview,
    )


def baseline_fingerprint(session, target: str, timeout: int) -> ResponseFingerprint | None:
    random_path = f'__attack_surface_mapper_not_found__{uuid.uuid4().hex}'
    url = urljoin(target.rstrip('/') + '/', random_path)
    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)
    except RequestError:
        return None
    return fingerprint_response(response)


def looks_like_baseline(response, baseline: ResponseFingerprint | None) -> bool:
    if baseline is None:
        return False
    current = fingerprint_response(response)
    if current.status_code == baseline.status_code and current.body_hash == baseline.body_hash:
        return True
    if (
        current.status_code == baseline.status_code
        and current.content_type == baseline.content_type
        and current.title
        and baseline.title
        and current.title == baseline.title
        and abs(current.body_length - baseline.body_length) < 32
    ):
        return True
    if (
        current.status_code == baseline.status_code
        and current.content_type == baseline.content_type
        and current.preview
        and baseline.preview
        and current.preview[:120] == baseline.preview[:120]
        and abs(current.body_length - baseline.body_length) < 24
    ):
        return True
    return False


def looks_like_login_surface(response, body_preview: str) -> bool:
    final_url = (getattr(response, 'url', '') or '').lower()
    content_type = (response.headers.get('Content-Type') or '').lower()
    if 'html' not in content_type:
        return False

    login_url_tokens = ('/login', '/signin', '/sign-in', '/account/login', '/admin/login', 'next=/admin')
    login_body_tokens = (
        'type="password"',
        "type='password'",
        'password',
        'username',
        'csrfmiddlewaretoken',
        'log in',
        'login',
        'sign in',
        'remember me',
    )

    url_signal = any(token in final_url for token in login_url_tokens)
    body_signal = sum(1 for token in login_body_tokens if token in body_preview)
    return url_signal and body_signal >= 2


def looks_like_setup_surface(response, body_preview: str) -> bool:
    final_url = (getattr(response, 'url', '') or '').lower()
    content_type = (response.headers.get('Content-Type') or '').lower()
    if 'html' not in content_type:
        return False

    setup_url_tokens = (
        '/wp-admin/install.php',
        '/install.php',
        '/setup',
        '/installer',
    )
    setup_body_token_groups = (
        ('wordpress', 'installation'),
        ('wordpress', 'install.php'),
        ('famous five-minute', 'installation'),
        ('proceso de instalación', 'wordpress'),
        ('información necesaria', 'wordpress'),
        ('site title', 'username', 'password'),
        ('título del sitio', 'nombre de usuario', 'contraseña'),
    )

    url_signal = any(token in final_url for token in setup_url_tokens)
    body_signal = any(all(token in body_preview for token in group) for group in setup_body_token_groups)
    return url_signal and body_signal
