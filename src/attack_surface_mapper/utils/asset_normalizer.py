
from __future__ import annotations

import socket
from urllib.parse import urlparse


def normalize_asset(target: str) -> dict[str, str | None]:
    parsed = urlparse(target if '://' in target else f'http://{target}')
    host_original = parsed.hostname
    port = str(parsed.port or (443 if parsed.scheme == 'https' else 80))
    resolved = None
    if host_original:
        try:
            resolved = socket.gethostbyname(host_original)
        except Exception:
            resolved = host_original
    return {
        'target_host_original': host_original,
        'asset_host': resolved or host_original,
        'asset_port': port,
    }
