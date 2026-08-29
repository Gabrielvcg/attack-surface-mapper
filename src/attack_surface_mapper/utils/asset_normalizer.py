
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def _is_ip_address(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def normalize_asset(target: str) -> dict[str, str | None]:
    parsed = urlparse(target if '://' in target else f'http://{target}')
    host_original = (parsed.hostname or '').strip().lower() or None
    port = str(parsed.port or (443 if parsed.scheme == 'https' else 80))
    resolved = None
    if host_original:
        if _is_ip_address(host_original):
            resolved = host_original
        else:
            try:
                resolved = socket.gethostbyname(host_original)
            except Exception:
                resolved = None
    return {
        'target_host_original': host_original,
        'asset_host': host_original,
        'asset_host_resolved': resolved,
        'asset_port': port,
    }
