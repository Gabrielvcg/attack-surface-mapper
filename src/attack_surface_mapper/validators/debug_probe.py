from __future__ import annotations

from urllib.parse import urljoin

from attack_surface_mapper.http_client import build_http_session
from attack_surface_mapper.validators.api_validator import APIValidator
from attack_surface_mapper.validators.auth_validator import AuthValidator
from attack_surface_mapper.validators.http_fingerprint import baseline_fingerprint, looks_like_baseline, normalise_text
from attack_surface_mapper.validators.panels_validator import PanelsValidator
from attack_surface_mapper.validators.sensitive_files_validator import SensitiveFilesValidator


def _resp_info(path: str, response, baseline) -> dict:
    body_preview = normalise_text(response.text, 300)
    return {
        'path': path,
        'status_code': response.status_code,
        'final_url': response.url,
        'content_type': (response.headers.get('Content-Type') or '').lower(),
        'content_length': len(response.text or ''),
        'baseline_like': looks_like_baseline(response, baseline),
        'preview': body_preview[:300],
    }


def probe_target(target: str, timeout: int = 6, *, backend: str = 'auto', mode: str = 'passive', user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36') -> dict:
    with build_http_session(backend=backend, mode=mode, timeout=timeout, user_agent=user_agent) as session:
        baseline = baseline_fingerprint(session, target, timeout)
        data: dict = {
            'baseline': None,
            'auth': [],
            'panels': [],
            'api': [],
            'sensitive_files': [],
        }
        if baseline:
            data['baseline'] = {
                'status_code': baseline.status_code,
                'content_type': baseline.content_type,
                'body_length': baseline.body_length,
                'title': baseline.title,
                'preview': baseline.preview[:200],
            }

        auth = AuthValidator(timeout=timeout, backend=backend, mode=mode, user_agent=user_agent)
        for path in auth.paths:
            url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
            try:
                r = session.get(url, timeout=timeout, allow_redirects=True)
            except Exception as exc:
                data['auth'].append({'path': path, 'error': str(exc)})
                continue
            preview = normalise_text(r.text, 1500)
            include, confidence, reason, verification = auth._classify_open_access(path, r, preview, baseline)
            row = _resp_info(path, r, baseline)
            row.update({'include': include, 'confidence': confidence, 'reason': reason, 'verification': verification})
            data['auth'].append(row)

        panels = PanelsValidator(timeout=timeout, backend=backend, mode=mode, user_agent=user_agent)
        for path in panels.paths:
            url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
            try:
                r = session.get(url, timeout=timeout, allow_redirects=True)
            except Exception as exc:
                data['panels'].append({'path': path, 'error': str(exc)})
                continue
            preview = normalise_text(r.text)
            include, confidence, reason, verification = panels._classify(path, r, preview, baseline)
            row = _resp_info(path, r, baseline)
            row.update({'include': include, 'confidence': confidence, 'reason': reason, 'verification': verification})
            data['panels'].append(row)

        api = APIValidator(timeout=timeout, backend=backend, mode=mode, user_agent=user_agent)
        for path in api.paths:
            url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
            try:
                r = session.get(url, timeout=timeout, allow_redirects=True)
            except Exception as exc:
                data['api'].append({'path': path, 'error': str(exc)})
                continue
            preview = normalise_text(r.text, 1500)
            include, confidence, reason, verification, title, description, severity = api._classify_path(path, r, preview, (r.headers.get('Content-Type') or '').lower(), baseline)
            row = _resp_info(path, r, baseline)
            row.update({'include': include, 'confidence': confidence, 'reason': reason, 'verification': verification, 'title': title, 'severity': severity})
            data['api'].append(row)

        sf = SensitiveFilesValidator(timeout=timeout, backend=backend, mode=mode, user_agent=user_agent)
        for path in sf.paths:
            url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
            try:
                r = session.get(url, timeout=timeout, allow_redirects=True)
            except Exception as exc:
                data['sensitive_files'].append({'path': path, 'error': str(exc)})
                continue
            preview = normalise_text(r.text, 1800)
            valid, confidence, reason = sf._classify(path, r, preview)
            row = _resp_info(path, r, baseline)
            row.update({'include': valid and not looks_like_baseline(r, baseline) and r.status_code in (200, 201, 202, 204), 'confidence': confidence, 'reason': reason, 'verification': 'confirmed' if confidence == 'high' else 'likely' if valid else 'discarded'})
            data['sensitive_files'].append(row)
        return data
