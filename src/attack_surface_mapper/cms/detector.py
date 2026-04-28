from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


GENERATOR_META_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)


@dataclass(slots=True)
class DetectedCMS:
    name: str
    confidence: str
    evidence: list[str] = field(default_factory=list)
    signals: dict[str, list[str]] = field(default_factory=dict)


class CMSDetector:
    """Detect CMS families from already observed content and URLs."""

    def detect(
        self,
        *,
        target: str,
        documents: dict[str, str],
        observed_urls: list[str],
        entry_body: str = '',
    ) -> list[DetectedCMS]:
        wordpress = self._detect_wordpress(target=target, documents=documents, observed_urls=observed_urls, entry_body=entry_body)
        return [wordpress] if wordpress else []

    def _detect_wordpress(
        self,
        *,
        target: str,
        documents: dict[str, str],
        observed_urls: list[str],
        entry_body: str,
    ) -> DetectedCMS | None:
        evidence: list[str] = []
        signals: dict[str, list[str]] = {
            'paths': [],
            'assets': [],
            'plugins': [],
            'themes': [],
            'generator': [],
        }
        bodies = [entry_body or '', *documents.values()]
        urls = sorted(set([*documents.keys(), *observed_urls]))

        for url in urls:
            lower_url = url.lower()
            parsed_path = (urlparse(url).path or '').lower()
            if '/wp-content/' in lower_url or '/wp-includes/' in lower_url:
                signals['assets'].append(url)
            if '/wp-json' in parsed_path or parsed_path in {'/wp-login.php', '/xmlrpc.php', '/wp-admin/install.php'}:
                signals['paths'].append(url)

        for body in bodies:
            lower_body = body.lower()
            for match in GENERATOR_META_RE.finditer(body or ''):
                generator = match.group(1).strip()
                if 'wordpress' in generator.lower():
                    signals['generator'].append(generator)
            if 'wp-content/' in lower_body or 'wp-includes/' in lower_body:
                signals['assets'].append(target)
            signals['plugins'].extend(self._extract_wp_slugs(body, 'plugins'))
            signals['themes'].extend(self._extract_wp_slugs(body, 'themes'))

        for key, values in list(signals.items()):
            signals[key] = self._dedupe(values)

        if signals['generator']:
            evidence.append(f"meta generator: {signals['generator'][0]}")
        if signals['assets']:
            evidence.append(f"WordPress asset markers observed: {len(signals['assets'])}")
        if signals['paths']:
            evidence.append(f"WordPress route markers observed: {len(signals['paths'])}")
        if signals['plugins']:
            evidence.append(f"plugin slugs observed: {', '.join(signals['plugins'][:5])}")
        if signals['themes']:
            evidence.append(f"theme slugs observed: {', '.join(signals['themes'][:5])}")

        score = 0
        if signals['generator']:
            score += 3
        if signals['assets']:
            score += 2
        if signals['paths']:
            score += 2
        if signals['plugins'] or signals['themes']:
            score += 1

        if score <= 0:
            return None
        confidence = 'high' if score >= 4 else 'medium'
        return DetectedCMS(name='wordpress', confidence=confidence, evidence=evidence, signals=signals)

    @staticmethod
    def _extract_wp_slugs(body: str, kind: str) -> list[str]:
        pattern = re.compile(rf'/wp-content/{kind}/([^/"\'\s<>?#]+)', re.IGNORECASE)
        return [match.group(1).strip() for match in pattern.finditer(body or '') if match.group(1).strip()]

    @staticmethod
    def _dedupe(values: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            out.append(value)
        return out
