from __future__ import annotations

from types import SimpleNamespace

import main


class DummyOrchestrator:
    calls: list[dict] = []

    def scan_target(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(target=kwargs['target'])


def _run_profile(monkeypatch, tmp_path, profile: str):
    DummyOrchestrator.calls = []
    monkeypatch.setattr(main, 'ScanOrchestrator', lambda: DummyOrchestrator())
    args = main.build_arg_parser().parse_args(['--profile', profile, 'http://target.example'])
    main.scan_one('http://target.example', args, {}, tmp_path)
    assert DummyOrchestrator.calls
    return DummyOrchestrator.calls[-1]


def test_cli_passive_stealth_matches_low_noise_profile_semantics(monkeypatch, tmp_path) -> None:
    call = _run_profile(monkeypatch, tmp_path, 'passive-stealth')

    assert call['run_nuclei'] is False
    assert call['run_nmap'] is False
    assert call['baseline_probe'] is False
    assert call['observed_only'] is True
    assert call['http_backend'] == 'requests'
    assert call['crawler_backend'] == 'requests'
    assert call['run_panels'] is False
    assert call['run_auth'] is False
    assert call['run_api'] is False
    assert call['run_sensitive_files'] is False
    assert call['run_secrets'] is False


def test_cli_passive_recon_safe_keeps_observed_only_without_hardcoded_probes(monkeypatch, tmp_path) -> None:
    call = _run_profile(monkeypatch, tmp_path, 'passive-recon-safe')

    assert call['run_nuclei'] is False
    assert call['baseline_probe'] is False
    assert call['observed_only'] is True
    assert call['crawl_include_js'] is True
    assert call['run_panels'] is False
    assert call['run_auth'] is False
    assert call['run_api'] is False
    assert call['run_sensitive_files'] is False


def test_cli_active_aggressive_uses_dynamic_crawler_and_nmap(monkeypatch, tmp_path) -> None:
    call = _run_profile(monkeypatch, tmp_path, 'active-aggressive')

    assert call['run_nuclei'] is True
    assert call['run_nmap'] is True
    assert call['baseline_probe'] is True
    assert call['observed_only'] is False
    assert call['http_mode'] == 'active'
    assert call['crawler_backend'] == 'scrapling'
    assert call['crawler_scrapling_mode'] == 'dynamic'
    assert call['crawl_include_js'] is True
