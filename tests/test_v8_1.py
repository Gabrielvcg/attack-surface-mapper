from __future__ import annotations

import argparse

from main import get_setting, safe_int, PROFILE_DEFAULTS


def test_get_setting_uses_default_when_config_value_is_none() -> None:
    args = argparse.Namespace(profile=None, severity=None, tags=None, templates=None, rate_limit=None, timeout=None, retries=None, validator_timeout=None, workers=None, crawl_max_pages=None, crawl_max_depth=None, crawl_include_js=False, panel_paths=None, report_title=None, report_formats=None, skip_reports=False)
    config = {"validator_timeout": None}
    assert get_setting(args, config, 'validator_timeout', PROFILE_DEFAULTS['deep']['validator_timeout']) == PROFILE_DEFAULTS['deep']['validator_timeout']


def test_safe_int_returns_default_for_none_and_invalid_values() -> None:
    assert safe_int(None, 8) == 8
    assert safe_int('abc', 8) == 8
    assert safe_int('12', 8) == 12
