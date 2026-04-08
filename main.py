from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / 'src'
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from attack_surface_mapper.batch import write_aggregate_reports
from attack_surface_mapper.orchestrator import ScanOrchestrator, ScanResult
from attack_surface_mapper.utils.config import load_yaml_config
from attack_surface_mapper.utils.exceptions import NucleiExecutionError, NucleiNotInstalledError

PROFILE_DEFAULTS: dict[str, dict[str, object]] = {
    'quick': {'severity': 'high,critical', 'rate_limit': 150, 'timeout': 8, 'retries': 1, 'validator_timeout': 5, 'crawl_max_pages': 10, 'crawl_max_depth': 1, 'http_mode': 'passive', 'crawl_include_js': False},
    'normal': {'severity': 'medium,high,critical', 'rate_limit': 150, 'timeout': 10, 'retries': 1, 'validator_timeout': 6, 'crawl_max_pages': 20, 'crawl_max_depth': 2, 'http_mode': 'passive', 'crawl_include_js': False},
    'deep': {'severity': 'low,medium,high,critical', 'rate_limit': 100, 'timeout': 15, 'retries': 2, 'validator_timeout': 8, 'crawl_max_pages': 40, 'crawl_max_depth': 2, 'http_mode': 'passive', 'crawl_include_js': True},
    'passive': {'severity': 'medium,high,critical', 'rate_limit': 150, 'timeout': 10, 'retries': 1, 'validator_timeout': 6, 'crawl_max_pages': 25, 'crawl_max_depth': 2, 'http_mode': 'passive', 'crawl_include_js': False},
    'active': {'severity': 'low,medium,high,critical', 'rate_limit': 100, 'timeout': 15, 'retries': 2, 'validator_timeout': 10, 'crawl_max_pages': 50, 'crawl_max_depth': 3, 'http_mode': 'active', 'crawl_include_js': True},
    'active-aggressive': {'severity': 'low,medium,high,critical', 'rate_limit': 100, 'timeout': 15, 'retries': 2, 'validator_timeout': 10, 'crawl_max_pages': 50, 'crawl_max_depth': 4, 'http_backend': 'requests', 'crawler_backend': 'scrapling', 'crawler_scrapling_mode': 'dynamic', 'http_mode': 'active', 'crawl_include_js': True, 'run_nuclei': True, 'run_nmap': True, 'baseline_probe': True, 'observed_only': False, 'run_panels': True, 'run_auth': True, 'run_api': True, 'run_sensitive_files': True, 'run_secrets': True},
    'passive-stealth': {'severity': 'low,medium,high,critical', 'rate_limit': 30, 'timeout': 8, 'retries': 0, 'validator_timeout': 5, 'crawl_max_pages': 12, 'crawl_max_depth': 1, 'http_backend': 'requests', 'crawler_backend': 'requests', 'http_mode': 'passive', 'crawl_include_js': False, 'run_nuclei': False, 'baseline_probe': False, 'observed_only': True, 'run_panels': False, 'run_auth': False, 'run_api': False, 'run_sensitive_files': False, 'run_secrets': False},
    'passive-recon': {'severity': 'medium,high,critical', 'rate_limit': 90, 'timeout': 10, 'retries': 1, 'validator_timeout': 6, 'crawl_max_pages': 25, 'crawl_max_depth': 2, 'http_backend': 'requests', 'crawler_backend': 'requests', 'http_mode': 'passive', 'crawl_include_js': True, 'run_nuclei': True, 'baseline_probe': True, 'observed_only': False, 'run_panels': True, 'run_auth': True, 'run_api': True, 'run_sensitive_files': True, 'run_secrets': True},
    'passive-recon-safe': {'severity': 'medium,high,critical', 'rate_limit': 45, 'timeout': 8, 'retries': 0, 'validator_timeout': 5, 'crawl_max_pages': 20, 'crawl_max_depth': 2, 'http_backend': 'requests', 'crawler_backend': 'requests', 'http_mode': 'passive', 'crawl_include_js': True, 'run_nuclei': False, 'baseline_probe': False, 'observed_only': True, 'run_panels': False, 'run_auth': False, 'run_api': False, 'run_sensitive_files': False, 'run_secrets': False},
    'passive-recon-enum': {'severity': 'medium,high,critical', 'rate_limit': 90, 'timeout': 10, 'retries': 1, 'validator_timeout': 6, 'crawl_max_pages': 25, 'crawl_max_depth': 2, 'http_backend': 'requests', 'crawler_backend': 'requests', 'http_mode': 'passive', 'crawl_include_js': True, 'run_nuclei': True, 'baseline_probe': True, 'observed_only': False, 'run_panels': True, 'run_auth': True, 'run_api': True, 'run_sensitive_files': True, 'run_secrets': True},
}


def split_csv(value: str | None) -> tuple[str, ...] | None:
    if not value:
        return None
    items = tuple(filter(None, (item.strip() for item in value.split(','))))
    return items or None


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Attack Surface Mapper: pipeline de Nuclei, Nmap opcional, validaciones propias, correlación y reporting.')
    parser.add_argument('target', nargs='?', default=None, help='Target único a escanear, por ejemplo https://example.com')
    parser.add_argument('--targets-file', default=None, help='Fichero con un target por línea')
    parser.add_argument('--config', default=None, help='Fichero YAML con configuración del escaneo')
    parser.add_argument('--profile', choices=tuple(PROFILE_DEFAULTS.keys()), default=None)
    parser.add_argument('--severity', default=None)
    parser.add_argument('--tags', default=None)
    parser.add_argument('--templates', default=None)
    parser.add_argument('--rate-limit', type=int, default=None)
    parser.add_argument('--timeout', type=int, default=None)
    parser.add_argument('--retries', type=int, default=None)
    parser.add_argument('--validator-timeout', type=int, default=None)
    parser.add_argument('--workers', type=int, default=None, help='Número de targets procesados en paralelo')
    parser.add_argument('--output-root', default='scans', help='Directorio raíz de ejecuciones')
    parser.add_argument('--run-name', default=None, help='Nombre manual para la ejecución. Si no se indica, se usa timestamp')
    parser.add_argument('--include-raw', action='store_true', default=None)
    parser.add_argument('--show-stderr', action='store_true', default=None)
    parser.add_argument('--no-follow-redirects', action='store_true', default=None)
    parser.add_argument('--compare', dest='compare_with_json', default=None)
    parser.add_argument('--use-nmap', action='store_true', default=None, help='Activa descubrimiento de puertos/servicios con Nmap (-Pn -sV).')
    parser.add_argument('--nmap-top-ports', type=int, default=None, help='Número de puertos más comunes a escanear con Nmap.')
    parser.add_argument('--nmap-args', default=None, help='Argumentos extra para Nmap separados por comas, por ejemplo: -sC,-T4')
    parser.add_argument('--nmap-timing', default=None, help='Plantilla de timing para Nmap, por ejemplo -T4')

    parser.add_argument('--skip-headers', action='store_true', default=None)
    parser.add_argument('--skip-panels', action='store_true', default=None)
    parser.add_argument('--skip-tls', action='store_true', default=None)
    parser.add_argument('--skip-crawl', action='store_true', default=None)
    parser.add_argument('--skip-secrets', action='store_true', default=None)
    parser.add_argument('--skip-auth', action='store_true', default=None)
    parser.add_argument('--skip-api', action='store_true', default=None)
    parser.add_argument('--skip-sensitive-files', action='store_true', default=None)
    parser.add_argument('--crawl-max-pages', type=int, default=None)
    parser.add_argument('--crawl-max-depth', type=int, default=None)
    parser.add_argument('--crawl-include-js', action='store_true', default=None)
    parser.add_argument('--panel-paths', default=None)
    parser.add_argument('--http-backend', choices=('auto','requests','scrapling'), default=None, help='Backend HTTP para validadores y crawling.')
    parser.add_argument('--http-mode', choices=('passive','active'), default=None, help='Modo HTTP para validadores/probes: passive usa fetch HTTP; active habilita render dinámico con Scrapling si se usa como backend HTTP.')
    parser.add_argument('--crawler-backend', choices=('auto','requests','scrapling'), default=None, help='Backend específico del crawler. Si no se indica, hereda de http.backend.')
    parser.add_argument('--crawler-scrapling-mode', choices=('auto','fetcher','dynamic','stealthy'), default=None, help='Modo interno de Scrapling para el crawler: fetcher para HTTP sin navegador, dynamic para Playwright y stealthy para browser stealth.')

    parser.add_argument('--user-agent', default=None, help='User-Agent HTTP para validadores y crawling.')
    parser.add_argument('--run-nuclei', action='store_true', default=None, help='Fuerza la ejecución de Nuclei si no se desactiva por configuración.')
    parser.add_argument('--baseline-probe', action='store_true', default=None, help='Activa la sonda baseline/not-found para validadores que la soportan.')
    parser.add_argument('--observed-only', action='store_true', default=None, help='Limita validadores a rutas observadas desde navegación/crawl.')

    parser.add_argument('--report-title', default=None)
    parser.add_argument('--report-formats', default=None, help='md,html,csv,summary-json,comparison-json')
    parser.add_argument('--skip-reports', action='store_true', default=None)
    parser.add_argument('--debug', action='store_true', default=None)
    return parser


def cli_value(args: argparse.Namespace, name: str) -> Any:
    return getattr(args, name, None)


def resolve_config_path(config_path: str | None) -> str | None:
    if not config_path:
        return None
    candidate = Path(config_path)
    if candidate.exists():
        return str(candidate)
    search_roots = [
        PROJECT_ROOT / 'config' / 'profiles',
        PROJECT_ROOT / 'config' / 'examples',
        PROJECT_ROOT / 'config' / 'defaults',
    ]
    for root in search_roots:
        probe = root / config_path
        if probe.exists():
            return str(probe)
    return config_path


def resolve_targets(args: argparse.Namespace, config: dict[str, Any]) -> list[str]:
    targets: list[str] = []
    if args.target:
        targets.append(args.target)
    if args.targets_file:
        file_targets = [line.strip() for line in Path(args.targets_file).read_text(encoding='utf-8').splitlines() if line.strip() and not line.strip().startswith('#')]
        targets.extend(file_targets)
    config_targets = config.get('targets') or []
    if isinstance(config_targets, list):
        targets.extend([str(item).strip() for item in config_targets if str(item).strip()])
    return list(dict.fromkeys(targets))


def get_setting(args: argparse.Namespace, config: dict[str, Any], name: str, default: Any = None) -> Any:
    value = cli_value(args, name)
    if value is not None:
        return value
    modules = config.get('modules', {}) if isinstance(config.get('modules', {}), dict) else {}
    validators = config.get('validators', {}) if isinstance(config.get('validators', {}), dict) else {}
    nuclei = config.get('nuclei', {}) if isinstance(config.get('nuclei', {}), dict) else {}
    crawl = config.get('crawl', {}) if isinstance(config.get('crawl', {}), dict) else {}
    crawler = config.get('crawler', {}) if isinstance(config.get('crawler', {}), dict) else {}
    reports = config.get('reports', {}) if isinstance(config.get('reports', {}), dict) else {}
    nmap = config.get('nmap', {}) if isinstance(config.get('nmap', {}), dict) else {}

    lookup = {
        'profile': config.get('profile'),
        'severity': nuclei.get('severity') or config.get('severity'),
        'tags': nuclei.get('tags') or config.get('tags'),
        'templates': nuclei.get('templates') or config.get('templates'),
        'rate_limit': nuclei.get('rate_limit') or config.get('rate_limit'),
        'timeout': nuclei.get('timeout') or config.get('timeout'),
        'retries': nuclei.get('retries') or config.get('retries'),
        'validator_timeout': config.get('validator_timeout'),
        'workers': config.get('workers'),
        'crawl_max_pages': crawl.get('max_pages') or crawler.get('max_pages') or config.get('crawl_max_pages'),
        'crawl_max_depth': crawl.get('max_depth') or crawler.get('max_depth') or config.get('crawl_max_depth'),
        'crawl_include_js': crawl.get('include_js') if 'include_js' in crawl else (crawler.get('include_js') if 'include_js' in crawler else (crawler.get('dynamic') if 'dynamic' in crawler else config.get('crawl_include_js'))),
        'crawler_backend': crawler.get('backend') or crawl.get('backend') or config.get('crawler_backend'),
        'crawler_scrapling_mode': crawler.get('scrapling_mode') or crawl.get('scrapling_mode') or config.get('crawler_scrapling_mode'),
        'panel_paths': config.get('panel_paths'),
        'http_backend': (config.get('http', {}) or {}).get('backend') if isinstance(config.get('http', {}), dict) else config.get('http_backend'),
        'http_mode': (config.get('http', {}) or {}).get('mode') if isinstance(config.get('http', {}), dict) else config.get('http_mode'),
        'user_agent': ((config.get('http', {}) or {}).get('headers', {}) or {}).get('User-Agent') if isinstance((config.get('http', {}) or {}).get('headers', {}), dict) else config.get('user_agent'),
        'run_nuclei': nuclei.get('enabled') if 'enabled' in nuclei else config.get('run_nuclei'),
        'baseline_probe': validators.get('baseline_probe') if 'baseline_probe' in validators else config.get('baseline_probe'),
        'observed_only': validators.get('observed_only') if 'observed_only' in validators else config.get('observed_only'),
        'browser_click_budget': (config.get('browser', {}) or {}).get('click_budget') if isinstance(config.get('browser', {}), dict) else config.get('browser_click_budget'),
        'browser_discovery_enabled': (config.get('browser', {}) or {}).get('enabled') if isinstance(config.get('browser', {}), dict) else config.get('browser_discovery_enabled'),
        'report_title': reports.get('title') or config.get('report_title'),
        'report_formats': reports.get('formats') or config.get('report_formats'),
        'skip_reports': reports.get('skip_reports') if 'skip_reports' in reports else config.get('skip_reports'),
        'use_nmap': nmap.get('enabled') if 'enabled' in nmap else config.get('use_nmap'),
        'nmap_top_ports': nmap.get('top_ports') or config.get('nmap_top_ports'),
        'nmap_args': nmap.get('args') or config.get('nmap_args'),
        'nmap_timing': nmap.get('timing') or config.get('nmap_timing'),
    }
    if name.startswith('skip_'):
        module_name = name.replace('skip_', '')
        if module_name in validators:
            return not bool(validators[module_name])
        if module_name in modules:
            return not bool(modules[module_name])
    resolved = lookup.get(name, default)
    return default if resolved is None else resolved


def safe_int(value: Any, default: int) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_slug(target: str) -> str:
    return re.sub(r'[^a-zA-Z0-9._-]+', '_', target.strip())[:80] or 'target'


def build_run_paths(output_root: str, run_name: str | None) -> tuple[Path, Path, Path]:
    name = run_name or datetime.now().strftime('%Y-%m-%d_%H%M%S')
    base = Path(output_root) / name
    targets_dir = base / 'targets'
    reports_dir = base / 'reports'
    targets_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    return base, targets_dir, reports_dir


def build_report_paths(base_dir: Path, formats: tuple[str, ...] | None, skip_reports: bool) -> dict[str, str | None]:
    if skip_reports:
        return {'report_markdown': None, 'report_html': None, 'report_csv': None, 'report_summary_json': None, 'report_comparison_json': None}
    base_dir.mkdir(parents=True, exist_ok=True)
    selected = {item.lower() for item in (formats or ('md', 'html', 'csv', 'summary-json', 'comparison-json'))}
    return {
        'report_markdown': str(base_dir / 'report.md') if 'md' in selected else None,
        'report_html': str(base_dir / 'report.html') if 'html' in selected else None,
        'report_csv': str(base_dir / 'report.csv') if 'csv' in selected else None,
        'report_summary_json': str(base_dir / 'report.summary.json') if 'summary-json' in selected else None,
        'report_comparison_json': str(base_dir / 'report.comparison.json') if 'comparison-json' in selected else None,
    }




def build_target_paths(targets_dir: Path, target: str) -> dict[str, Path]:
    slug = safe_slug(target)
    target_dir = targets_dir / slug
    findings_dir = target_dir / 'findings'
    reports_dir = target_dir / 'reports'
    artifacts_dir = target_dir / 'artifacts'
    debug_dir = target_dir / 'debug'
    for path in (target_dir, findings_dir, reports_dir, artifacts_dir, debug_dir):
        path.mkdir(parents=True, exist_ok=True)
    return {
        'target_dir': target_dir,
        'findings_dir': findings_dir,
        'reports_dir': reports_dir,
        'artifacts_dir': artifacts_dir,
        'debug_dir': debug_dir,
    }


def scan_one(target: str, args: argparse.Namespace, config: dict[str, Any], targets_dir: Path) -> ScanResult:
    profile_name = str(get_setting(args, config, 'profile', 'normal') or 'normal').lower()
    profile = PROFILE_DEFAULTS.get(profile_name, PROFILE_DEFAULTS['normal'])
    severities = split_csv(get_setting(args, config, 'severity')) or split_csv(str(profile['severity'])) or ('medium', 'high', 'critical')
    tags = split_csv(get_setting(args, config, 'tags'))
    panel_paths = split_csv(get_setting(args, config, 'panel_paths'))
    report_formats = split_csv(get_setting(args, config, 'report_formats'))
    skip_reports = bool(get_setting(args, config, 'skip_reports', False) or args.skip_reports)
    use_nmap = bool(get_setting(args, config, 'use_nmap', profile.get('run_nmap', False)) or args.use_nmap)
    nmap_top_ports = safe_int(get_setting(args, config, 'nmap_top_ports', 100), 100)
    nmap_args = split_csv(get_setting(args, config, 'nmap_args'))
    nmap_timing = get_setting(args, config, 'nmap_timing')

    rate_limit = safe_int(get_setting(args, config, 'rate_limit', profile['rate_limit']), int(profile['rate_limit']))
    timeout = safe_int(get_setting(args, config, 'timeout', profile['timeout']), int(profile['timeout']))
    retries = safe_int(get_setting(args, config, 'retries', profile['retries']), int(profile['retries']))
    validator_timeout = safe_int(get_setting(args, config, 'validator_timeout', profile['validator_timeout']), int(profile['validator_timeout']))
    crawl_max_pages = safe_int(get_setting(args, config, 'crawl_max_pages', profile['crawl_max_pages']), int(profile['crawl_max_pages']))
    crawl_max_depth = safe_int(get_setting(args, config, 'crawl_max_depth', profile['crawl_max_depth']), int(profile['crawl_max_depth']))
    http_mode = str(get_setting(args, config, 'http_mode', profile.get('http_mode', 'passive')) or profile.get('http_mode', 'passive')).lower()
    http_backend = str(get_setting(args, config, 'http_backend', profile.get('http_backend', 'auto')) or profile.get('http_backend', 'auto')).lower()
    crawler_backend = str(get_setting(args, config, 'crawler_backend', profile.get('crawler_backend', http_backend)) or profile.get('crawler_backend', http_backend)).lower()
    crawler_scrapling_mode = str(get_setting(args, config, 'crawler_scrapling_mode', profile.get('crawler_scrapling_mode', 'auto')) or profile.get('crawler_scrapling_mode', 'auto')).lower()
    crawl_include_js_default = bool(profile.get('crawl_include_js', False)) or http_mode == 'active'
    crawl_include_js = bool(get_setting(args, config, 'crawl_include_js', crawl_include_js_default) or args.crawl_include_js or http_mode == 'active')
    user_agent = str(get_setting(args, config, 'user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36') or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36')
    run_nuclei = bool(get_setting(args, config, 'run_nuclei', profile.get('run_nuclei', True)))
    baseline_probe = bool(get_setting(args, config, 'baseline_probe', profile.get('baseline_probe', True)))
    observed_only = bool(get_setting(args, config, 'observed_only', profile.get('observed_only', False)))
    browser_click_budget = safe_int(get_setting(args, config, 'browser_click_budget', 12), 12)
    browser_discovery_enabled = bool(get_setting(args, config, 'browser_discovery_enabled', profile.get('browser_discovery_enabled', True)))

    target_paths = build_target_paths(targets_dir, target)
    report_paths = build_report_paths(target_paths['reports_dir'], report_formats, skip_reports)

    orchestrator = ScanOrchestrator()
    return orchestrator.scan_target(
        target=target,
        severity=severities,
        tags=tags,
        templates=get_setting(args, config, 'templates'),
        rate_limit=rate_limit,
        timeout_seconds=timeout,
        retries=retries,
        follow_redirects=not args.no_follow_redirects,
        output_json=str(target_paths['findings_dir'] / 'vulnerabilities.json'),
        raw_output_jsonl=str(target_paths['artifacts_dir'] / 'nuclei_raw.jsonl'),
        include_raw=args.include_raw,
        compare_with_json=args.compare_with_json,
        run_headers=not bool(get_setting(args, config, 'skip_headers', False) or args.skip_headers),
        run_panels=not bool(get_setting(args, config, 'skip_panels', not bool(profile.get('run_panels', True))) or args.skip_panels),
        run_tls=not bool(get_setting(args, config, 'skip_tls', False) or args.skip_tls),
        run_crawl=not bool(get_setting(args, config, 'skip_crawl', False) or args.skip_crawl),
        run_secrets=not bool(get_setting(args, config, 'skip_secrets', not bool(profile.get('run_secrets', True))) or args.skip_secrets),
        run_auth=not bool(get_setting(args, config, 'skip_auth', not bool(profile.get('run_auth', True))) or args.skip_auth),
        run_api=not bool(get_setting(args, config, 'skip_api', not bool(profile.get('run_api', True))) or args.skip_api),
        run_sensitive_files=not bool(get_setting(args, config, 'skip_sensitive_files', not bool(profile.get('run_sensitive_files', True))) or args.skip_sensitive_files),
        validator_timeout=validator_timeout,
        crawl_max_pages=crawl_max_pages,
        crawl_max_depth=crawl_max_depth,
        crawl_include_js=crawl_include_js,
        panel_paths=panel_paths,
        http_backend=http_backend,
        crawler_backend=crawler_backend,
        crawler_scrapling_mode=crawler_scrapling_mode,
        http_mode=http_mode,
        report_title=get_setting(args, config, 'report_title', 'Informe de vulnerabilidades y misconfiguraciones') or 'Informe de vulnerabilidades y misconfiguraciones',
        run_nuclei=run_nuclei,
        user_agent=user_agent,
        baseline_probe=baseline_probe,
        observed_only=observed_only,
        browser_click_budget=browser_click_budget,
        browser_discovery_enabled=browser_discovery_enabled,
        run_nmap=use_nmap,
        nmap_top_ports=nmap_top_ports,
        nmap_args=nmap_args,
        nmap_xml_output=str(target_paths['artifacts_dir'] / 'nmap_raw.xml'),
        nmap_timing_template=nmap_timing,
        debug=bool(args.debug),
        **report_paths,
    )


def main() -> int:
    args = build_arg_parser().parse_args()
    try:
        config = load_yaml_config(resolve_config_path(args.config))
    except (FileNotFoundError, ValueError) as exc:
        print(f'[ERROR] {exc}', file=sys.stderr)
        return 4

    targets = resolve_targets(args, config)
    if not targets:
        print('[ERROR] Debes indicar un target, un --targets-file o targets en el YAML.', file=sys.stderr)
        return 4

    workers = safe_int(get_setting(args, config, 'workers', 1), 1)
    run_name = args.run_name or config.get('run_name')
    base_dir, targets_dir, reports_dir = build_run_paths(args.output_root, run_name)

    results: list[ScanResult] = []
    errors: list[str] = []

    def _job(target: str) -> ScanResult:
        return scan_one(target, args, config, targets_dir)

    with cf.ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        future_map = {executor.submit(_job, target): target for target in targets}
        for future in cf.as_completed(future_map):
            target = future_map[future]
            try:
                result = future.result()
                results.append(result)
                print(f'[{target}] {len(result.vulnerabilities)} hallazgos correlacionados -> {result.output_json_path}')
                if args.debug:
                    findings_dir = Path(result.output_json_path or '').parent if result.output_json_path else None
                    if findings_dir:
                        target_dir = findings_dir.parent
                        debug_dir = target_dir / 'debug'
                        artifacts_dir = target_dir / 'artifacts'
                        debug_dir.mkdir(parents=True, exist_ok=True)
                        artifacts_dir.mkdir(parents=True, exist_ok=True)
                        (debug_dir / 'debug_probe.json').write_text(json.dumps(result.debug_probe, indent=2, ensure_ascii=False), encoding='utf-8')
                        (debug_dir / 'debug_counts.json').write_text(json.dumps(result.debug_counts, indent=2, ensure_ascii=False), encoding='utf-8')
                        (debug_dir / 'debug_http_trace.json').write_text(json.dumps(result.debug_http_trace, indent=2, ensure_ascii=False), encoding='utf-8')
                        if result.nmap_stdout:
                            (artifacts_dir / 'nmap_debug.stdout').write_text(result.nmap_stdout, encoding='utf-8')
                        if result.nmap_stderr:
                            (artifacts_dir / 'nmap_debug.stderr').write_text(result.nmap_stderr, encoding='utf-8')
            except (NucleiNotInstalledError, NucleiExecutionError) as exc:
                errors.append(f'{target}: {exc}')
            except Exception as exc:  # noqa: BLE001
                errors.append(f'{target}: {exc}')

    aggregate_paths = write_aggregate_reports(results, str(reports_dir)) if results else {}
    manifest = {
        'run_dir': str(base_dir),
        'targets': [r.target for r in results],
        'aggregate_reports': aggregate_paths,
        'errors': errors,
        'profile': str(get_setting(args, config, 'profile', '') or ''),
        'pipeline': {
            'stages': sorted({stage for r in results for stage in getattr(r, 'stages_executed', [])}),
            'collectors': sorted({collector for r in results for collector in getattr(r, 'collectors_used', [])}),
        },
        'per_target': [
            {
                'target': r.target,
                'stages': getattr(r, 'stages_executed', []),
                'collectors': getattr(r, 'collectors_used', []),
                'observed_urls': getattr(r, 'observed_urls', []),
                'observed_actions_count': len(getattr(r, 'observed_actions', []) or []),
                'observed_api_calls': getattr(r, 'observed_api_calls', []),
                'raw_findings_count': r.raw_findings_count,
                'findings': len(r.vulnerabilities),
            }
            for r in results
        ],
    }
    (base_dir / 'run_manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')

    print(f'Run dir: {base_dir}')
    if aggregate_paths:
        print('Informes agregados:')
        for name, path in aggregate_paths.items():
            print(f'  - {name}: {path}')
    if args.show_stderr:
        for result in results:
            if result.stderr.strip():
                print(f'\n[stderr][{result.target}]\n{result.stderr.strip()}')
    if errors:
        print('\nErrores detectados:')
        for err in errors:
            print(f'  - {err}')
    if any(any((v.priority or '').lower() in {'critical', 'high'} for v in r.vulnerabilities) for r in results):
        return 1
    return 2 if errors and not results else 0


if __name__ == '__main__':
    raise SystemExit(main())
