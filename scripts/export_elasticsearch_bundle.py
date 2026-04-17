from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / 'src'
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from attack_surface_mapper.reporting import export_elasticsearch_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Genera un bundle de salida para Elasticsearch a partir de un run existente.'
    )
    parser.add_argument(
        '--run-dir',
        required=True,
        help='Directorio del run ya generado, por ejemplo scans/2026-04-14_120000 o scans/lab_juice_shop_passive_recon_enum',
    )
    parser.add_argument(
        '--index-prefix',
        default='attack-surface-mapper',
        help='Prefijo de índices para findings, summaries y runs.',
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    manifest = export_elasticsearch_bundle(args.run_dir, index_prefix=args.index_prefix)
    print(f"Bundle Elasticsearch exportado en: {manifest['output_dir']}")
    print(f"Indices: {manifest['indices']}")
    print(f"Documentos: {manifest['documents']}")
    if manifest.get('warnings'):
        print('Advertencias:')
        for warning in manifest['warnings']:
            print(f'- {warning}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
