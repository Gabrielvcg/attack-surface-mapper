from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / 'src'
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from attack_surface_mapper.reporting.review_matrix import build_review_rows, write_review_matrix


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Exporta una matriz CSV para revisar hallazgos de labs y etiquetarlos como verdadero/falso/dudoso.')
    parser.add_argument('run_dirs', nargs='*', help='Directorios de run dentro de scans/. Si se omite, usa scans/lab_*')
    parser.add_argument('--output', default='reviews/lab_findings_review.csv', help='Ruta CSV de salida')
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.run_dirs:
        run_dirs = [Path(item) for item in args.run_dirs]
    else:
        run_dirs = sorted(Path('scans').glob('lab_*'))
    rows = build_review_rows(run_dirs)
    if not rows:
        print('No se encontraron hallazgos para exportar.')
        return 1
    output = write_review_matrix(rows, args.output)
    print(f'Matriz de revisión exportada: {output}')
    print(f'Filas: {len(rows)}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
