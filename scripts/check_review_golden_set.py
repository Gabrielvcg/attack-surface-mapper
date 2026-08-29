from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / 'src'
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from attack_surface_mapper.reporting import evaluate_review_rows_against_golden_set, load_review_golden_set, load_review_matrix


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Comprueba una matriz de revisión de labs contra un golden set de expectativas.')
    parser.add_argument('matrix_csv', help='Ruta al CSV exportado por export_review_matrix.py')
    parser.add_argument('--golden-set', default='tests/data/lab_review_golden_set.json', help='Ruta al JSON con expectativas mínimas')
    return parser


def main() -> int:
    args = build_parser().parse_args()
    rows = load_review_matrix(args.matrix_csv)
    golden = load_review_golden_set(args.golden_set)
    evaluation = evaluate_review_rows_against_golden_set(rows, golden)
    print(f"Golden set comprobado: {evaluation['checked']} expectativas")
    if evaluation['missing']:
        print('Filas ausentes:')
        for item in evaluation['missing']:
            print(f" - {item['run_name']} :: {item['title']}")
    if evaluation['mismatches']:
        print('Desajustes:')
        for item in evaluation['mismatches']:
            print(
                f" - {item['run_name']} :: {item['title']} :: {item['field']} "
                f"(esperado={item['expected']} actual={item['actual']})"
            )
    return 0 if evaluation['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
