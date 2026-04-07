from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_yaml_config(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f'No se encontró el fichero de configuración: {path}')
    data = yaml.safe_load(file_path.read_text(encoding='utf-8')) or {}
    if not isinstance(data, dict):
        raise ValueError('El fichero YAML debe contener un objeto raíz de tipo diccionario.')
    return data
