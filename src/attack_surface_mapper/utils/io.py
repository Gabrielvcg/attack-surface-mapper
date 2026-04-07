from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from attack_surface_mapper.models.vulnerability import Vulnerability


def save_vulnerabilities_json(vulnerabilities: Iterable[Vulnerability], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [item.to_dict() for item in vulnerabilities]
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
