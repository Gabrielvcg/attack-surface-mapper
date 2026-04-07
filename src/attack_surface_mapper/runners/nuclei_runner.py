from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from attack_surface_mapper.utils.exceptions import NucleiExecutionError, NucleiNotInstalledError


@dataclass(slots=True)
class NucleiRunConfig:
    target: str
    severity: Sequence[str] = field(default_factory=lambda: ('medium', 'high', 'critical'))
    tags: Sequence[str] | None = None
    templates: str | None = None
    rate_limit: int | None = 150
    timeout_seconds: int | None = 10
    retries: int | None = 1
    follow_redirects: bool = True
    jsonl_output_path: str | None = None
    extra_args: Sequence[str] = field(default_factory=tuple)


class NucleiRunner:
    def __init__(self, binary_name: str = 'nuclei') -> None:
        self.binary_name = binary_name

    def ensure_installed(self) -> None:
        if shutil.which(self.binary_name) is None:
            raise NucleiNotInstalledError(
                f"No se encontró el binario '{self.binary_name}'. Instala Nuclei y asegúrate de que esté en PATH."
            )

    def build_command(self, config: NucleiRunConfig) -> list[str]:
        command: list[str] = [
            self.binary_name,
            '-u', config.target,
            '-jsonl',
            '-silent',
            '-no-color',
        ]

        if config.severity:
            command.extend(['-severity', ','.join(config.severity)])
        if config.tags:
            command.extend(['-tags', ','.join(config.tags)])
        if config.templates:
            command.extend(['-t', config.templates])
        if config.rate_limit is not None:
            command.extend(['-rl', str(config.rate_limit)])
        if config.timeout_seconds is not None:
            command.extend(['-timeout', str(config.timeout_seconds)])
        if config.retries is not None:
            command.extend(['-retries', str(config.retries)])
        if config.follow_redirects:
            command.append('-fr')
        if config.jsonl_output_path:
            output_path = Path(config.jsonl_output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            command.extend(['-o', str(output_path)])

        command.extend(config.extra_args)
        return command

    def run(self, config: NucleiRunConfig) -> tuple[str, str, int, list[str]]:
        self.ensure_installed()
        command = self.build_command(config)

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        stdout = process.stdout or ''
        stderr = process.stderr or ''

        if process.returncode not in (0, 1):
            raise NucleiExecutionError(
                f'Nuclei terminó con código inesperado {process.returncode}: {stderr.strip()}'
            )

        if config.jsonl_output_path:
            output_path = Path(config.jsonl_output_path)
            if output_path.exists() and not stdout.strip():
                stdout = output_path.read_text(encoding='utf-8', errors='replace')

        return stdout, stderr, process.returncode, command
