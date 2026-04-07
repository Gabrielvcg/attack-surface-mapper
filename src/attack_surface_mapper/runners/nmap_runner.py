from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(slots=True)
class NmapRunConfig:
    target: str
    top_ports: int = 100
    extra_args: tuple[str, ...] = ()
    xml_output_path: str | None = None
    timing_template: str | None = None


class NmapNotInstalledError(RuntimeError):
    pass


class NmapRunner:
    def ensure_installed(self) -> None:
        if shutil.which('nmap') is None:
            raise NmapNotInstalledError('nmap no está instalado o no se encuentra en PATH.')

    @staticmethod
    def normalize_target_for_nmap(target: str) -> tuple[str, str | None]:
        value = (target or '').strip()
        if '://' not in value:
            return value, None

        parsed = urlparse(value)
        host = parsed.hostname or parsed.netloc or value
        port = str(parsed.port) if parsed.port is not None else None
        return host, port

    def run(self, config: NmapRunConfig) -> tuple[str, str, int, list[str]]:
        self.ensure_installed()
        nmap_target, port_hint = self.normalize_target_for_nmap(config.target)
        command = ['nmap', '-Pn', '-sV', '--top-ports', str(config.top_ports), '-oX', '-']
        if port_hint:
            command.extend(['-p', port_hint])
        if config.timing_template:
            command.append(config.timing_template)
        command.extend(config.extra_args)
        command.append(nmap_target)
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        stdout = completed.stdout or ''
        stderr = completed.stderr or ''
        if config.xml_output_path:
            path = Path(config.xml_output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(stdout, encoding='utf-8')
        return stdout, stderr, completed.returncode, command
