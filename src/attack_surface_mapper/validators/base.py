from __future__ import annotations

from abc import ABC, abstractmethod

from attack_surface_mapper.models.vulnerability import Vulnerability


class BaseValidator(ABC):
    @abstractmethod
    def run(self, target: str) -> list[Vulnerability]:
        raise NotImplementedError
