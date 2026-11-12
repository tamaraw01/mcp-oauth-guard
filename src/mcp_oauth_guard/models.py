"""Shared finding and report structures."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


SEVERITY_ORDER = {"CRITICAL": 0, "ERROR": 1, "WARNING": 2, "INFO": 3}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    target: str
    message: str
    remediation: str
    source: str = "audit"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
