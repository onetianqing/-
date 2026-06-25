from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GradeResult:
    score: int
    success: bool
    grader: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "success": self.success,
            "grader": self.grader,
            "details": self.details,
        }
