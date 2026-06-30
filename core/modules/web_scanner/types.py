from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, Optional

import httpx


@dataclass
class WebFinding:
    url: str
    vuln_type: str
    severity: str
    detail: str
    kb_id: Optional[str] = None

    def as_dict(self) -> Dict[str, str]:
        data: Dict[str, str] = {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "detail": self.detail,
        }
        if self.kb_id:
            data["kb_id"] = self.kb_id
        return data


@dataclass(frozen=True)
class WebCheck:
    name: str
    run: Callable[[httpx.AsyncClient, str], Awaitable[Optional[WebFinding]]]
