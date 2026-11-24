from dataclasses import dataclass
from typing import Optional

@dataclass
class ScanResult:
    host: str
    port: int
    status: str  # Например: "open", "closed", "timeout"
    service: Optional[str] = None
    banner: Optional[str] = None