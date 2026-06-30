import re
from pathlib import Path
from .results import Finding
from .patterns import WEAK_SESSION_PATTERNS

TARGET_EXTENSIONS = {".php"}

def detect_weak_session(file: Path, lines: list[str]) -> list[Finding]:
    if file.suffix not in TARGET_EXTENSIONS:
        return []

    findings = []

    for line_number, line in enumerate(lines, start=1):
        for pattern in WEAK_SESSION_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    type="weak_session_id",
                    severity="high",
                    file=str(file),
                    line=line_number,
                    value=line.strip()[:60],
                ))
                break

    return findings