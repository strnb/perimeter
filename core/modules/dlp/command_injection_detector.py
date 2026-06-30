import re
from pathlib import Path
from .results import Finding
from .patterns import COMMAND_INJECTION_PATTERNS

TARGET_EXTENSIONS = {".php", ".py"}

def detect_command_injection(file: Path, lines: list[str]) -> list[Finding]:
    if file.suffix not in TARGET_EXTENSIONS:
        return []

    findings = []

    for line_number, line in enumerate(lines, start=1):
        for pattern in COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    type="command_injection",
                    severity="critical",
                    file=str(file),
                    line=line_number,
                    value=line.strip()[:60],
                ))

    return findings