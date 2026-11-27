import re
from pathlib import Path
from .results import Finding
from .patterns import TOKEN_PATTERNS

def detect_tokens(file: Path, lines: list[str]) -> list[Finding]:
    findings = []

    for line_number, line in enumerate(lines, start=1):
        for token_type, (pattern, severity, kb_id) in TOKEN_PATTERNS.items():
            match = re.search(pattern, line)
            if match:
                value = match.group(1) if match.lastindex else match.group(0)
                findings.append(Finding(
                    type=token_type,
                    severity=severity,
                    file=str(file),
                    line=line_number,
                    value=value[:40],
                    kb_id=kb_id,
                ))

    return findings
