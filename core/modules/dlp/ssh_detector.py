from pathlib import Path
from .results import Finding
from .patterns import SSH_PATTERNS

def detect_ssh(file: Path, lines: list[str]) -> list[Finding]:
    findings = []

    for line_number, line in enumerate(lines, start=1):
        for pattern in SSH_PATTERNS:
            if pattern in line:
                findings.append(Finding(
                    type="ssh_key",
                    severity="critical",
                    file=str(file),
                    line=line_number,
                    kb_id="VULN-005",
                    value=line.strip()[:40],
                ))

    return findings