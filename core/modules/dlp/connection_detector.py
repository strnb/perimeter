import re
from pathlib import Path
from .results import Finding
from .patterns import CONNECTION_PATTERN, is_placeholder

def detect_connections(file: Path, lines: list[str]) -> list[Finding]:
    findings = []

    for line_number, line in enumerate(lines, start=1):
        match = CONNECTION_PATTERN.search(line)
        if not match:
            continue
        password = match.group("value")
        if is_placeholder(password):
            continue
        findings.append(Finding(
            type="connection_string",
            severity="critical",
            file=str(file),
            line=line_number,
            value=password[:40],
            kb_id="VULN-040",
        ))

    return findings
