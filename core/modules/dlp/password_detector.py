import re
from pathlib import Path
from .results import Finding
from .patterns import PASSWORD_RULES, TOKEN_PATTERNS, is_placeholder

# Известные форматы токенов уже нашёл token_detector — не дублируем их как generic_api_key
_TOKEN_REGEXES = [re.compile(pattern) for pattern, _, _ in TOKEN_PATTERNS.values()]


def detect_passwords(file: Path, lines: list[str]) -> list[Finding]:
    findings = []

    for line_number, line in enumerate(lines, start=1):
        for pattern, finding_type, severity, kb_id in PASSWORD_RULES:
            match = pattern.search(line)
            if not match:
                continue

            value = match.group("value").strip().strip("\"'")
            if is_placeholder(value):
                continue
            if finding_type == "generic_api_key" and any(r.search(value) for r in _TOKEN_REGEXES):
                continue

            findings.append(Finding(
                type=finding_type,
                severity=severity,
                file=str(file),
                line=line_number,
                value=value[:40],
                kb_id=kb_id,
            ))

    return findings
