import re
from pathlib import Path
from .results import Finding
from .patterns import API_TOKEN_PATTERNS

def detect_tokens(file: Path, lines: list[str]) -> list[Finding]:
    findings = []

    for line_number, line in enumerate(lines, start=1):
        for token_type, pattern in API_TOKEN_PATTERNS.items():
            match = re.search(pattern, line)
            if match:
                findings.append(Finding(
                    type=token_type,
                    severity="critical",
                    file=str(file),
                    line=line_number,
                    value=match.group(0)[:40],
                ))

    return findings

# python -c "
# from pathlib import Path
# from core.modules.dlp.token_detector import detect_tokens

# file = Path('tests/fixtures/fake_tokens.env')
# lines = file.read_text().splitlines()
# findings = detect_tokens(file, lines)

# print('Найдено:', len(findings))
# for f in findings:
#     print(f.type, '—', f.value)
# "