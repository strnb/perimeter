import yara
from pathlib import Path
from .results import Finding

# Путь к папке с правилами — рядом с этим файлом
RULES_DIR = Path(__file__).parent / "rules"

# Соответствие названия правила YARA → тип Finding
RULE_TYPE_MAP = {
    "SSH_Private_Key":    "ssh_key",
    "AWS_Access_Key":     "aws_key",
    "Hardcoded_Password": "password",
    "API_Token":          "api_token",
}

def _load_rules() -> yara.Rules:
    rule_files = {
        path.stem: str(path)
        for path in RULES_DIR.glob("*.yar")
    }
    return yara.compile(filepaths=rule_files)

def run_yara(file: Path) -> list[Finding]:
    try:
        rules = _load_rules()
        matches = rules.match(str(file))
    except Exception:
        return []

    findings = []
    for match in matches:
        finding_type = RULE_TYPE_MAP.get(match.rule, match.rule)
        findings.append(Finding(
            type=finding_type,
            severity="critical",
            file=str(file),
            line=0,  # YARA не возвращает номер строки
            value=match.rule,
        ))

    return findings