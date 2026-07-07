import yara
from pathlib import Path
from .results import Finding

# Пропускать тестовые файлы — там захардкоженные строки это норма
TEST_PATH_MARKERS = {"test", "tests", "spec", "fixture", "mock", "stub"}

# Путь к папке с правилами — рядом с этим файлом
RULES_DIR = Path(__file__).parent / "rules"

# Соответствие названия правила YARA → тип Finding
# Обновлено под актуальные имена правил в passwords.yar
RULE_TYPE_MAP = {
    # ssh_keys.yar
    "SSH_Private_Key":               "ssh_key",
    # aws_keys.yar
    "AWS_Access_Key":                "aws_key",
    # tokens.yar
    "API_Token":                     "api_token",
    # passwords.yar — все пять правил
    "Hardcoded_Password_Assignment": "password",
    "Hardcoded_Password_Comparison": "password",
    "Hardcoded_Password_In_Call":    "password",
    "Hardcoded_Admin_Credentials":   "password",
    "Hardcoded_Config_Credential":   "password",
}


def _load_rules() -> yara.Rules:
    rule_files = {
        path.stem: str(path)
        for path in RULES_DIR.glob("*.yar")
    }
    return yara.compile(filepaths=rule_files)


def run_yara(file: Path) -> list[Finding]:
    # Проверяем путь ДО запуска матчинга — не тратим время на тестовые файлы
    if any(part.lower() in TEST_PATH_MARKERS for part in file.parts):
        return []

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
            value=match.rule,  # имя сработавшего правила — понятнее чем пустое значение
        ))

    return findings