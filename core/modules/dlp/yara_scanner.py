import logging
from pathlib import Path

from core.paths import resource_path
from .results import Finding

try:
    import yara
except ImportError:  # DLP работает и без YARA, только на regex-детекторах
    yara = None

logger = logging.getLogger(__name__)

# Путь к папке с правилами — из репозитория или share/perimeter после pip install
RULES_DIR = resource_path("core/modules/dlp/rules")

_rules = None
_rules_loaded = False
_rules_error = None

def _load_rules():
    """Компилирует правила один раз за процесс: на каждый файл это дорого."""
    global _rules, _rules_loaded, _rules_error
    if _rules_loaded:
        return _rules
    _rules_loaded = True

    if yara is None:
        _rules_error = "yara-python не установлен"
        return None

    rule_files = {path.stem: str(path) for path in RULES_DIR.glob("*.yar")}
    if not rule_files:
        _rules_error = f"правила не найдены: {RULES_DIR}"
        return None

    try:
        _rules = yara.compile(filepaths=rule_files)
    except Exception as exc:
        _rules_error = str(exc)
        logger.error("YARA: не удалось скомпилировать правила: %s", exc)
    return _rules

def rules_failed() -> bool:
    _load_rules()
    return _rules_error is not None

def _first_offset(match):
    offset = None
    for string in match.strings:
        for instance in string.instances:
            if offset is None or instance.offset < offset:
                offset = instance.offset
    return offset

def run_yara(file: Path, data: bytes = None) -> list[Finding]:
    rules = _load_rules()
    if rules is None:
        return []
    try:
        matches = rules.match(data=data) if data is not None else rules.match(str(file))
    except Exception as exc:
        logger.error("YARA: ошибка сканирования %s: %s", file, exc)
        return []

    findings = []
    for match in matches:
        meta = match.meta or {}
        offset = _first_offset(match)

        value = match.rule
        for string in match.strings:
            for instance in string.instances:
                if instance.offset == offset:
                    value = instance.matched_data.decode("utf-8", errors="ignore")

        findings.append(Finding(
            type=meta.get("type", match.rule),
            severity=meta.get("severity", "high"),
            file=str(file),
            # YARA даёт смещение, а не номер строки
            line=data.count(b"\n", 0, offset) + 1 if offset is not None and data else 0,
            value=value[:40],
            kb_id=meta.get("kb_id"),
        ))

    return findings
