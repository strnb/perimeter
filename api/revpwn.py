"""rev-pwn (ctfkit) — CTF-помощник по Linux ELF x86-64: триаж бинаря,
генерация скелетов эксплойтов, ROP/GOT/libc/heap-хелперы.

Это тонкий фасад над вендоренным пакетом ``core.modules.ctfkit`` (проект
rev-pwn, встроен в Perimeter). Логика и набор подкоманд живут в самом пакете;
здесь только безопасная точка входа для CLI/UI: мы пробрасываем аргументы в
``ctfkit.cli.main`` и не дублируем его ~14 подкоманд.

Базовый режим работает без зависимостей (fallback на readelf/objdump/nm).
Полная точность — с pwntools (extra ``revpwn``), часть команд требует
Linux-инструментов (gdb, patchelf, one_gadget); на других ОС они сообщат об
отсутствии тулзы, но импорт безопасен.
"""

import logging
from typing import Optional, Sequence

logger = logging.getLogger(__name__)

try:
    from core.modules.ctfkit.cli import main as _ctfkit_main
    from core.modules.ctfkit import __version__ as REVPWN_VERSION

    REVPWN_AVAILABLE = True
except ImportError:  # pragma: no cover - модуль всегда на месте, страховка на будущее
    REVPWN_AVAILABLE = False
    REVPWN_VERSION = None
    logger.warning("rev-pwn (ctfkit) module not available")


def revpwn_available() -> bool:
    """Доступен ли модуль rev-pwn (ctfkit) для импорта."""
    return REVPWN_AVAILABLE


def run_revpwn(argv: Optional[Sequence[str]] = None) -> int:
    """Выполнить команду ctfkit, пробросив ей аргументы как есть.

    ``argv`` — список аргументов после ``perimeter rev`` (например,
    ``["triage", "./chall"]``). Пустой список показывает справку ctfkit,
    а не запускает интерактивное меню — так предсказуемее внутри perimeter.

    Возвращает код выхода (0 — успех), совместимый с остальными командами CLI.
    """
    if not REVPWN_AVAILABLE:
        print("[-] Модуль rev-pwn (ctfkit) недоступен")
        return 1

    args = list(argv or [])
    if not args:
        # по умолчанию — справка, а не блокирующий TUI
        args = ["-h"]

    try:
        return int(_ctfkit_main(args) or 0)
    except SystemExit as ex:  # argparse -h/--help/--version завершаются через SystemExit
        return int(ex.code or 0)
