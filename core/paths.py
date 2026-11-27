"""Пути к данным: из репозитория или из share/perimeter после pip install."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# setuptools data-files кладёт данные сюда: <prefix>/share/perimeter/<относительный путь>
INSTALLED_ROOT = Path(sys.prefix) / "share" / "perimeter"


def resource_path(relative: str) -> Path:
    for root in (ROOT, INSTALLED_ROOT):
        path = root / relative
        if path.exists():
            return path
    return ROOT / relative


def app_data_dir() -> Path:
    """Изменяемые данные (БД, vault) — вне site-packages."""
    path = Path.home() / ".perimeter"
    path.mkdir(parents=True, exist_ok=True)
    return path
