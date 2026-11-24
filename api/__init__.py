"""
api — фасад модулей Perimeter для UI и CLI.

Сама логика разложена по файлам рядом (dlp, vault, network, osint, web,
pipeline, knowledge, reports), а здесь только реэкспорт: `import api`
и вызовы вида `api.scan_dlp(...)` работают как раньше.
Все async-функции вызываются через asyncio.run() или await.
"""

from .knowledge import enrich_finding
from .reports import generate_json_report, generate_text_report, save_report
from .dlp import scan_dlp
from .vault import (
    vault_unlock,
    vault_lock,
    vault_save,
    vault_load,
    vault_list,
    vault_is_initialized,
)
from .network import scan_network
from .osint import run_osint_report
from .web import scan_web
from .pipeline import run_combined_pipeline

__all__ = [
    # knowledge base
    "enrich_finding",
    # reports
    "generate_json_report",
    "generate_text_report",
    "save_report",
    # dlp
    "scan_dlp",
    # crypto vault
    "vault_unlock",
    "vault_lock",
    "vault_save",
    "vault_load",
    "vault_list",
    "vault_is_initialized",
    # network / osint / web / combined
    "scan_network",
    "run_osint_report",
    "scan_web",
    "run_combined_pipeline",
]
