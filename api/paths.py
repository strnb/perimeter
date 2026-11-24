"""Пути проекта, общие для модулей api: корень, база знаний, wordlist."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # .../perimeter-cli
KB_PATH = ROOT / "knowledge_base" / "vulnerabilities.json"
DEFAULT_WORDLIST = str(ROOT / "core" / "subdomains_wordlist.txt")
