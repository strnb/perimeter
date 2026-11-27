"""Пути проекта, общие для модулей api: корень, база знаний, wordlist."""

from core.paths import resource_path

KB_PATH = resource_path("knowledge_base/vulnerabilities.json")
DEFAULT_WORDLIST = str(resource_path("core/subdomains_wordlist.txt"))
