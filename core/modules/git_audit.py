"""
git_audit.py

Проверка Git-репозитория.

Собирает:

- последний коммит
- изменённые файлы
- утечки .env и *.pem в истории Git
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List


def _run_git(args: list[str], cwd: Path) -> str:
    """
    Выполняет git-команду.
    """

    try:

        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return ""

        return result.stdout.strip()

    except Exception:
        return ""


def run_git_audit(project_path: str) -> Dict:
    """
    Проверка Git-репозитория.

    Returns
    -------
    {
        last_commit,
        dirty_files,
        leaked_in_history
    }
    """

    project = Path(project_path)

    git_dir = project / ".git"

    if not git_dir.exists():

        return {
            "enabled": False,
            "last_commit": "",
            "dirty_files": [],
            "leaked_in_history": [],
        }

    #
    # Последний коммит
    #

    last_commit = _run_git(
        [
            "log",
            "-1",
            '--format=%H %s - %an',
        ],
        project,
    )

    #
    # Изменённые файлы
    #

    dirty_output = _run_git(
        [
            "diff",
            "--name-only",
        ],
        project,
    )

    dirty_files = [
        line.strip()
        for line in dirty_output.splitlines()
        if line.strip()
    ]

    #
    # Проверка истории
    #

    leaked = []

    history_patterns = [
        "*.env",
        "*.pem",
    ]

    for pattern in history_patterns:

        output = _run_git(
            [
                "log",
                "--all",
                "--full-history",
                "--",
                pattern,
            ],
            project,
        )

        if output:

            leaked.append(pattern)

    return {
        "enabled": True,
        "last_commit": last_commit,
        "dirty_files": dirty_files,
        "leaked_in_history": leaked,
    }