"""Smoke-тест CLI: python test_cli.py (без pytest, на assert'ах)."""
import argparse
import tempfile
from pathlib import Path

import cli
import api
import database


def test_parser():
    p = cli.build_parser()
    assert p.parse_args(["dlp", "C:\\x"]).command == "dlp"
    assert p.parse_args(["scan", "host", "--ports", "22,80,8000-8002"]).ports == [22, 80, 8000, 8001, 8002]
    assert p.parse_args(["vault", "save", "x"]).vault_cmd == "save"
    assert p.parse_args(["report", "-o", "r.pdf"]).output == "r.pdf"
    try:
        cli._ports_arg("0,99999")
        raise AssertionError("невалидные порты должны отклоняться")
    except argparse.ArgumentTypeError:
        pass


def test_dlp_and_db(tmp: Path):
    # фикстура с фейковыми секретами
    sample = tmp / "sample"
    sample.mkdir()
    (sample / "config.env").write_text(
        'password = "SuperSecret123"\naws_key = AKIAIOSFODNN7EXAMPLE\n', encoding="utf-8")

    findings = api.scan_dlp(str(sample))
    types = {f.get("type") for f in findings}
    assert "password" in types, f"password не найден: {findings}"
    assert "aws_key" in types, f"aws_key не найден: {findings}"

    # CLI-обработчики на изолированной БД
    database.DB_PATH = str(tmp / "test.db")
    database.init_db()
    args = cli.build_parser().parse_args(["dlp", str(sample)])
    assert cli.cmd_dlp(args) == 0
    assert cli.cmd_history(cli.build_parser().parse_args(["history"])) == 0

    # PDF-отчёт из БД (проверяет и путь к шрифту)
    pdf = tmp / "report.pdf"
    assert cli.cmd_report(cli.build_parser().parse_args(["report", "-o", str(pdf)])) == 0
    assert pdf.exists() and pdf.stat().st_size > 0

    assert cli.cmd_clear(cli.build_parser().parse_args(["clear", "--yes"])) == 0


def test_vault(tmp: Path):
    from core.modules.vault import master, storage
    import core.modules.vault as vault
    # изолируем хранилище от боевого vault/
    master.VAULT_DIR = storage.VAULT_DIR = tmp / "vault"
    master.MASTER_FILE = master.VAULT_DIR / ".master"
    storage.STORAGE_FILE = storage.VAULT_DIR / "encrypted.json"

    assert vault.unlock("test-master-pass")  # первый запуск инициализирует
    vault.save_secret("token", "s3cret-value")
    assert vault.load_secret("token") == "s3cret-value"
    assert vault.list_secrets() == ["token"]
    vault.lock()
    assert not vault.unlock("wrong-pass")


def test_help_and_completion():
    # опечатка в команде -> подсказка
    assert cli._suggest_command("dpl") == "dlp"
    assert cli._suggest_command("vau") == "vault"
    assert cli._suggest_command("zzzzzz") == ""

    # без введённых слов Tab предлагает все команды
    commands = set(cli._complete([""]))
    assert {"dlp", "scan", "osint", "web", "pipeline", "vault",
            "report", "history", "clear", "completion"} <= commands, commands

    # после 'vault' — действия, после 'scan' — флаги, фильтр по префиксу
    assert cli._complete(["vault", ""]) == ["list", "load", "save"]
    assert "--ports" in cli._complete(["scan", ""])
    assert cli._complete(["scan", "--p"]) == ["--ports"]

    # shell-скрипты печатаются
    assert "complete -o default -F _perimeter_complete perimeter" in cli.COMPLETION_BASH
    assert "Register-ArgumentCompleter -Native" in cli.COMPLETION_POWERSHELL
    assert cli.cmd_completion(cli.build_parser().parse_args(["completion", "zsh"])) == 0

    # подсказка на опечатку из main()
    assert cli.main(["dpl", "."]) == 2


if __name__ == "__main__":
    test_parser()
    test_help_and_completion()
    with tempfile.TemporaryDirectory() as d:
        test_dlp_and_db(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_vault(Path(d))
    print("OK: все проверки пройдены")
