"""Smoke-тесты CLI: python tests/test_cli.py (без pytest, на assert'ах)."""
import argparse
import asyncio
import contextlib
import io
import os
import sys
import tempfile
from pathlib import Path

from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cli
import api
import database

SSH_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"


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
    assert all(f.get("fix") for f in findings), "находки должны обогащаться из базы знаний"

    # секреты маскируются по умолчанию, полные значения — только по запросу
    dumped = api.generate_json_report(findings)
    assert "SuperSecret123" not in dumped, "секрет не должен попадать в отчёт"
    full = api.scan_dlp(str(sample), show_secrets=True)
    assert any(f.get("value") == "SuperSecret123" for f in full), full

    # CLI-обработчики на изолированной БД
    database.DB_PATH = str(tmp / "test.db")
    database.init_db()
    args = cli.build_parser().parse_args(["dlp", str(sample)])
    with contextlib.redirect_stdout(io.StringIO()):
        assert cli.cmd_dlp(args) == 0
        assert cli.cmd_history(cli.build_parser().parse_args(["history"])) == 0

        # PDF-отчёт из БД (проверяет и путь к шрифту)
        pdf = tmp / "report.pdf"
        assert cli.cmd_report(cli.build_parser().parse_args(["report", "-o", str(pdf)])) == 0
        assert pdf.exists() and pdf.stat().st_size > 0

        assert cli.cmd_clear(cli.build_parser().parse_args(["clear", "--yes"])) == 0


def test_dlp_edge_cases(tmp: Path):
    # несуществующий путь — ошибка, а не «чисто»
    assert "error" in api.scan_dlp(str(tmp / "nope"))[0]

    sample = tmp / "keys"
    sample.mkdir()
    (sample / "id_rsa").write_text(SSH_KEY, encoding="utf-8")
    (sample / "server.pem").write_text(SSH_KEY, encoding="utf-8")
    (sample / "two.env").write_text(
        'password = "FirstSecret1"\npassword = "SecondSecret2"\n', encoding="utf-8")

    findings = api.scan_dlp(str(sample))
    files = {f.get("file") for f in findings}
    assert str(sample / "id_rsa") in files, "id_rsa без расширения должен сканироваться"
    assert str(sample / "server.pem") in files, ".pem должен сканироваться"

    passwords = [f for f in findings
                 if f.get("type") == "password" and str(f.get("file")).endswith("two.env")]
    assert len(passwords) == 2, f"два пароля в одном файле — две находки: {passwords}"

    # YARA-правила компилируются один раз на процесс
    from core.modules.dlp import yara_scanner
    assert yara_scanner._load_rules() is yara_scanner._load_rules()
    assert yara_scanner._load_rules() is not None


def test_vault(tmp: Path):
    from core.modules.vault import master, storage
    import core.modules.vault as vault
    # изолируем хранилище от боевого vault/ (cipher берёт путь из master)
    master.VAULT_DIR = tmp / "vault"
    master.MASTER_FILE = master.VAULT_DIR / ".master"
    storage.VAULT_DIR = master.VAULT_DIR
    storage.STORAGE_FILE = storage.VAULT_DIR / "encrypted.json"

    assert vault.unlock("test-master-pass")  # первый запуск инициализирует
    assert master.MASTER_FILE.read_text().startswith("pbkdf2_sha256$"), \
        "мастер-пароль должен храниться солёным PBKDF2, а не SHA-256"

    # старый vault (несолёный SHA-256) пускает и обновляет формат
    import hashlib
    old = tmp / "legacy_master"
    master.MASTER_FILE = old
    old.write_text(hashlib.sha256(b"legacy-pass").hexdigest())
    assert master.verify_password("legacy-pass")
    assert old.read_text().startswith("pbkdf2_sha256$")
    assert not master.verify_password("wrong-pass")
    master.MASTER_FILE = tmp / "vault" / ".master"
    vault.save_secret("token", "s3cret-value")
    assert vault.load_secret("token") == "s3cret-value"
    assert vault.list_secrets() == ["token"]
    vault.lock()
    assert not vault.unlock("wrong-pass")

    # потеря .salt: секреты не расшифровать, но новый salt не создаётся молча
    (master.VAULT_DIR / ".salt").unlink()
    vault.lock()
    try:
        vault.unlock("test-master-pass")
        raise AssertionError("потеря .salt должна давать ошибку, а не новый ключ")
    except RuntimeError as exc:
        assert ".salt" in str(exc)


def test_reports_and_enrichment():
    # обогащение из базы знаний
    assert "отозвать" in api.enrich_finding({"type": "ssh_key"}).get("fix", "").lower()

    # текстовый отчёт понимает находки сети/веба и пустой severity
    txt = api.generate_text_report([
        {"host": "1.2.3.4", "port": 80, "service": "http", "title": "X", "severity": None},
        {"url": "http://x/admin", "vuln_type": "sensitive_path", "severity": "high"},
    ])
    assert "1.2.3.4:80" in txt and "http://x/admin" in txt
    assert "None" not in txt


def test_network_db_and_signatures(tmp: Path):
    # миграция старой БД: network_details без колонки host
    import sqlite3
    database.DB_PATH = str(tmp / "net.db")
    conn = sqlite3.connect(database.DB_PATH)
    conn.execute("""CREATE TABLE network_details (
        id INTEGER PRIMARY KEY AUTOINCREMENT, result_id INTEGER, port INTEGER,
        service TEXT, banner TEXT, vulnerability_title TEXT, severity TEXT)""")
    conn.commit()
    conn.close()
    database.init_db()
    conn = sqlite3.connect(database.DB_PATH)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(network_details)")}
    conn.close()
    assert "host" in cols, "миграция должна добавить host в старую БД"

    database.save_network_result("2026-01-01", "10.0.0.0/24", 1, 1, [{
        "host": "10.0.0.5", "port": 80, "service": "http",
        "banner": "Server: <b>&co", "vulnerability_title": "X", "severity": "HIGH",
    }])
    conn = sqlite3.connect(database.DB_PATH)
    host = conn.execute("SELECT host FROM network_details").fetchone()[0]
    conn.close()
    assert host == "10.0.0.5", host

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        cli.cmd_history(cli.build_parser().parse_args(["history"]))
    assert "10.0.0.5:80" in out.getvalue(), out.getvalue()

    # PDF не падает на <, >, & из баннера (экранирование)
    from core.modules.report_generator_utils.report_generator import generate_pdf_report
    pdf = tmp / "net.pdf"
    generate_pdf_report(str(pdf))
    assert pdf.exists() and pdf.stat().st_size > 0

    # сигнатуры: имя сервиса само по себе не уязвимость
    import asyncio
    from types import SimpleNamespace as R
    from core.modules.scanner.vuln_signatures import match_vulnerabilities
    results = [
        R(host="h", port=5432, service="postgresql", banner="open"),
        R(host="h", port=5900, service="vnc", banner="RFB 003.008"),
        R(host="h", port=81, service="http-tomcat", banner="open"),
        R(host="h", port=5432, service="postgresql", banner="VULNERABLE: пароль postgres"),
        R(host="h", port=445, service="smb", banner="open"),
        R(host="h", port=21, service="ftp", banner="220 (vsFTPd 2.3.4)"),
    ]
    found = match_vulnerabilities(results)
    got = [(f.port, f.cve) for f in found]
    assert (5432, "Weak/Default Credentials") in got, got
    assert (5900, "Weak Authentication") not in got, got
    assert (81, "Default Credentials") not in got, got
    assert (445, "Possible CVE-2007-2447") not in got, got
    assert "CVE-2011-2523" in [c for _, c in got], got

    # лимит размера скана срабатывает до создания задач
    from core.modules.scanner.port_scanner import scan_ports
    try:
        asyncio.run(scan_ports("10.0.0.0/8", ports=[80]))
        raise AssertionError("скан /8 должен отклоняться")
    except ValueError:
        pass

    # Tomcat: активная проверка возвращает weak_creds, а не vulnerable
    from core.modules.scanner import port_scanner
    original = port_scanner.check_tomcat_default_creds

    async def fake_tomcat(host, port):
        return {"status": "open", "weak_creds": True}

    port_scanner.check_tomcat_default_creds = fake_tomcat
    try:
        _, banner = asyncio.run(port_scanner._identify_service("h", 8180))
    finally:
        port_scanner.check_tomcat_default_creds = original
    assert banner.startswith("VULNERABLE"), banner

    # SMB: подтверждён протокол, а не уязвимость
    original_smb = port_scanner.check_smb_ghost

    async def fake_smb(host, port):
        return {"status": "open", "vulnerable": False, "smb_confirmed": True,
                "detail": "SMB Negotiate подтверждён, данные: 'WORKGROUP'"}

    port_scanner.check_smb_ghost = fake_smb
    try:
        _, banner = asyncio.run(port_scanner._identify_service("h", 445))
    finally:
        port_scanner.check_smb_ghost = original_smb
    assert "VULNERABLE" not in banner and "SMB Negotiate" in banner, banner

    # два отчёта подряд не затирают друг друга
    report_a = api.save_report([{"type": "a", "severity": "high"}], str(tmp / "reports"))
    report_b = api.save_report([{"type": "b", "severity": "low"}], str(tmp / "reports"))
    assert report_a != report_b, report_a
    assert "a" in Path(report_a[0]).read_text(encoding="utf-8")
    assert "b" in Path(report_b[0]).read_text(encoding="utf-8")


def test_web_checks_and_dns(tmp: Path):
    import asyncio
    import httpx
    from core.modules.web_scanner import open_redirect

    def handler(request):
        return httpx.Response(307, headers={"Location": "http://example.com/"})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await open_redirect.run_check(client, "http://target")

    finding = asyncio.run(run())
    assert finding and finding.vuln_type == "Open HTTP Redirect", "307 + слеш в Location"

    # wildcard DNS: все имена резолвятся в один IP — это шум, а не поддомены
    from types import SimpleNamespace
    from core.modules.scanner import osint
    wordlist = tmp / "words.txt"
    wordlist.write_text("www\nmail\n", encoding="utf-8")

    class FakeDNS:
        async def query_status(self, name, rtype):
            records = await self.query(name, rtype)
            return records, bool(records)

        async def query(self, name, rtype):
            if rtype != "A":
                return []
            ip = "1.2.3.4" if ("wildcard" in name or name.startswith("mail.")) else "5.6.7.8"
            return [SimpleNamespace(address=ip)]

    found = asyncio.run(osint.find_subdomains(
        "example.com", str(wordlist), dns_client=FakeDNS()))
    assert [f["subdomain"] for f in found] == ["www.example.com"], found


def test_resource_fallback(tmp: Path):
    from core import paths
    old = paths.INSTALLED_ROOT
    try:
        paths.INSTALLED_ROOT = tmp
        (tmp / "knowledge_base").mkdir()
        (tmp / "knowledge_base" / "x.json").write_text("{}", encoding="utf-8")
        found = paths.resource_path("knowledge_base/x.json")
        assert found == tmp / "knowledge_base" / "x.json", found
    finally:
        paths.INSTALLED_ROOT = old


def test_wordlist_and_speed(tmp: Path):
    from core.modules.scanner import osint

    # внешний словарь через env подхватывается по умолчанию
    custom = tmp / "custom.txt"
    custom.write_text("www\n# комментарий\nmail\nbad name\n", encoding="utf-8")
    # BOM из Windows не должен съедать первую строку
    bom = tmp / "bom.txt"
    bom.write_bytes("\ufeffwww\nmail\n".encode("utf-8"))
    old_env = os.environ.get(osint.WORDLIST_ENV)
    os.environ[osint.WORDLIST_ENV] = str(custom)
    try:
        assert osint.default_wordlist() == str(custom)
        assert osint._read_wordlist(str(custom)) == ["www", "mail"], osint._read_wordlist(str(custom))
        assert osint._read_wordlist(str(bom)) == ["www", "mail"], osint._read_wordlist(str(bom))
    finally:
        if old_env is None:
            os.environ.pop(osint.WORDLIST_ENV, None)
        else:
            os.environ[osint.WORDLIST_ENV] = old_env

    # встроенный словарь непустой и без дублей
    assert os.path.getsize(osint._DEFAULT_WORDLIST) > 5000
    bundled = osint._read_wordlist(osint._DEFAULT_WORDLIST)
    assert len(bundled) > 1000 and len(bundled) == len(set(bundled)), len(bundled)

    # CNAME спрашивается и при наличии A: висячий CNAME резолвится через CDN
    calls = []

    class CountingDNS:
        async def query_status(self, name, rtype):
            calls.append((name, rtype))
            if name.startswith("has-a."):
                return ([SimpleNamespace(address="1.1.1.1")] if rtype == "A" else []), True
            return [], True

        async def query(self, name, rtype):
            records, _ = await self.query_status(name, rtype)
            return records

    result = asyncio.run(osint._resolve_host("has-a.example.com", CountingDNS(), asyncio.Semaphore(1)))
    assert calls == [("has-a.example.com", "A"), ("has-a.example.com", "CNAME")], calls
    assert result["ips"] == ["1.1.1.1"]

    calls.clear()
    asyncio.run(osint._resolve_host("no-a.example.com", CountingDNS(), asyncio.Semaphore(1)))
    assert calls == [("no-a.example.com", "A"), ("no-a.example.com", "AAAA"),
                     ("no-a.example.com", "CNAME")], calls


def test_help_and_completion():
    # опечатка в команде -> подсказка
    assert cli._suggest_command("dpl") == "dlp"
    assert cli._suggest_command("vau") == "vault"

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

    # подсказка на опечатку из main()
    with contextlib.redirect_stdout(io.StringIO()):
        assert cli.main(["dpl", "."]) == 2


if __name__ == "__main__":
    test_parser()
    test_help_and_completion()
    test_reports_and_enrichment()
    with tempfile.TemporaryDirectory() as d:
        test_dlp_and_db(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_dlp_edge_cases(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_vault(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_network_db_and_signatures(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_resource_fallback(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_web_checks_and_dns(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_wordlist_and_speed(Path(d))
    print("OK: все проверки пройдены")
