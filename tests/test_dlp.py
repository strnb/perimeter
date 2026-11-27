"""Тесты DLP: python tests/test_dlp.py (assert'ы, без pytest)."""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import api
from core.modules.dlp.scanner import MAX_FILE_SIZE, run_scan, walk_files

SECRETS = {
    "app.py": 'password = "Sup3rSecret!"\nclient_secret = "abcdef1234567890xyz"\n',
    "config.yaml": 'db:\n  password: "Hunter2Pass"\n  api_key: "abcdef1234567890abcd"\n',
    "config.json": '{"auth_token": "zyxwvutsrq12345678"}',
    "prod.env": "DB_PASSWORD=ProdSecret123\nAPI_TOKEN=abcdef1234567890xyz\npassword = SecondProdPass\n",
    "id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n",
    "server.pem": "-----BEGIN PRIVATE KEY-----\nabc\n",
    "docker-compose.yml": "DATABASE_URL=postgres://admin:SecretPass123@db:5432/app\n",
    "shadow": "root:$6$abcdefgh$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:19000:0:99999:7:::\n",
    "aws_credentials": (
        "[default]\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    ),
    "tokens.py": (
        'GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"\n'
        'OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"\n'
        'GOOGLE_KEY = "AIzaabcdefghijklmnopqrstuvwxyz012345678"\n'
        'JWT_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"\n'
    ),
    "dup.env": 'password = "SameSecret123"\npassword = "SameSecret123"\n',
    "upper.env": "DB_PASSWORD=PRODSECRET2024\npassword = MYPASS2024\n",
    "dump.env": "".join(f"service{i}_password = DumpSecret{i}000\n" for i in range(1, 7)),
}

NOISE = {
    "app.js": (
        'const task = "task-runner";\n'
        'const risk = "risk-report";\n'
        'const disk = "disk-usage";\n'
        "const password = process.env.PASSWORD;\n"
    ),
    "ci.yml": "password: ${{ secrets.DB_PASSWORD }}\nkey: ${{ secrets.AWS_KEY }}\n",
    "placeholder.py": (
        'password = "changeme"\n'
        'api_key = os.getenv("API_KEY")\n'
        'password = "${DB_PASSWORD}"\n'
    ),
}

EXCLUDED = {
    "bundle.min.js": 'password = "RealSecretInMinified"\n',
    "package-lock.json": '{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"}',
    "dist/app.js": 'password = "RealSecretInDist"\n',
    "build/out.py": 'password = "RealSecretInBuild"\n',
    "node_modules/pkg/index.js": 'password = "RealSecretInNodeModules"\n',
    ".git/config": 'password = "RealSecretInGit"\n',
}


def _write(root: Path, files: dict):
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def test_positive(tmp: Path):
    _write(tmp, SECRETS)
    (tmp / "creds.ini").write_bytes("password=Utf16Secret99\n".encode("utf-16"))

    findings = api.scan_dlp(str(tmp))
    by_file = {}
    for f in findings:
        by_file.setdefault(Path(f["file"]).name, set()).add(f["type"])

    expected = {
        "app.py": {"password", "generic_api_key"},
        "config.yaml": {"password", "generic_api_key"},
        "config.json": {"generic_api_key"},
        "prod.env": {"password", "generic_api_key"},
        "upper.env": {"password"},
        "id_rsa": {"ssh_key"},
        "server.pem": {"ssh_key"},
        "docker-compose.yml": {"connection_string"},
        "creds.ini": {"password"},
        "shadow": {"password_hash"},
        "tokens.py": {"github", "openai", "google", "jwt"},
        "dump.env": {"password", "secret_dump"},
    }
    for name, types in expected.items():
        assert name in by_file, f"{name} не сканировался"
        missing = types - by_file[name]
        assert not missing, f"{name}: не найдено {missing}, есть {by_file[name]}"

    assert "aws_secret" in by_file["aws_credentials"], by_file["aws_credentials"]
    assert "aws_credentials" in by_file["aws_credentials"], by_file["aws_credentials"]

    # два одинаковых секрета в разных строках — две находки
    dup = [f for f in findings if f["file"].endswith("dup.env")]
    assert len(dup) == 2 and {f["line"] for f in dup} == {1, 2}, dup

    # пароль из заглавных букв и цифр — не имя константы
    upper = [f for f in findings if f["file"].endswith("upper.env")]
    assert len(upper) == 2, upper

    # заглушка — только имя константы с подчёркиванием; пароль из заглавных
    # букв и цифр секретом быть не перестаёт
    from core.modules.dlp.patterns import is_placeholder
    assert is_placeholder("API_KEY") is True
    assert is_placeholder("VULN-006") is True
    assert is_placeholder("PRODSECRET2024") is False
    assert is_placeholder("MYPASS2024") is False

    # YARA даёт реальный номер строки и значение
    shadow = next(f for f in findings if f["type"] == "password_hash")
    assert shadow["line"] == 1 and shadow["value"], shadow

    # каждая находка обогащена из базы знаний
    assert all(f.get("fix") for f in findings), [f for f in findings if not f.get("fix")]

    # сортировка: critical раньше high
    severities = [f["severity"] for f in findings]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert severities == sorted(severities, key=order.get), severities


def test_negative(tmp: Path):
    _write(tmp, NOISE)
    _write(tmp, EXCLUDED)
    (tmp / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    # текстовое расширение, но двоичное содержимое — отсекается при чтении
    (tmp / "fake.txt").write_bytes(b"\x00\x01\x02\x03")
    (tmp / "big.env").write_text("password = " + "a" * MAX_FILE_SIZE, encoding="utf-8")

    stats = {}
    findings = api.scan_dlp(str(tmp), stats=stats)

    assert findings == [], f"ложные срабатывания: {findings}"
    assert stats["skipped_binary"] == 1, stats
    assert stats["skipped_big"] == 1, stats
    assert stats["scanned"] == 3, stats  # только app.js, ci.yml, placeholder.py

    # минифицированные, lock-файлы и каталоги сборки не читаются вообще
    walked = {p.relative_to(tmp).as_posix() for p in walk_files(str(tmp))}
    for excluded in ("bundle.min.js", "package-lock.json", "logo.png",
                     "dist/app.js", "build/out.py", "node_modules/pkg/index.js",
                     ".git/config"):
        assert excluded not in walked, f"{excluded} не должен попадать в обход"
    # big.env отсекается по размеру при чтении, а не в обходе
    assert "big.env" in walked


def test_masking(tmp: Path):
    _write(tmp, {"app.py": SECRETS["app.py"]})

    findings = api.scan_dlp(str(tmp))
    dumped = api.generate_json_report(findings)
    assert "Sup3rSecret!" not in dumped
    assert all(f["secret"] for f in findings)

    full = api.scan_dlp(str(tmp), show_secrets=True)
    assert any(f["value"] == "Sup3rSecret!" for f in full), full

    # код-риски не маскируются
    code = run_scan(str(tmp))
    assert all("secret" in f for f in code)


def test_code_checks(tmp: Path):
    files = {
        "bad_sql.php": 'mysql_query("SELECT * FROM users WHERE id=" . $_GET[\'id\']);\n',
        "good_sql.php": '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");\n'
                        '$stmt->execute([$_GET["id"]]);\n',
        "bad_cmd.php": 'system("ping " . $_GET[\'host\']);\n',
        "good_cmd.php": 'system("ls -la");\n',
        "bad_cmd.py": 'import os\nos.system(input("cmd: "))\n',
        "good_cmd.py": 'import subprocess\nsubprocess.run(["ls"], check=True)\n',
        "session.php": 'setcookie("sid", md5(time()));\n',
    }
    _write(tmp, files)
    by_file = {}
    for f in run_scan(str(tmp)):
        by_file.setdefault(Path(f["file"]).name, set()).add(f["type"])

    assert "sql_injection" in by_file.get("bad_sql.php", set()), by_file
    assert "sql_injection" not in by_file.get("good_sql.php", set()), by_file
    assert "command_injection" in by_file.get("bad_cmd.php", set()), by_file
    assert "command_injection" not in by_file.get("good_cmd.php", set()), by_file
    assert "command_injection" in by_file.get("bad_cmd.py", set()), by_file
    assert "command_injection" not in by_file.get("good_cmd.py", set()), by_file
    assert "weak_session_id" in by_file.get("session.php", set()), by_file


GIT_ENV = {
    "GIT_AUTHOR_NAME": "Test Author",
    "GIT_AUTHOR_EMAIL": "author@example.com",
    "GIT_COMMITTER_NAME": "Test Author",
    "GIT_COMMITTER_EMAIL": "author@example.com",
}


def _git(repo: Path, *args, env=None) -> str:
    import subprocess
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, encoding="utf-8",
        env={**os.environ, **GIT_ENV, **(env or {})},
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _commit(repo: Path, files: dict, message: str, date: str) -> str:
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    env = {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
    _git(repo, "commit", "-m", message, env=env)
    return _git(repo, "rev-parse", "HEAD").strip()


def test_git_history(tmp: Path):
    import shutil
    from core.modules.dlp.git_history import is_git_repo, scan_git_history

    if shutil.which("git") is None:
        print("  (git не установлен — тест истории пропущен)")
        return

    repo = tmp / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Test Author")
    _git(repo, "config", "user.email", "author@example.com")

    first = _commit(repo, {
        "app.py": 'password = "HistSecret123"\n',
        "gone.py": 'password = "GoneSecret42"\n',
        "src/deep.py": 'password = "DeepSecret77"\n',
    }, "add config", "2024-01-01T10:00:00")
    _commit(repo, {"gone.py": None}, "remove old file", "2024-02-01T10:00:00")
    _commit(repo, {"node_modules/pkg/index.js": 'const password = "NodeSecret123";\n'},
            "vendor dump", "2024-03-01T10:00:00")
    _commit(repo, {"current.env": "DB_PASSWORD=StillHere123\n"}, "keep another one",
            "2024-04-01T10:00:00")
    _commit(repo, {"gone.py": 'password = "GoneSecret42"\n'}, "bring it back",
            "2024-05-01T10:00:00")
    _commit(repo, {"gone.py": None}, "remove again", "2024-06-01T10:00:00")
    head = _git(repo, "rev-parse", "HEAD").strip()

    assert is_git_repo(str(repo))

    stats = {}
    findings = scan_git_history(str(repo), stats=stats)
    by_file = {(f["file"], f["type"]): f for f in findings}

    # секрет, которого уже нет в коде, найден в истории
    secret = by_file[("gone.py", "password")]
    assert secret["value"] == "GoneSecret42"
    assert secret["commit_full"] == first, (secret["commit_full"], first)
    assert secret["date"] == "2024-01-01", secret
    assert secret["commits"] == 2, secret
    assert secret["source"] == "git" and secret["author"] == "Test Author"
    assert secret["line"] == 1

    # из node_modules история тоже не читается
    assert not any(path.startswith("node_modules/") for path, _ in by_file), by_file

    assert stats["git_commits"] == 6, stats
    assert stats["git_error"] is None

    # абсолютный путь вне репозитория — честная ошибка, а не тишина
    outside = tmp / "plain"
    outside.mkdir(parents=True, exist_ok=True)
    stats = {}
    assert scan_git_history(str(outside), stats=stats) == []
    assert "не git-репозиторий" in stats["git_error"], stats

    # глубина ограничивает число коммитов: последний коммит только удаляет файл
    assert scan_git_history(str(repo), depth=1, stats={}) == []

    # при скане подпапки в отчёт не попадает история чужих каталогов
    inside = scan_git_history(str(repo / "src"), stats={})
    assert [(f["file"], f["value"]) for f in inside] == [("src/deep.py", "DeepSecret77")], inside

    # api: в рабочем каталоге секрета нет, а с --git он находится
    fs_only = api.scan_dlp(str(repo))
    assert not any(str(f.get("file", "")).endswith("gone.py") for f in fs_only), fs_only

    stats = {}
    with_git = api.scan_dlp(str(repo), git=True, stats=stats)
    hist = next(f for f in with_git if f.get("file") == "gone.py")
    assert hist["value"].startswith("Gone…"), hist
    assert hist["commit"] == first[:12]
    assert hist["commits"] == 2
    assert stats["git_commits"] == 6

    full = api.scan_dlp(str(repo), git=True, show_secrets=True)
    assert any(f.get("value") == "GoneSecret42" for f in full)

    # секрет, который до сих пор в файле, не дублируется
    current = [f for f in with_git if str(f.get("file", "")).endswith("current.env")]
    assert len(current) == 1, current
    assert current[0]["also_in_git"] is True
    assert current[0]["commits"] == 1

    # текстовый отчёт показывает коммит
    text = api.generate_text_report(with_git)
    assert "Commit" in text and first[:12] in text, text

    # история после HEAD не теряется при повторном коммите
    assert _git(repo, "rev-parse", "HEAD").strip() == head


def test_yara_and_errors(tmp: Path):
    from core.modules.dlp import yara_scanner
    assert yara_scanner.rules_failed() is False
    assert yara_scanner._load_rules() is yara_scanner._load_rules()

    # YARA принимает уже прочитанные байты, файл не читается второй раз
    tmp.mkdir(parents=True, exist_ok=True)
    sample = tmp / "netrc"
    sample.write_text("machine example.com login user password NetrcSecret1\n", encoding="utf-8")
    findings = yara_scanner.run_yara(sample, sample.read_bytes())
    assert [f.type for f in findings] == ["password"], findings

    # несуществующий путь — ошибка, stats не ломается
    result = run_scan(str(tmp / "nope"))
    assert "error" in result[0]


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        test_positive(Path(d) / "secrets")
    with tempfile.TemporaryDirectory() as d:
        test_negative(Path(d) / "noise")
    with tempfile.TemporaryDirectory() as d:
        test_masking(Path(d) / "mask")
    with tempfile.TemporaryDirectory() as d:
        test_yara_and_errors(Path(d) / "yara")
    with tempfile.TemporaryDirectory() as d:
        test_code_checks(Path(d) / "code")
    with tempfile.TemporaryDirectory() as d:
        test_git_history(Path(d) / "git")
    print("OK: DLP-проверки пройдены")
