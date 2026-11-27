"""Шаблоны поиска секретов и опасного кода.

Токены заданы парами (regex, severity, kb_id); значение всегда в группе value
или в группе 1 — детекторы берут именно его, а не всю строку.
"""

import re

TOKEN_PATTERNS = {
    "aws_key":      (r'\b(AKIA[0-9A-Z]{16})\b', "critical", "VULN-007"),
    "aws_secret":   (r'(?i)aws_secret_access_key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})', "critical", "VULN-007"),
    "github":       (r'\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})\b', "critical", "VULN-007"),
    "gitlab":       (r'\b(glpat-[A-Za-z0-9_-]{20,})\b', "critical", "VULN-007"),
    "openai":       (r'\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b', "critical", "VULN-007"),
    "stripe":       (r'\b([sr]k_live_[0-9a-zA-Z]{20,})\b', "critical", "VULN-007"),
    "slack":        (r'(xox[baprs]-[A-Za-z0-9-]{10,}|https://hooks\.slack\.com/services/[A-Za-z0-9/]+)',
                     "critical", "VULN-007"),
    "google":       (r'\b(AIza[0-9A-Za-z_-]{35})\b', "critical", "VULN-007"),
    "sendgrid":     (r'\b(SG\.[\w-]{22}\.[\w-]{43})\b', "critical", "VULN-007"),
    "npm":          (r'\b(npm_[A-Za-z0-9]{36})\b', "critical", "VULN-007"),
    "digitalocean": (r'\b(dop_v1_[a-f0-9]{64})\b', "critical", "VULN-007"),
    "telegram":     (r'\b(\d{8,10}:[A-Za-z0-9_-]{35})\b', "critical", "VULN-007"),
    # Только настоящий JWT: три base64url-сегмента, а не любой eyJ в base64
    "jwt":          (r'\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b',
                     "high", "VULN-007"),
}

# Приватные ключи: заголовок однозначен, поэтому regex, а не YARA
SSH_PATTERNS = [
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "PuTTY-User-Key-File",
]

# (regex, тип, severity, kb_id); значение — именованная группа value
PASSWORD_RULES = [
    (re.compile(r'(?i)(?<![A-Za-z0-9])(?:password|passwd|pwd|passphrase)\b["\']?\s*[:=]\s*'
                r'["\']?(?P<value>[^\s"\']{6,})'),
     "password", "high", "VULN-006"),
    (re.compile(r'(?i)(?<![A-Za-z0-9])(?:secret|client[_-]?secret|api[_-]?key|apikey|'
                r'(?:auth|access|api)?[_-]?token)\b["\']?\s*[:=]\s*'
                r'["\']?(?P<value>[^\s"\']{12,})'),
     "generic_api_key", "high", "VULN-007"),
]

PASSWORD_EXCLUSIONS = {
    "", "none", "null", "undefined", "true", "false", "password", "passwd", "pass", "secret",
    "your_password_here", "<password>", "changeme", "change_me", "placeholder", "redacted",
}

# Строка подключения с паролем: postgres://user:pass@host/db
CONNECTION_PATTERN = re.compile(
    r'\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|amqps|ftp|smtp)'
    r'://[^:\s/@]+:(?P<value>[^@\s"\']+)@[^\s"\']+',
    re.IGNORECASE,
)


def is_placeholder(value: str) -> bool:
    """Отсекает заготовки и подстановки из окружения — это не утёкший секрет."""
    v = value.strip().strip("\"'").rstrip(";,)]")
    low = v.lower()

    if not v or low in PASSWORD_EXCLUSIONS:
        return True
    # хеши паролей начинаются с $ — их ищет YARA, паролем считать нельзя
    if v.startswith(("$", "${", "{{", "<", "%", "os.getenv", "process.env", "env.")):
        return True
    # выражения кода: getenv(...), request.json(...), ENV["..."]
    if re.match(r'^[\w.]+\s*[\(\[]', v):
        return True
    if low.startswith(("your_", "example", "dummy", "sample", "placeholder", "redacted",
                       "changeme", "change_me", "xxx", "todo")):
        return True
    # VULN-006, API_KEY — имя константы, а не значение секрета
    if re.fullmatch(r'[A-Z][A-Z0-9_-]{2,}', v):
        return True
    return not re.search(r'\w', v)


COMMAND_INJECTION_PATTERNS = [
    r'(system|exec|shell_exec|passthru|popen)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)',
    r'(system|exec|shell_exec|passthru|popen)\s*\([^;]*\binput\s*\(',
    r'os\.(system|popen)\s*\([^;]*\binput\s*\(',
    r'(system|exec|shell_exec|passthru|popen)\s*\([^;]*["\']\s*\.\s*\$',
]

SQL_INJECTION_PATTERNS = [
    r'(mysql_query|mysqli_query|pg_query|->query)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)',
    r'(mysql_query|mysqli_query|pg_query|->query)\s*\([^;]*["\']\s*\.\s*\$',
    r'(SELECT|INSERT|UPDATE|DELETE)\b[^;]*\$_(GET|POST|REQUEST|COOKIE)',
]

WEAK_SESSION_PATTERNS = [
    r'md5\s*\(\s*(time\(\)|rand\(|mt_rand\()',   # md5 от предсказуемого значения
    r'sha1\s*\(\s*(time\(\)|rand\(|mt_rand\()',  # sha1 от предсказуемого значения
    r'setcookie\s*\(.*\b(rand\(|mt_rand\(|time\()',  # cookie с предсказуемым значением
    r'=\s*rand\(\s*\)',                          # просто голый rand() без засева
    r'=\s*mt_rand\(\s*\)',                       # mt_rand() без аргументов — максимально предсказуем
]
