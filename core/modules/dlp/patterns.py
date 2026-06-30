API_TOKEN_PATTERNS = {
    "aws_key":    r'AKIA[0-9A-Z]{16}',
    "aws_secret": r'(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}',
    "github":     r'ghp_[A-Za-z0-9]{36}',
    "openai":     r'sk-[A-Za-z0-9]{48}',
    "telegram":   r'\d{8,10}:[A-Za-z0-9_-]{35}',
    "jwt":        r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
}

SSH_PATTERNS = [
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
]

PASSWORD_PATTERNS = [
    r'(?i)(password|passwd|pwd)\s*=\s*["\']?[^\s"\']{6,}',
    r'(?i)(secret|api_key|apikey|token)\s*=\s*["\']?[^\s"\']{6,}',
]

PASSWORD_EXCLUSIONS = ["", "None", "null", "your_password_here", "<password>"]

COMMAND_INJECTION_PATTERNS = [
    r'(system|exec|shell_exec|passthru|popen)\s*\(\s*[\'"]?.*\$\w+',
    r'os\.system\s*\(\s*input\s*\(',
]

SQL_INJECTION_PATTERNS = [
    r'(mysql_query|mysqli_query|->query)\s*\(.*\$\w+',
    r'SELECT.*\$\w+',
    r'(SELECT|INSERT|UPDATE|DELETE).*\$_(GET|POST|REQUEST)',
]

WEAK_SESSION_PATTERNS = [
    r'md5\s*\(\s*(time\(\)|rand\(|mt_rand\()',   # md5 от предсказуемого значения
    r'sha1\s*\(\s*(time\(\)|rand\(|mt_rand\()',  # sha1 от предсказуемого значения
    r'setcookie\s*\(.*\b(rand\(|mt_rand\(|time\()',  # cookie с предсказуемым значением
    r'=\s*rand\(\s*\)',                          # просто голый rand() без засева
    r'=\s*mt_rand\(\s*\)',                       # mt_rand() без аргументов — максимально предсказуем
]