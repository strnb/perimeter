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