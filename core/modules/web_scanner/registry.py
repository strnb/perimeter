from core.modules.web_scanner import (
    brute_force,
    csrf_check,
    file_upload,
    open_redirect,
    xss_check,
)
from core.modules.web_scanner.types import WebCheck

CHECKS: list[WebCheck] = [
    brute_force.CHECK,
    csrf_check.CHECK,
    xss_check.CHECK,
    file_upload.CHECK,
    open_redirect.CHECK,
]
