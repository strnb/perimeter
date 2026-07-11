"""
config.py — параметры таргета для web_scanner.
"""
from dataclasses import dataclass, field
from typing import Optional, Dict


@dataclass
class WebTarget:
    name: str
    xss_path: str
    xss_param: str
    csrf_path: str
    login_path: Optional[str]
    login_user_param: str
    login_pass_param: str
    login_submit_param: Optional[str]
    upload_path: Optional[str]
    upload_file_param: Optional[str]
    redirect_path: Optional[str]
    redirect_param: Optional[str]

    # --- Авторизация (общие поля для DVWA и реальных сайтов) ---
    username: Optional[str] = None
    password: Optional[str] = None
    # Подстрока в HTML, которая появляется ТОЛЬКО после успешного входа.
    # Если не задано — используется эвристика "форма логина больше не отображается".
    login_success_marker: Optional[str] = None
    # Доп. шаг после логина (например, security.php у DVWA). Опционально.
    post_login_path: Optional[str] = None
    post_login_data: Optional[Dict[str, str]] = None


DVWA = WebTarget(
    name="DVWA",
    xss_path="/vulnerabilities/xss_r/",
    xss_param="name",
    csrf_path="/vulnerabilities/csrf/",
    login_path="/login.php",
    login_user_param="username",
    login_pass_param="password",
    login_submit_param="Login",
    upload_path="/vulnerabilities/upload/",
    upload_file_param="uploaded",
    redirect_path="/vulnerabilities/redirect/",
    redirect_param="redirect",
    username="admin",
    password="password",
    login_success_marker="logout.php",
    post_login_path="/security.php",
    post_login_data={"security": "low", "seclev_submit": "Submit"},
)

GENERIC = WebTarget(
    name="Generic",
    xss_path="/search",
    xss_param="q",
    csrf_path="/account/settings",
    login_path="/login",
    login_user_param="username",
    login_pass_param="password",
    login_submit_param=None,
    upload_path=None,
    upload_file_param=None,
    redirect_path="/redirect",
    redirect_param="url",
    # username/password для GENERIC не заданы по умолчанию —
    # значит сканер просто не будет логиниться (неавторизованный скан).
    # Если нужен авторизованный скан реального сайта — заполняете эти поля
    # (руками или из UI формы "креды для скана") перед запуском.
)

ACTIVE_PROFILE = DVWA
