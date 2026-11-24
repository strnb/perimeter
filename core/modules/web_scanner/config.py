"""
config.py — параметры таргета для web_scanner.
Позволяет переключаться между DVWA и любым реальным сайтом
без правки кода плагинов.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class WebTarget:
    name: str
    xss_path: str
    xss_param: str
    csrf_path: str
    login_path: str
    login_user_param: str
    login_pass_param: str
    login_submit_param: Optional[str]
    upload_path: Optional[str]
    upload_file_param: Optional[str]
    redirect_path: Optional[str]
    redirect_param: Optional[str]


DVWA = WebTarget(
    name="DVWA",
    xss_path="/vulnerabilities/xss_r/",
    xss_param="name",
    csrf_path="/vulnerabilities/csrf/",
    login_path="/vulnerabilities/brute/",
    login_user_param="username",
    login_pass_param="password",
    login_submit_param="Login",
    upload_path="/vulnerabilities/upload/",
    upload_file_param="uploaded",
    redirect_path="/vulnerabilities/redirect/",
    redirect_param="redirect",
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
)

ACTIVE_PROFILE = DVWA