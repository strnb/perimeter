async def run_web_assessment(
    target_ip: str,
    port: int,
    cookies: Optional[Dict[str, str]] = None,
):
    """
    Главная точка входа Web Scanner.
    """

    scheme = "https" if port == 443 else "http"

    base_url = f"{scheme}://{target_ip}:{port}"

    async with httpx.AsyncClient(
        cookies=cookies,
        follow_redirects=False,
        verify=False,
    ) as client:

        logger.info(
            "[Web Scanner] Запуск %s модулей для %s",
            len(CHECKS),
            base_url,
        )

        findings = await _run_checks(
            client,
            base_url,
        )

    return _serialize_findings(findings)