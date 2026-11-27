"""Тесты OSINT: python tests/test_osint.py (assert'ы, без сети и pytest)."""
import asyncio
import contextlib
import io
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
from dns.rdataclass import IN
from dns.rdatatype import A, AAAA, CAA, CNAME, DS, MX, NS, SOA, TXT
from dns.rdata import from_text

import api
import cli
import database
from core.modules.scanner import osint_checks as checks
from core.modules.scanner.osint import (
    get_crtsh,
    normalize_domain,
    run_osint,
)


def rd(rtype, text):
    return from_text(IN, rtype, text)


class FakeDNS:
    def __init__(self, records):
        self.records = records
        self.names = {name for name, _rtype in records}

    async def query_status(self, name, rtype):
        records = self.records.get((name, rtype), [])
        return records, name in self.names

    async def query(self, name, rtype):
        return self.records.get((name, rtype), [])


class FakeWhois:
    registrar = "REG.RU"
    org = "Example LLC"
    creation_date = datetime(2011, 3, 4)
    expiration_date = datetime.now() + timedelta(days=400)
    updated_date = datetime(2024, 1, 1)
    status = ["clientTransferProhibited"]
    name_servers = ["NS1.EXAMPLE.COM", "ns2.example.com"]


def make_dns():
    return FakeDNS({
        ("example.com", "A"): [rd(A, "93.184.216.34")],
        ("example.com", "MX"): [rd(MX, "10 mail.example.com.")],
        ("example.com", "TXT"): [rd(TXT, '"v=spf1 include:_spf.google.com ~all"')],
        ("example.com", "NS"): [rd(NS, "ns1.example.com."), rd(NS, "ns2.example.com.")],
        ("example.com", "SOA"): [rd(SOA, "ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300")],
        ("example.com", "CAA"): [rd(CAA, '0 issue "letsencrypt.org"')],
        ("_dmarc.example.com", "TXT"): [rd(TXT, '"v=DMARC1; p=none; rua=mailto:dmarc@example.com"')],
        ("selector1._domainkey.example.com", "TXT"): [rd(TXT, '"v=DKIM1; k=rsa; p=AAAA"')],
        ("www.example.com", "A"): [rd(A, "93.184.216.34")],
        ("admin.example.com", "A"): [rd(A, "93.184.216.34")],
        ("old.example.com", "CNAME"): [rd(CNAME, "old.herokuapp.com.")],
    })


def make_http():
    def handler(request):
        host = request.url.host
        if host == "crt.sh":
            return httpx.Response(200, json=[
                {"name_value": "www.example.com\n*.api.example.com"},
                {"name_value": "admin.example.com"},
                {"name_value": "old.example.com"},
                {"name_value": "evil.com"},
                {"common_name": "EXAMPLE.COM"},
            ])
        if host == "admin.example.com":
            return httpx.Response(200, text="<html><title>Grafana</title></html>")
        if host == "old.example.com":
            return httpx.Response(404, text="No such app")
        raise httpx.ConnectError("no route")

    return httpx.AsyncClient(transport=httpx.MockTransport(handler), verify=False)


async def fake_axfr(domain, name_servers):
    return "VULNERABLE: ns1.example.com"


def test_normalize_domain():
    assert normalize_domain("Example.COM.") == "example.com"
    assert normalize_domain("https://www.example.com/path?q=1") == "example.com"
    assert normalize_domain("example.com:8443") == "example.com"
    assert normalize_domain("  EXAMPLE.com  ") == "example.com"
    assert normalize_domain("пример.рф") == "xn--e1afmkfd.xn--p1ai"

    for bad in ("", "localhost", "not a domain", "example", "http://", "-bad.com", "a..b.com"):
        try:
            normalize_domain(bad)
            raise AssertionError(f"должно отклоняться: {bad!r}")
        except ValueError:
            pass


def test_spf_dmarc():
    # нет SPF
    data, findings = checks.analyze_spf([])
    assert any(f["type"] == "spf_missing" for f in findings), findings

    # +all — critical
    data, findings = checks.analyze_spf(["v=spf1 +all"])
    assert data["policy"] == "+all"
    assert any(f["severity"] == "critical" for f in findings), findings

    # ?all — medium
    _, findings = checks.analyze_spf(["v=spf1 ?all"])
    assert any(f["type"] == "spf_neutral" for f in findings), findings

    # -all и один include — чисто
    data, findings = checks.analyze_spf(["v=spf1 include:_spf.google.com -all"])
    assert data["policy"] == "-all" and data["lookups"] == 1
    assert findings == [], findings

    # несколько SPF-записей
    _, findings = checks.analyze_spf(["v=spf1 -all", "v=spf1 ~all"])
    assert any(f["type"] == "spf_multiple" for f in findings), findings

    # слишком много lookup
    many = "v=spf1 " + " ".join(f"include:{i}.example.com" for i in range(12)) + " -all"
    _, findings = checks.analyze_spf([many])
    assert any(f["type"] == "spf_too_many_lookups" for f in findings), findings

    # DMARC
    _, findings = checks.analyze_dmarc([])
    assert any(f["type"] == "dmarc_missing" for f in findings), findings

    data, findings = checks.analyze_dmarc(["v=DMARC1; p=none"])
    assert data["policy"] == "none"
    assert any(f["type"] == "dmarc_none" for f in findings), findings

    data, findings = checks.analyze_dmarc(["v=DMARC1; p=reject"])
    assert data["policy"] == "reject" and findings == []


def test_security_and_takeover():
    _, findings = checks.analyze_security([], [], "not_checked")
    types = {f["type"] for f in findings}
    assert types == {"dnssec_disabled", "caa_missing"}, types

    _, findings = checks.analyze_security(["12345 8 2 AB"], ['0 issue "ca.example"'],
                                          "VULNERABLE: ns1.example.com")
    assert [f["type"] for f in findings] == ["dns_zone_transfer"], findings

    assert checks.takeover_provider("old.herokuapp.com") == "Heroku"
    assert checks.takeover_provider("x.github.io") == "GitHub Pages"
    assert checks.takeover_provider("example.com") is None
    assert checks.takeover_provider(None) is None

    assert checks.is_takeover_candidate("old.herokuapp.com", 404, "No such app")
    assert not checks.is_takeover_candidate("old.herokuapp.com", 200, "Welcome")
    assert not checks.is_takeover_candidate("cdn.example.com", 404, "No such app")


def test_crtsh_parsing():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=[
        {"name_value": "A.Example.com\n*.b.example.com"},
        {"name_value": "example.com"},
        {"name_value": "notexample.com"},
    ]))

    async def run():
        async with httpx.AsyncClient(transport=transport) as client:
            return await get_crtsh("example.com", client)

    names, status = asyncio.run(run())
    assert names == ["a.example.com", "b.example.com"], names
    assert status == "crt.sh: 2"

    # сервис недоступен — это статус, а не исключение
    async def fail():
        async with httpx.AsyncClient(transport=httpx.MockTransport(
                lambda request: httpx.Response(502))) as client:
            return await get_crtsh("example.com", client)

    names, status = asyncio.run(fail())
    assert names == [] and "502" in status, status


def test_full_report(tmp: Path):
    cache = tmp / "cache"
    http = make_http()

    async def run(**kwargs):
        return await run_osint(
            "example.com",
            whois_func=lambda domain: FakeWhois(),
            dns_client=make_dns(),
            http_client=http,
            axfr_func=fake_axfr,
            cache_dir=cache,
            **kwargs,
        )

    report = asyncio.run(run(active=True))
    asyncio.run(http.aclose())

    assert report["domain"] == "example.com"
    assert report["whois"]["registrar"] == "REG.RU"
    assert report["whois"]["expires_in_days"] > 0
    assert report["dns"]["A"] == ["93.184.216.34"]
    assert report["dns"]["MX"] == ["10 mail.example.com"]
    assert report["security"]["dnssec"] is False
    assert report["security"]["zone_transfer"] == "VULNERABLE: ns1.example.com"

    names = {sub["subdomain"] for sub in report["subdomains"]}
    assert {"www.example.com", "admin.example.com", "old.example.com"} <= names, names
    assert "evil.com" not in names

    admin = next(sub for sub in report["subdomains"] if sub["subdomain"] == "admin.example.com")
    assert admin["http"]["title"] == "Grafana"

    old = next(sub for sub in report["subdomains"] if sub["subdomain"] == "old.example.com")
    assert old["cname"] == "old.herokuapp.com"
    assert old["takeover"] is True

    types = {finding["type"] for finding in report["findings"]}
    assert {"dmarc_none", "dnssec_disabled", "dns_zone_transfer",
            "admin_panel_exposed", "subdomain_takeover"} <= types, types
    assert all(finding["fix"] for finding in report["findings"])

    # кэш: второй вызов не идёт в сеть и говорит об этом
    async def cached_run():
        return await run_osint(
            "example.com",
            whois_func=lambda domain: FakeWhois(),
            dns_client=make_dns(),
            http_client=None,
            cache_dir=cache,
            active=True,
        )

    cached_report = asyncio.run(cached_run())
    assert cached_report["cached"] is True
    assert cached_report["domain"] == "example.com"


def test_errors_and_fallbacks():
    # несуществующий домен: DNS пуст, WHOIS упал -> понятная ошибка
    class BrokenWhois:
        pass

    def broken(domain):
        raise RuntimeError("whois is down")

    async def run():
        return await run_osint(
            "example.com",
            whois_func=broken,
            dns_client=FakeDNS({}),
            use_cache=False,
        )

    try:
        asyncio.run(run())
        raise AssertionError("должна быть ошибка про нерезолвящийся домен")
    except ValueError as exc:
        assert "не резолвится" in str(exc), exc

    # кривой домен — ValueError из normalize
    try:
        asyncio.run(run_osint("не домен"))
        raise AssertionError("должен быть ValueError")
    except ValueError:
        pass


def test_database(tmp: Path):
    database.DB_PATH = str(tmp / "osint.db")

    # старая схема без новых колонок
    conn = sqlite3.connect(database.DB_PATH)
    conn.execute("""CREATE TABLE osint_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_time TEXT, target_domain TEXT,
        registrar TEXT, subdomains_count INTEGER)""")
    conn.commit()
    conn.close()

    database.init_db()
    conn = sqlite3.connect(database.DB_PATH)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(osint_results)")}
    conn.close()
    assert {"expires_at", "findings_count"} <= columns, columns

    subdomains = [
        {"subdomain": "www.example.com", "ips": ["1.2.3.4"], "cname": None,
         "source": "wordlist", "http": {"status": 200, "title": "Home"}},
        {"subdomain": "old.example.com", "ips": ["1.2.3.4"], "cname": "old.herokuapp.com",
         "source": "passive", "http": {"status": 404, "title": ""}},
    ]
    database.save_osint_result("2026-01-01", "example.com", "REG.RU", 2,
                               expires_at="2027-01-01", findings_count=3,
                               subdomains=subdomains)
    names = database.get_previous_osint_subdomains("example.com")
    assert names == {"www.example.com", "old.example.com"}, names
    assert database.get_previous_osint_subdomains("other.com") == set()

    conn = sqlite3.connect(database.DB_PATH)
    row = conn.execute("SELECT expires_at, findings_count FROM osint_results").fetchone()
    conn.close()
    assert row == ("2027-01-01", 3), row


def test_http_probe_limit():
    from core.modules.scanner import osint as osint_module

    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, text="<title>ok</title>")

    subs = [{"subdomain": f"s{i}.example.com"} for i in range(osint_module.MAX_HTTP_PROBES + 50)]

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), verify=False) as client:
            await osint_module._http_inventory(subs, client)

    asyncio.run(run())
    assert len(calls) == osint_module.MAX_HTTP_PROBES, len(calls)
    # последние 50 имён остались без HTTP-данных, но не потеряны из отчёта
    assert len(subs) == osint_module.MAX_HTTP_PROBES + 50
    assert "http" in subs[0] and "http" not in subs[-1]


def test_cli(tmp: Path):
    database.DB_PATH = str(tmp / "cli.db")
    database.init_db()

    report = {
        "domain": "example.com",
        "scan_time": "2026-01-01 00:00:00",
        "duration_sec": 1.2,
        "sources": {"whois": "ok", "dns": "ok", "crt.sh": "crt.sh: 2"},
        "whois": {"registrar": "REG.RU", "expiration_date": "2027-01-01",
                  "expires_in_days": 400, "name_servers": ["ns1.example.com"],
                  "creation_date": "2011-03-04", "age_days": 5000, "status": []},
        "dns": {"A": ["93.184.216.34"], "MX": ["10 mail.example.com"]},
        "email": {"spf": {"record": "v=spf1 -all", "lookups": 0},
                  "dmarc": {"policy": "reject"}, "dkim": ["selector1"]},
        "security": {"dnssec": True, "caa": True, "zone_transfer": "failed"},
        "subdomains": [
            {"subdomain": "www.example.com", "ip": "93.184.216.34", "ips": ["93.184.216.34"],
             "source": "wordlist", "http": {"status": 200, "title": "Home"}},
        ],
        "findings": [{"kb_id": "VULN-044", "type": "dmarc_none", "severity": "medium",
                      "title": "DMARC в режиме мониторинга", "detail": "p=none", "fix": "p=reject"}],
    }

    original = api.run_osint_report

    async def fake(domain, **options):
        return report

    api.run_osint_report = fake
    try:
        json_path = tmp / "out.json"
        args = cli.build_parser().parse_args(
            ["osint", "example.com", "--json", str(json_path)])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.cmd_osint(args)
        text = out.getvalue()
    finally:
        api.run_osint_report = original

    assert code == 0, text
    assert "WHOIS" in text and "ПОДДОМЕНЫ" in text and "НАХОДКИ" in text, text
    assert "www.example.com" in text
    assert json_path.exists() and "example.com" in json_path.read_text(encoding="utf-8")
    assert database.get_previous_osint_subdomains("example.com") == {"www.example.com"}

    # второй запуск видит новый поддомен
    report["subdomains"].append({"subdomain": "new.example.com", "ips": [], "source": "passive"})
    api.run_osint_report = fake
    try:
        args = cli.build_parser().parse_args(["osint", "example.com"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.cmd_osint(args)
    finally:
        api.run_osint_report = original
    assert "новых с прошлого скана: 1" in out.getvalue(), out.getvalue()

    # неизвестный источник — код 2, без сети
    args = cli.build_parser().parse_args(["osint", "example.com", "--sources", "shodan"])
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert cli.cmd_osint(args) == 2
    assert "Неизвестные источники" in out.getvalue()


if __name__ == "__main__":
    test_normalize_domain()
    test_spf_dmarc()
    test_security_and_takeover()
    test_crtsh_parsing()
    test_errors_and_fallbacks()
    with tempfile.TemporaryDirectory() as d:
        test_full_report(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_database(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_cli(Path(d))
    test_http_probe_limit()
    print("OK: OSINT-проверки пройдены")
