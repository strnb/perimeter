# Справочник

Полное описание CLI: команды, флаги, коды возврата, лимиты, форматы данных.
Сценарии — в [usage.md](usage.md), внутреннее устройство — в
[architecture.md](architecture.md).

Справка по любой команде доступна из самого инструмента:

```bash
perimeter -h
perimeter <команда> -h
perimeter vault <действие> -h
```

---

## Общие правила

```
perimeter <команда> [аргументы] [флаги]
```

- `-h`, `--help` работают на любом уровне.
- Неизвестная команда: печатается подсказка с ближайшим совпадением, код `2`.
- Вывод — UTF-8; на Windows stdout переключается в UTF-8, чтобы кириллица и
  баннеры корректно писались в файл.
- Отчёты `--report` создаются в `./reports` текущей директории.
- Все результаты (кроме `--json`/`--report`) автоматически пишутся в локальную
  историю SQLite.

### Коды возврата

| Код | Значение |
|---|---|
| `0` | успех (в том числе «находок нет») |
| `1` | ошибка выполнения: неверный путь, недоступная цель, потерян `.salt` |
| `2` | неверные аргументы, неизвестная команда или неизвестный источник |
| `130` | прервано с клавиатуры (Ctrl+C) |

### Переменные окружения

| Переменная | Действие |
|---|---|
| `PERIMETER_WORDLIST` | путь к словарю поддоменов по умолчанию |
| `SHELL` | используется `completion` для выбора bash/zsh |

### Где хранятся данные

| Что | Репозиторий / `pip install -e .` | Обычный `pip install .` |
|---|---|---|
| История | `./perimeter.db` | `~/.perimeter/perimeter.db` |
| Vault | `./vault/` | `~/.perimeter/vault/` |
| Кэш OSINT | `~/.perimeter/cache/osint/` | `~/.perimeter/cache/osint/` |
| Отчёты | `./reports/` | `./reports/` |
| PDF по умолчанию | `./perimeter_report.pdf` | `./perimeter_report.pdf` |

Ресурсы (база знаний, шрифт, словарь, YARA-правила) ищутся сначала в
репозитории, затем в `<prefix>/share/perimeter/` после установки.

---

## `perimeter dlp`

```
perimeter dlp PATH [--report] [--show-secrets] [--git] [--git-depth N]
```

| Аргумент / флаг | Описание |
|---|---|
| `PATH` | папка для сканирования |
| `--report` | сохранить JSON и TXT в `./reports` |
| `--show-secrets` | не маскировать значения в выводе и отчётах |
| `--git` | проверить историю git |
| `--git-depth N` | сколько последних коммитов (по умолчанию `1000`) |

### Типы находок DLP

| `type` | Severity | `kb_id` | Что найдено |
|---|---|---|---|
| `ssh_key` | critical | VULN-039 | приватный ключ: RSA, DSA, EC, OpenSSH, PKCS#8, encrypted, PGP, PuTTY |
| `aws_key` | critical | VULN-007 | `AKIA…` |
| `aws_secret` | critical | VULN-007 | `aws_secret_access_key = …` |
| `aws_credentials` | critical | VULN-007 | файл с парой access key + secret (YARA) |
| `github` | critical | VULN-007 | `ghp_…`, `github_pat_…` |
| `gitlab` | critical | VULN-007 | `glpat-…` |
| `openai` | critical | VULN-007 | `sk-…`, `sk-proj-…` |
| `stripe` | critical | VULN-007 | `sk_live_…`, `rk_live_…` |
| `slack` | critical | VULN-007 | `xox…`, webhook |
| `google` | critical | VULN-007 | `AIza…` |
| `sendgrid` | critical | VULN-007 | `SG.…` |
| `npm` | critical | VULN-007 | `npm_…` |
| `digitalocean` | critical | VULN-007 | `dop_v1_…` |
| `telegram` | critical | VULN-007 | `<id>:<token>` |
| `jwt` | high | VULN-007 | три base64url-сегмента |
| `password` | high | VULN-006 | `password: …`, `DB_PASSWORD=…` |
| `generic_api_key` | high | VULN-007 | `api_key`, `client_secret`, `auth_token` |
| `connection_string` | critical | VULN-040 | `postgres://user:pass@host`, `mysql://`, `mongodb://`, `redis://` и др. |
| `password_hash` | critical | VULN-041 | shadow, htpasswd (YARA) |
| `secret_dump` | high | VULN-042 | 5+ присваиваний секретов в файле (YARA) |
| `sql_injection` | critical | VULN-031 | SQL-запрос из `$_GET/$_POST` |
| `command_injection` | critical | VULN-032 | `system()/exec()` с пользовательским вводом |
| `weak_session_id` | high | VULN-033 | `md5(time())`, `rand()` для сессии |

Токены сгруппированы: один и тот же фрагмент не будет найден дважды как
конкретный токен и как `generic_api_key`.

### Что пропускается

Каталоги: `.git`, `.hg`, `.svn`, `node_modules`, `venv`, `.venv`, `env`,
`__pycache__`, `.mypy_cache`, `.pytest_cache`, `.tox`, `.idea`, `dist`, `build`,
`target`, `vendor`, `coverage`, `.next`, `.nuxt`, `*.egg-info`.

Файлы: lock-файлы (`package-lock.json`, `yarn.lock`, `poetry.lock`,
`Cargo.lock`, `go.sum`, `composer.lock`, `Pipfile.lock` и др.),
`*.min.js`, `*.min.css`, `*.map`, двоичные расширения (`.exe`, `.dll`, `.so`,
`.png`, `.jpg`, `.pdf`, `.zip`, `.jar`, `.pyc`, `.db`, …), `.yar`, файлы
больше 1 МБ, нечитаемые файлы.

После скана печатается, сколько файлов проверено и сколько пропущено
(бинарных / больших / нечитаемых).

### Маскировка

- по умолчанию: первые 4 символа + `…`, если значение длиннее 8 символов;
  иначе только `…`;
- маскируются только типы-секреты; код-риски (`sql_injection`,
  `command_injection`, `weak_session_id`) выводятся как есть;
- значения DLP в SQLite не пишутся вообще — только счётчики.

### История git

```
perimeter dlp . --git --git-depth 5000
```

- Читается `git log --all -p -U0 --no-merges --max-count=N`.
- Проверяются только **добавленные** строки.
- Поля находки: `commit` (12 символов), `commit_full`, `author`, `date`
  (`YYYY-MM-DD`), `subject`, `commits` (сколько коммитов содержат секрет),
  `also_in_git` (если секрет есть и в рабочем дереве).
- Указывается **самый старый** коммит — момент появления секрета.
- Исключения по путям те же, что для файлов; при скане подпапки история
  других каталогов не показывается.
- Ошибки (нет git, не репозиторий) не роняют скан: в `stats.git_error` и в
  выводе будет причина.

### Статистика (`stats` в Python API)

`scanned`, `skipped_binary`, `skipped_big`, `skipped_unreadable`,
`yara_failed`, `git_commits`, `git_lines`, `git_error`.

---

## `perimeter scan`

```
perimeter scan TARGET [--ports PORTS] [--report]
```

| Аргумент / флаг | Описание |
|---|---|
| `TARGET` | IP, домен или CIDR |
| `--ports` | `22,80,8000-8100`; по умолчанию 33 популярных порта |
| `--report` | JSON/TXT в `./reports` |

### Порты по умолчанию (33)

`21, 22, 23, 25, 53, 80, 111, 139, 443, 445, 512, 513, 514, 1099, 1524, 2049,
2121, 2181, 3306, 3632, 5432, 5900, 6000, 6200, 6379, 6667, 6697, 8009, 8080,
8180, 8443, 8787, 27017`

### Лимит

`len(hosts) × len(ports) > 65 536` → команда отклоняется до сетевых запросов.
Параллелизм — 100 задач на процесс.

### Сигнатуры

**По баннеру** (regex по содержимому баннера):

| Сигнатура | Severity | CVE / метка |
|---|---|---|
| `vsftpd 2.3.4` | critical | CVE-2011-2523 |
| `proftpd` | high | CVE-2010-4221 |
| `openssh 4.7` | medium | устаревшая версия |
| `samba 3.0` | critical | CVE-2007-2447 |
| `distcc` | critical | CVE-2004-2687 |
| `unreal` | critical | CVE-2010-2075 |

**По номеру порта** (баннер не нужен):

| Порт | Severity | Что |
|---|---|---|
| 1524 | critical | Ingreslock backdoor |
| 512/513/514 | critical | rexec/rlogin/rsh |
| 1099 | high | Java RMI |
| 8787 | high | Ruby DRb |
| 6000 | medium | X11 |
| 139/445 | high | SMB exposed |
| 6667/6697 | low | IRC exposed |

**Только при подтверждении активной проверкой** (в баннере есть `VULNERABLE`):

| Порт | Severity | Что |
|---|---|---|
| 8180 | high | Tomcat Manager: tomcat/tomcat |
| 5432 | medium | PostgreSQL: postgres/postgres |
| 6379 | critical | Redis без аутентификации |
| 27017 | critical | MongoDB без аутентификации |

**Требуют реального баннера** (иначе не считаются находкой): 21 FTP,
23 Telnet.

### Слабые пароли БД

Файлы `db_checker.py` используют необязательные драйверы:

```bash
pip install -e ".[db-checks]"   # pymongo, PyMySQL, psycopg2-binary
```

Без драйверов баннер порта содержит
`open (проверка слабых паролей недоступна: <причина>)` — это не ошибка скана.

### SMB

Ответ на SMB Negotiate означает, что протокол работает, а не что хост уязвим.
Баннер: `SMB Negotiate: <данные>`. Находка `SMB exposed` формируется по порту.

---

## `perimeter osint`

```
perimeter osint DOMAIN [--active] [--sources LIST] [--concurrency N]
                        [--wordlist PATH] [--no-cache] [--json PATH] [--report]
```

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--active` | выкл. | AXFR, HTTP/TLS-проба, панели, takeover |
| `--sources` | `crt,wordlist` | список через запятую: `crt`, `wordlist`, `hackertarget` |
| `--concurrency` | `50` | параллельные DNS-запросы |
| `--wordlist` | авто | путь к словарю поддоменов |
| `--no-cache` | выкл. | игнорировать кэш (TTL 24 ч) |
| `--json` | — | сохранить полный отчёт в указанный файл |
| `--report` | — | сохранить полный JSON в `./reports` |

### Домен

Принимается `example.com`, `www.example.com`, `https://example.com/path`,
`EXAMPLE.COM.`, `example.com:8443`, IDN (`пример.рф` → punycode). Не-домен
(`localhost`, `not a domain`) отклоняется с кодом `1`.

### Пассивный режим

- WHOIS: регистратор, организация, даты, возраст, срок, статусы, NS.
- DNS: `A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, DS` — все записи, не первая.
- crt.sh: сертификаты прозрачности, до 5 000 имён, 2 попытки при 502/таймауте.
- hackertarget: `api.hackertarget.com/hostsearch`, лимит около 100 запросов в
  сутки, только по флагу.
- Wordlist: встроенный (2 274 имени), SecLists из стандартных путей или
  `--wordlist` / `PERIMETER_WORDLIST`.
- Wildcard DNS: два случайных имени; имена, у которых все IP совпадают с
  wildcard, отбрасываются (кроме найденных пассивно).
- Почта: SPF, DMARC (`_dmarc`), DKIM (9 частых селекторов, пустой `p=`
  не считается ключом).
- Находки: SPF/DMARC/DNSSEC/CAA, срок домена.

### Активный режим

- AXFR по каждому NS, таймаут 5 с.
- HTTP-проба до 200 имён: сначала HTTPS, затем HTTP; тело до 200 КБ.
- Панели управления по `<title>`: Jenkins, Grafana, phpMyAdmin, GitLab,
  Kibana, Prometheus, Adminer, Jupyter, SonarQube, RabbitMQ, Portainer.
- Subdomain takeover: CNAME на 18 сервисов (Heroku, GitHub Pages, S3, Azure,
  CloudFront, Netlify, Vercel, Firebase, Shopify и др.) + маркер «приложения
  нет». Всегда формулируется как кандидат.

### Находки OSINT

| `type` | Severity | `kb_id` |
|---|---|---|
| `spf_missing` | high | VULN-043 |
| `spf_allow_all` | critical | VULN-043 |
| `spf_neutral`, `spf_no_all`, `spf_multiple`, `spf_too_many_lookups` | medium | VULN-043 |
| `dmarc_missing` | high | VULN-044 |
| `dmarc_none`, `dmarc_no_policy` | medium | VULN-044 |
| `dnssec_disabled` | medium | VULN-045 |
| `caa_missing` | low | VULN-046 |
| `dns_zone_transfer` | critical | VULN-047 |
| `subdomain_takeover` | high | VULN-048 |
| `domain_expiring`, `tls_expiring` | medium/high | VULN-049 |
| `admin_panel_exposed` | medium | VULN-050 |

### Кэш

`~/.perimeter/cache/osint/<домен>.json`, TTL 24 часа. Ключ учитывает домен,
источники, `--active` и путь+размер словаря. Запуск из кэша не пишет новую
запись в историю.

### JSON-отчёт

```
domain, scan_time, duration_sec, sources{}, whois{}, dns{}, email{spf,dmarc,dkim},
security{dnssec,caa,zone_transfer}, subdomains[], findings[], cached, cache_age_hours
```

Поддомен: `subdomain, ip, ips[], cname, source ("passive"|"wordlist"),
http{url,status,title,server,tls_expires,tls_days_left,tls_issuer}, takeover`.

---

## `perimeter web`

```
perimeter web TARGET [--port PORT] [--cookie K=V] [--report]
```

| Флаг | По умолчанию | Описание |
|---|---|---|
| `TARGET` | — | IP или хост |
| `--port` | `4280` | порт приложения |
| `--cookie` | — | cookie сессии, можно повторять |
| `--report` | — | JSON/TXT в `./reports` |

Профиль проверок — **DVWA**. Пути:

| Проверка | Путь |
|---|---|
| brute force / rate limiting | `/vulnerabilities/brute/` |
| CSRF | `/vulnerabilities/csrf/` |
| reflected XSS | `/vulnerabilities/xss_r/` |
| file upload | `/vulnerabilities/upload/` |
| open redirect | `/vulnerabilities/redirect/` |

На обычном приложении эти пути дадут 404 и «Находок: 0». Это ожидаемо:
модуль предназначен для учебного стенда, а не для аудита произвольного сайта.

File upload реально загружает файл на стенд и не удаляет его (помечено
`shortcut:` в коде).

---

## `perimeter pipeline`

```
perimeter pipeline DOMAIN [--scan] [--ports PORTS] [--concurrency N] [--json PATH]
```

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--scan` | выкл. | сканировать порты найденных хостов |
| `--ports` | топ | порты для скана |
| `--concurrency` | `10` | сколько хостов одновременно |
| `--json` | — | полный отчёт в файл (структурированный JSON) |

Без `--scan` выполняется только OSINT и печатается сводка. Скан портов
выключен по умолчанию, потому что IP за CDN принадлежат провайдеру.

Структура JSON: `domain`, `osint` (полный отчёт), `targets{ip: [имена]}`,
`scan_results{ip: [ScanResult]}` (при `--scan`), `findings[]`.

---

## `perimeter vault`

```
perimeter vault save NAME
perimeter vault load NAME
perimeter vault list
```

| Действие | Что делает |
|---|---|
| `save NAME` | спрашивает мастер-пароль и значение (оба скрыто), шифрует и пишет |
| `load NAME` | спрашивает мастер-пароль, печатает значение в stdout |
| `list` | печатает имена без пароля |

Криптография:

- ключ: PBKDF2-HMAC-SHA256, 480 000 итераций, соль 16 байт из `.salt`;
- шифрование: Fernet (AES-128-CBC + HMAC-SHA256);
- мастер-пароль: солёный PBKDF2-хеш в `.master`, сравнение `compare_digest`;
- запись атомарная (`os.replace`); POSIX-права `0600` / каталог `0700`.

Файлы: `.master`, `.salt`, `encrypted.json`. Бэкапить нужно все три.
Если `.master` есть, а `.salt` нет — команда завершится ошибкой и **не**
создаст новый ключ (иначе старые секреты стали бы нечитаемыми навсегда).

Ограничения: нет удаления и переименования секретов; нет неинтерактивного
режима (пароль вводится с терминала).

---

## `perimeter report`

```
perimeter report [-o FILE]
```

PDF по истории из `perimeter.db`. По умолчанию `perimeter_report.pdf`.
Содержит: сводку, последние 5 сканов OSINT (поддомены, находки, срок домена),
последние 5 сканов DLP (критические / высокие / средние / низкие) и сетевые
детали по портам с хостом.

Значения секретов в PDF не попадают. Все строки из БД экранируются.

---

## `perimeter history`

```
perimeter history [--limit N]
```

Печатает последние `N` (по умолчанию 5) записей DLP, сети и OSINT.
Для сети дополнительно показывает найденные уязвимости по портам с хостом.
Только чтение.

---

## `perimeter clear`

```
perimeter clear [--yes]
```

Удаляет все таблицы истории и создаёт пустые заново. Без `--yes` спрашивает
подтверждение (`y` / `yes` / `д` / `да`).

---

## `perimeter completion`

```
perimeter completion [bash|zsh|powershell]
```

Печатает скрипт автодополнения. Без аргумента выбирает по `$SHELL`
(на Windows — PowerShell).

```bash
eval "$(perimeter completion bash)"          # ~/.bashrc
eval "$(perimeter completion zsh)"           # ~/.zshrc
perimeter completion powershell | Add-Content $PROFILE   # PS 7+
```

Fish и PowerShell 5.1 не поддерживаются.

---

## Лимиты

| Ограничение | Значение | Как изменить |
|---|---|---|
| Размер файла DLP | 1 МБ | — |
| Глубина истории git | 1 000 коммитов | `--git-depth N` |
| Находок из истории git | 500 | сузить путь или глубину |
| Проверок в `scan` | 65 536 (хосты × порты) | сузить CIDR/порты |
| Имён поддоменов | 20 000 | `--wordlist` |
| Имён из crt.sh | 5 000 | — |
| HTTP-проб за `--active` | 200 | — |
| Тело HTTP-пробы | 200 КБ | — |
| Кэш OSINT | 24 ч | `--no-cache` |
| Параллелизм DNS | 50 | `--concurrency N` |
| Параллелизм портов | 100 | — |
| Параллелизм HTTP-проб | 20 | — |

---

## Схема SQLite

```
dlp_results(id, scan_time, checked_path, critical_count, high_count,
            medium_count, low_count)
network_results(id, scan_time, target, open_ports_count, vulnerabilities_count)
network_details(id, result_id, host, port, service, banner,
                vulnerability_title, severity)
osint_results(id, scan_time, target_domain, registrar, subdomains_count,
              expires_at, findings_count)
osint_subdomains(id, result_id, name, ips, cname, source, http_status, title)
```

Миграции идемпотентны: при старте команды отсутствующие колонки добавляются
через `ALTER TABLE`. Значения секретов DLP в базе не хранятся.

---

## JSON отчёта DLP / scan / web

`--report` пишет **массив находок**. Поля зависят от типа:

DLP-находка:

```json
{
  "type": "password",
  "severity": "high",
  "file": "/home/user/project/.env",
  "line": 1,
  "value": "Prod…",
  "secret": true,
  "kb_id": "VULN-006",
  "source": "fs",
  "title": "Пароль в открытом виде",
  "description": "…",
  "fix": "…",
  "risk": "…"
}
```

С `--git` добавляются `commit`, `commit_full`, `author`, `date`, `subject`,
`commits`, `also_in_git`; `source` = `"git"` только у находок, которых нет в
рабочем дереве.

Сетевая находка: `host`, `port`, `service`, `banner`, `severity`, `cve`,
`title`, `recommendation`, `kb_id`.

Веб-находка: `url`, `vuln_type`, `severity`, `detail`, `kb_id`.

---

## Python API

```python
import api

findings = api.scan_dlp(path, show_secrets=False, stats=stats,
                        git=False, git_depth=0)
findings = await api.scan_network(target, ports=None)
findings = await api.scan_web(target, port=4280, cookies=None)
report   = await api.run_osint_report(domain, wordlist_path=None,
                                      active=False, sources=None,
                                      concurrency=50, use_cache=True)
result   = await api.run_combined_pipeline(domain, ports=None,
                                           host_concurrency=10,
                                           enrich=True, scan=False)

api.enrich_finding(finding)
api.generate_json_report(findings)
api.generate_text_report(findings)
api.save_report(findings, reports_dir="reports")
api.save_osint_report(report, reports_dir="reports")

api.vault_unlock(password)   # RuntimeError, если потерян .salt
api.vault_save(name, value)
api.vault_load(name)
api.vault_list()
api.vault_lock()
api.vault_is_initialized()
```

`scan_dlp` и `*_osint_report` возвращают `{"error": "…"}` вместо исключения
при ошибке ввода. `vault_unlock` намеренно пробрасывает `RuntimeError`:
потерянный `.salt` — не «неверный пароль».
