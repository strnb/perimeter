# Архитектура

Документ для разработчика: как разложен код, как ходят данные, какие решения
приняты и почему. Пользовательские сценарии — в [usage.md](usage.md), флаги —
в [reference.md](reference.md).

---

## 1. Что это и границы

Локальный CLI-комплекс аудита безопасности. Один процесс, один аналитик,
локальные SQLite и vault. Нет сервера, фоновых воркеров, пользователей и
сетевого API.

Внешние границы:

- файловая система (DLP, vault, БД, отчёты);
- сеть (сканер портов, OSINT, веб-проверки);
- git (история коммитов);
- терминал (ввод мастер-пароля, вывод).

---

## 2. Слои

```
┌──────────────────────────────────────────────────────────────┐
│ cli.py            argparse, команды, вывод, автодополнение    │
├──────────────────────────────────────────────────────────────┤
│ api/              фасад для CLI и внешних скриптов            │
│                   dlp network osint web pipeline vault        │
│                   knowledge reports paths                     │
├──────────────────────────────────────────────────────────────┤
│ core/modules/     вся логика                                  │
│   dlp/            детекторы, YARA, git-история                │
│   scanner/        порты, баннеры, сигнатуры, OSINT, проверки  │
│   web_scanner/    5 проверок DVWA                              │
│   vault/          PBKDF2 + Fernet, атомарная запись            │
│   report_generator_utils/   PDF (reportlab)                    │
├──────────────────────────────────────────────────────────────┤
│ core/paths.py     ресурсы и ~/.perimeter                      │
│ database.py       SQLite: схема, миграции, запись             │
│ knowledge_base/   50 записей: описание, риск, fix             │
│ assets/           DejaVuSans.ttf                               │
└──────────────────────────────────────────────────────────────┘
```

Правила слоёв:

- `cli.py` не импортирует `core/modules/*` напрямую — только `api.*`
  (исключение: `report` вызывает генератор PDF, потому что это одна функция).
- `api/*` — тонкие обёртки: изоляция ошибок, нормализация результата, маскировка.
- `core/modules/*` не знает про CLI и не печатает в stdout. Единственное
  исключение — предупреждение о ненайденном шрифте PDF.
- `database.py` — запись и миграции. PDF-генератор читает историю напрямую из
  SQLite (историческое исключение, менять только вместе с тестом).

---

## 3. Карта модулей

| Файл | Ответственность |
|---|---|
| `cli.py` | разбор аргументов, вывод, коды возврата, completion, `_jsonable` |
| `database.py` | схема, миграции, `save_*`, `get_previous_osint_subdomains`, `clear_all_data` |
| `api/dlp.py` | скан + обогащение + маскировка |
| `api/network.py` | скан + обогащение находок |
| `api/osint.py` | обёртка `run_osint`, превращает исключения в `{"error"}` |
| `api/pipeline.py` | OSINT → (скан) → обогащение |
| `api/web.py` | DVWA-проверки |
| `api/vault.py` | сессия vault; `RuntimeError` о потере `.salt` пропускается наверх |
| `api/knowledge.py` | загрузка `vulnerabilities.json`, `TYPE_TO_KB`, `enrich_finding` |
| `api/reports.py` | JSON/TXT, имена файлов, PDF-пути |
| `api/paths.py` | `KB_PATH` |
| `core/paths.py` | `resource_path`, `app_data_dir` |
| `core/modules/dlp/scanner.py` | обход, чтение, декодирование, дедуп, сортировка, git-слияние |
| `core/modules/dlp/patterns.py` | regex-шаблоны, `is_placeholder`, паттерны кода |
| `core/modules/dlp/*_detector.py` | по одному узкому детектору |
| `core/modules/dlp/yara_scanner.py` | компиляция правил один раз, метаданные, номер строки |
| `core/modules/dlp/git_history.py` | разбор `git log -p`, поиск в добавленных строках |
| `core/modules/scanner/port_scanner.py` | порты, сервисы, лимит задач |
| `core/modules/scanner/db_checker.py` | активные пробы: SMB, Telnet, MySQL, PostgreSQL, Mongo, Redis, Tomcat, distccd, FTP |
| `core/modules/scanner/vuln_signatures.py` | сигнатуры по баннеру/порту/подтверждению |
| `core/modules/scanner/osint.py` | WHOIS, DNS, crt.sh, поддомены, кэш, активные проверки |
| `core/modules/scanner/osint_checks.py` | чистые проверки SPF/DMARC/DNSSEC/CAA/HTTP/takeover |
| `core/modules/scanner/pipeline.py` | склейка OSINT и сканера |
| `core/modules/web_scanner/` | registry проверок, `config.py` c профилем DVWA |
| `core/modules/vault/` | `master` (хеш пароля), `cipher` (ключ), `storage` (Fernet) |
| `core/modules/report_generator_utils/` | PDF, экранирование, шрифт |

---

## 4. Потоки данных

### 4.1. DLP: файловая система

```
cli.cmd_dlp
  → api.scan_dlp(path, stats, git)
      → run_scan
          → walk_files: os.walk, каталоги отсекаются до входа
          → на файл: read_text (лимит 1 МБ, NUL-проверка, BOM→UTF-16→UTF-8→cp1251→latin-1)
          → ssh / tokens / passwords / connections / yara(data) / code-детекторы
          → дедуп (type, file, line, value) + сортировка по severity
      → git_history.scan_git_history (если --git): слияние с файловыми
      → enrich_finding (база знаний)
      → маскировка значений, у которых secret=True
  → вывод, SQLite (только счётчики), --report
```

Файл читается **один раз**: байты идут и в декодер, и в YARA.

### 4.2. DLP: история git

```
scan_git_history
  → проверка git + repo_root (+ префикс подпапки)
  → Popen: git log --all -p -U0 --no-merges --max-count=N
  → построчный разбор: заголовок коммита → diff --git → +++ b/path → @@ +N
  → только строки, начинающиеся с "+"
  → те же regex-детекторы, номер строки из ханка
  → ключ (type, value, path): самый старый коммит + множество коммитов
```

`stderr` направлен в `DEVNULL`: иначе большой вывод ошибок заблокировал бы
пайп и скан завис бы.

### 4.3. Скан портов

```
api.scan_network
  → scan_ports: hosts × ports, лимит 65 536, asyncio.Semaphore(100)
      → scan_port: TCP connect (1 с)
      → _identify_service: второй connect + баннер/активная проба
  → match_vulnerabilities: баннер → сигнатуры; порт → сигнатуры;
    VULNERABLE → подтверждённые правила
  → enrich_finding
  → cli: вывод + network_results/network_details
```

### 4.4. OSINT

```
run_osint
  → normalize_domain (URL, порт, www, IDN, punycode)
  → кэш (домен, источники, active, путь+размер словаря, TTL 24 ч)
  → gather: WHOIS (to_thread, 30 с) + DNS (9 типов параллельно)
  → DMARC + DKIM (9 селекторов параллельно)
  → crt.sh (2 попытки, 45 с) + hackertarget (отдельный клиент, verify=True)
  → find_subdomains: wordlist + пассивные имена, wildcard по множеству IP
  → если --active: AXFR по NS (to_thread, 5 с) + HTTP-инвентарь (200 имён, 20 параллельно)
  → osint_checks: SPF, DMARC, DNSSEC, CAA, AXFR, панели, TLS, takeover, WHOIS-срок
  → сортировка находок, запись кэша
```

Ошибка отдельного источника (`crt.sh: HTTP 502`) не роняет отчёт: она попадает
в `sources`.

### 4.5. Vault

```
unlock(password)
  → первый запуск: derive_key (создаёт .salt) → save_master_hash (.master)
  → иначе verify_password (PBKDF2 + compare_digest), затем derive_key
  → ключ Fernet живёт в памяти процесса

save_secret → storage: загрузить JSON, encrypt, атомарная запись (os.replace)
load_secret → base64 → decrypt
```

`verify_password` и `derive_key` используют **разные** соли: `.master` хранит
свою соль в строке хеша, `.salt` — соль ключа шифрования.

### 4.6. PDF

```
cli.cmd_report → generate_pdf_report
  → SQLite: сводка по трём таблицам, последние 5 OSINT/DLP, детали сети
  → reportlab: Paragraph(escape(...)) для каждого значения из БД
  → DejaVuSans.ttf для кириллицы (поиск через resource_path)
```

---

## 5. Конкурентность

| Место | Модель | Лимит |
|---|---|---|
| Порты | `asyncio` задачи + семафор | 100 |
| DNS-поддомены | `asyncio` + семафор | 50 (`--concurrency`) |
| HTTP-пробы | `asyncio` + семафор | 20 |
| WHOIS, AXFR | `asyncio.to_thread` + `wait_for` | по одному |
| git log | `subprocess.Popen`, потоковое чтение | — |

Общего пула потоков нет: блокирующие вызовы (`whois`, `dns.query.xfr`)
выносятся в один поток на вызов и ограничены таймаутом.

---

## 6. Обработка ошибок

Три уровня:

1. **Ввод** — `ValueError` с понятным текстом (`это не домен: …`), CLI даёт код 1.
2. **Источник** — сбой попадает в отчёт как статус (`sources["crt.sh"] =
   "crt.sh: HTTP 502"`), остальное собирается.
3. **Файл/хост** — пропуск с инкрементом `stats["skipped_*"]` или пустой
   результат, без исключения.

Отдельно: `database.init_db()` вызывается в `main()`, а не при импорте, чтобы
`-h` работал на read-only дереве. Если база недоступна — предупреждение, команда
продолжает работу.

---

## 7. Ключевые решения

| Решение | Почему |
|---|---|
| `api/` как фасад | CLI и внешние скрипты не зависят от внутренних модулей; проще тестировать |
| Один детектор — один владелец | YARA только файловые условия (несколько строк), regex — одиночные секреты; нет дублей находок |
| Маскировка по умолчанию | отчёт пересылают; полное значение — только `--show-secrets` |
| В БД только счётчики DLP | база не должна становиться ещё одной утечкой |
| `verify=False` только для проб целей | у целей часто самоподписанные сертификаты; API (crt.sh, hackertarget) проверяются |
| Веб — только DVWA | профиль проверок жёстко привязан к путям стенда; честнее, чем ложный «аудит любого сайта» |
| `pipeline --scan` по умолчанию выключен | IP за CDN принадлежат провайдеру, а не владельцу домена |
| Ошибка при потере `.salt` | иначе новый ключ молча делает секреты нечитаемыми навсегда |
| Лимиты до сети | опечатка в CIDR не должна съедать память и время |
| Ресурсы через `resource_path` | репозиторий и `pip install .` работают одинаково |
| Изменяемые данные: репозиторий → `~/.perimeter` | site-packages только для чтения |
| Никаких новых зависимостей | 6 runtime-пакетов; всё остальное — stdlib |
| Свои assert-тесты вместо pytest | не тянуть dev-зависимости; запуск одной командой |

---

## 8. Как расширять

### Добавить детектор DLP

1. Создайте `core/modules/dlp/<name>_detector.py` с функцией
   `detect_<name>(file: Path, lines: list[str]) -> list[Finding]`.
2. Возвращайте `Finding(type=..., severity=..., file=..., line=..., value=..., kb_id=...)`.
3. Подключите в `scanner.py` (файловый скан) и, если нужно, в
   `git_history.DETECTORS`.
4. Если тип содержит секрет — не добавляйте его в `NON_SECRET_TYPES`
   (`results.py`), маскировка включится сама.
5. Добавьте запись в `knowledge_base/vulnerabilities.json` и маппинг в
   `api/knowledge.py: TYPE_TO_KB`.
6. Тест: позитивный и негативный случай в `tests/test_dlp.py`.

### Добавить YARA-правило

Файл `core/modules/dlp/rules/<name>.yar` с `meta: type, severity, kb_id`.
Только условия, которые нельзя выразить одной строкой. Одиночный токен —
regex-детектор, не YARA.

### Добавить исключение для DLP

- каталог: `EXCLUDED_DIRS` в `scanner.py`;
- файл/расширение: `EXCLUDED_FILENAMES` / `EXCLUDED_EXTENSIONS`;
- путь в истории git проверяется той же функцией `_excluded_git_path`.

### Добавить проверку OSINT

1. Чистая функция в `osint_checks.py`: принимает данные, возвращает
   `(summary, findings)` или список находок.
2. Никакой сети внутри — сеть собирается в `osint.py`.
3. Запись в `vulnerabilities.json` + `kb_id`.
4. Тест в `tests/test_osint.py` без сети.

### Добавить сигнатуру сканера

- баннер: `BANNER_SIGNATURES` (regex по баннеру);
- порт: `PORT_SIGNATURES` (только если порт сам доказывает проблему);
- активное подтверждение: `ACTIVE_CONFIRMED_RULES` + строка `VULNERABLE`
  в баннере. Не добавляйте сигнатуру по имени сервиса — это даёт ложные CVE.

### Добавить команду CLI

1. `cmd_<name>(args)` в `cli.py`.
2. `_add(sub, "<name>", "краткое", "подробное", "Примеры:\n  …")`.
3. Аргументы через `p.add_argument`, `p.set_defaults(func=cmd_<name>)`.
4. Функция в `api/` — не тяните `core` в CLI.
5. Тест парсера и обработчика, обновить `docs/reference.md`.

---

## 9. Тесты

| Файл | Что проверяет |
|---|---|
| `tests/test_cli.py` | парсер, DLP-смоук, PDF, vault (+потеря `.salt`), миграции, сигнатуры, лимит CIDR, wildcard DNS, лимит HTTP-проб, автодополнение |
| `tests/test_dlp.py` | 13 позитивных сценариев, негативные, маскировка, YARA, история git на временном репозитории |
| `tests/test_osint.py` | нормализация домена, SPF/DMARC, AXFR, takeover, кэш, CLI, diff, миграция БД |
| `tests/test_docs.py` | ссылки и якоря, команды и флаги в примерах, версия в CHANGELOG |

Сеть в тестах отсутствует: `httpx.MockTransport`, фейковый DNS-клиент,
подменённые WHOIS/AXFR. Git-тесты создают настоящий временный репозиторий.

---

## 10. Известный технический долг

Помечено в коде или осознанно отложено:

- **Два TCP-подключения на порт**: `scan_port`, затем `_identify_service`.
  Можно объединить, но это меняет границу функций сканера.
- **Нет host discovery**: подсеть за файрволом ждёт таймауты.
- **Нет ретеншена истории**: `perimeter.db` растёт; чистится вручную `clear`.
- **Веб: file upload оставляет файл** на стенде (`shortcut:` в коде).
- **Vault**: нет удаления/переименования, нет неинтерактивного режима.
- **Git**: submodules и LFS не разбираются отдельно.
- **Находки OSINT не попадают в PDF** (только срок и счётчик) — нужна колонка
  с JSON находок и миграция.
- **`pipeline` не пишет в историю** — результат только в консоль/JSON.

Это не баги, а границы текущей версии. При доработке — добавлять тест и
обновлять этот раздел.
