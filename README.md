# Периметр CLI

**Терминальный комплекс аудита безопасности**: поиск утечек секретов (DLP,
включая историю git), сканирование портов, разведка домена (OSINT), проверки
веб-приложения, шифрованное хранилище секретов и PDF-отчёты.

Один процесс, локальные данные, без сервера и облака.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Dependencies](https://img.shields.io/badge/runtime%20deps-6-informational)
![Tests](https://img.shields.io/badge/tests-4%20suites-success)
![License](https://img.shields.io/badge/license-MIT-green)

> **ВНИМАНИЕ.** Инструмент предназначен исключительно для легального аудита.
> Сканирование сторонних ресурсов без письменного согласия владельцев незаконно
> (ст. 272–274 УК РФ). Активные проверки (`--active`, `web`, `pipeline --scan`)
> запускайте только на своих системах или в рамках подписанного договора.
> Вы используете инструмент на свой страх и риск.

---

## Содержание

- [Возможности](#возможности)
- [Требования](#требования)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [Команды](#команды)
- [Ограничения](#ограничения)
- [Где хранятся данные](#где-хранятся-данные)
- [Документация](#документация)
- [Тесты](#тесты)
- [Безопасность](#безопасность)
- [Участие в разработке](#участие-в-разработке)
- [Лицензия](#лицензия)

---

## Возможности

| Модуль | Что делает | Активность |
|---|---|---|
| **DLP** | Пароли, токены, приватные ключи, строки подключения, хеши паролей, `.netrc`, дампы секретов; SQLi / command injection / слабые сессии в коде | только чтение файлов |
| **DLP · git** | Те же секреты в **истории коммитов** — с автором, датой и хешем коммита | только чтение репозитория |
| **Scan** | TCP-порты, баннеры сервисов, сигнатуры известных уязвимостей, слабые пароли БД (опционально) | сетевое подключение |
| **OSINT** | WHOIS, 9 типов DNS, поддомены из crt.sh и wordlist, SPF/DMARC/DKIM/DNSSEC/CAA | пассивно по умолчанию |
| **OSINT · active** | AXFR, HTTP/TLS-пробы, панели управления, кандидаты на subdomain takeover | активные запросы |
| **Web** | XSS, CSRF, brute force, file upload, open redirect — **профиль DVWA** | активные запросы |
| **Vault** | Шифрованное хранилище секретов: PBKDF2-SHA256 (480 000 итераций) + Fernet | локально |
| **Отчёты** | JSON/TXT по находкам, полный JSON OSINT, сводный PDF по истории из SQLite | локально |

Все находки DLP, сети и веба обогащаются описанием, риском и рекомендацией из
базы знаний (50 записей). Секреты в выводе и отчётах **по умолчанию маскируются**.

---

## Требования

- **Python 3.10+**
- **git** — только для `dlp --git` (без него остальной DLP работает)
- ОС: Windows 10/11, Linux, macOS
- Для `.[db-checks]`: клиентские библиотеки MySQL / PostgreSQL / MongoDB

Зависимости: `yara-python`, `cryptography`, `httpx`, `reportlab`,
`python-whois`, `dnspython`. Опционально: `pymongo`, `PyMySQL`, `psycopg2-binary`.

---

## Установка

### Linux / macOS

```bash
git clone https://github.com/strnb/perimeter.git
cd perimeter
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Если `pip` отвечает `externally-managed-environment` (Debian 12, Ubuntu 23+),
используйте venv — это правильный путь. `--break-system-packages` не
рекомендуется.

Для сборки `yara-python` на Alpine/ARM без готового wheel:

```bash
sudo apt install build-essential libffi-dev automake libtool   # Debian/Ubuntu
# Alpine: apk add build-base libffi-dev automake libtool
```

### Windows

```powershell
git clone https://github.com/strnb/perimeter.git
cd perimeter
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Проверки слабых паролей БД (необязательно):

```bash
pip install -e ".[db-checks]"
```

После установки команда `perimeter` доступна из любой директории.

---

## Быстрый старт

```bash
perimeter                                   # баннер и справка
perimeter dlp ~/project --report            # секреты в файлах + JSON/TXT в ./reports
perimeter dlp . --git                       # + секреты в прошлых коммитах
perimeter scan 192.168.1.10                 # 33 популярных порта + сигнатуры
perimeter osint example.com --report        # WHOIS, DNS, поддомены, находки
perimeter vault save github_token           # пароль и секрет вводятся скрыто
perimeter report -o audit.pdf               # сводный PDF по истории сканов
```

Пример вывода `perimeter dlp . --git`:

```
[CRITICAL] aws_key              deploy/config.py:12
           AKIA…
           fix: Немедленно отозвать обнаруженный токен, выпустить новый и хранить секреты вне исходного кода.
[HIGH    ] password             .env:3
           DB_P…
           git 4f2c1a9 2025-11-02 добавил конфиг
           удалён из кода; коммитов с этим секретом: 3
```

Больше примеров с реальным выводом — в [docs/usage.md](docs/usage.md).

---

## Команды

| Команда | Назначение | Справочник |
|---|---|---|
| `dlp PATH` | секреты в файлах и истории git | [dlp](docs/reference.md#perimeter-dlp) |
| `scan TARGET` | порты, баннеры, сигнатуры | [scan](docs/reference.md#perimeter-scan) |
| `osint DOMAIN` | WHOIS, DNS, поддомены, конфигурация | [osint](docs/reference.md#perimeter-osint) |
| `web TARGET` | 5 проверок для стенда DVWA | [web](docs/reference.md#perimeter-web) |
| `pipeline DOMAIN` | OSINT и, по флагу `--scan`, порты хостов | [pipeline](docs/reference.md#perimeter-pipeline) |
| `vault save\|load\|list` | шифрованное хранилище секретов | [vault](docs/reference.md#perimeter-vault) |
| `report` | PDF по истории сканов | [report](docs/reference.md#perimeter-report) |
| `history` | последние записи истории | [history](docs/reference.md#perimeter-history) |
| `clear` | очистить историю | [clear](docs/reference.md#perimeter-clear) |
| `completion` | автодополнение для shell | [completion](docs/reference.md#perimeter-completion) |

Справка по любой команде: `perimeter <команда> -h`.

---

## Ограничения

| Ограничение | Значение |
|---|---|
| Размер файла DLP | 1 МБ |
| Глубина истории git | 1 000 коммитов (`--git-depth N`) |
| Проверок в `scan` | 65 536 (хосты × порты) |
| Имён поддоменов | 20 000 |
| HTTP-проб за `--active` | 200 |
| Кэш OSINT | 24 часа (`--no-cache`) |

Важное:

- **`web` работает только для DVWA.** На обычном приложении пути
  `/vulnerabilities/...` дадут 404 и «находок 0».
- **`pipeline` по умолчанию не сканирует порты.** IP за CDN принадлежат
  провайдеру; скан включается флагом `--scan`.
- **Subdomain takeover — только кандидат**, требует ручной проверки.
- **Сканер портов не делает host discovery** — хосты за файрволом не ответят.
- **В PDF по DLP попадают только счётчики**, не значения секретов.

Полная таблица лимитов — [docs/reference.md#лимиты](docs/reference.md#лимиты).

---

## Где хранятся данные

| Что | Репозиторий / `pip install -e .` | Обычный `pip install .` |
|---|---|---|
| История сканов | `./perimeter.db` | `~/.perimeter/perimeter.db` |
| Vault | `./vault/` | `~/.perimeter/vault/` |
| Кэш OSINT | `~/.perimeter/cache/osint/` | `~/.perimeter/cache/osint/` |
| Отчёты `--report` | `./reports/` | `./reports/` |

В историю попадают время, цель, счётчики, баннеры, поддомены и их IP.
**Значения секретов DLP в базу не пишутся.** База не шифруется; vault шифрует
значения, но имена хранит открыто. Права доступа определяются ОС.

---

## Документация

| Слой | Для кого | Где |
|---|---|---|
| Обзор и установка | первый визит | этот файл |
| Сценарии «хочу сделать X» | пользователь | [docs/usage.md](docs/usage.md) |
| Все флаги, коды, форматы | пользователь | [docs/reference.md](docs/reference.md), `--help` |
| Модули, потоки данных, решения | разработчик | [docs/architecture.md](docs/architecture.md) |
| Как собрать, тесты, PR | контрибьютор | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Что изменилось | все | [CHANGELOG.md](CHANGELOG.md) |

Навигация по документации — [docs/README.md](docs/README.md).
Ссылки, команды и флаги в документации проверяются автоматически:
`python tests/test_docs.py`.

---

## Тесты

Тесты не требуют pytest и сети — это assert-скрипты:

```bash
python tests/test_docs.py    # ссылки, якоря, команды и флаги в документации
python tests/test_cli.py     # CLI, PDF, vault, миграции БД, лимиты
python tests/test_dlp.py     # DLP, YARA, история git, ложные срабатывания
python tests/test_osint.py   # OSINT: домены, SPF/DMARC, takeover, кэш, БД
```

Живые проверки (сеть, DVWA) в тесты не входят: они требуют разрешения
владельца. CI гоняет все четыре набора на Ubuntu и Windows.

---

## Безопасность

- **Секреты маскируются по умолчанию** и в консоли, и в отчётах. Полные
  значения — только с `--show-secrets`; такой файл считайте секретным.
- **Vault** хранит мастер-пароль как солёный PBKDF2-хеш (480 000 итераций),
  данные шифруются Fernet; запись атомарная, на POSIX права `0600`.
- **В историю попадают только счётчики DLP**, не сами секреты.
- **Активные действия** (`--active`, `web`, `pipeline --scan`, file upload)
  видны в логах целевой системы. Запускайте только с разрешения.
- **Юридически:** инструмент не даёт права сканировать чужие ресурсы.
  Ответственность за использование лежит на операторе.

---

## Участие в разработке

Правила сборки, тестов, стиля и PR — в [CONTRIBUTING.md](CONTRIBUTING.md).
Коротко:

1. Форк и ветка: `git switch -c feature/имя`.
2. `pip install -e .` в venv.
3. Перед PR: все четыре набора тестов зелёные.
4. Новые runtime-зависимости не добавляются без необходимости.
5. Документация обновляется в том же PR, что и код.

---

## Лицензия

[MIT](LICENSE) © 2026 EvdokimovAD.

Код можно использовать, изменять и распространять, в том числе в коммерческих
проектах, при сохранении текста лицензии и уведомления об авторских правах.
Программа поставляется «как есть», без гарантий.

Инструмент предназначен только для легального аудита: лицензия не даёт права
сканировать чужие системы без разрешения владельца.
