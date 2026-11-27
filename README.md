# Периметр CLI

Терминальная версия комплекса «Периметр» — без GUI, все модули через подкоманды.

> ВНИМАНИЕ: исключительно для легального аудита. Сканирование сторонних ресурсов
> без согласия владельцев незаконно (ст. 272-274 УК РФ).

## Установка

```bash
cd perimeter-cli
pip install -e .
```

Проверки слабых паролей MySQL/PostgreSQL/MongoDB включаются отдельно:
`pip install -e ".[db-checks]"`. Без них сканер честно пишет
«проверка слабых паролей недоступна» в баннере порта.

После этого команда `perimeter` доступна из любой директории.

## Команды

```bash
perimeter                        # баннер + справка
perimeter dlp C:\project --report   # DLP-скан папки (+ JSON/TXT отчёт в ./reports)
perimeter scan 192.168.1.1 --ports 22,80,8000-8100
perimeter osint example.com      # WHOIS + DNS + поддомены
perimeter web 10.0.0.5 --port 8080 --cookie session=abc
perimeter pipeline example.com   # OSINT -> скан всех найденных хостов
perimeter vault save github_token   # пароль и секрет вводятся скрыто
perimeter vault load github_token
perimeter vault list
perimeter report -o report.pdf   # PDF по истории сканов из БД
perimeter history --limit 10     # история сканов + имена найденных уязвимостей
perimeter clear --yes            # очистка истории
```

Результаты сканов автоматически пишутся в `perimeter.db` (в папке проекта),
vault хранится в `vault/` там же. После обычного `pip install .` (не `-e`)
изменяемые данные уходят в `~/.perimeter/`. Отчёты `--report` — в `./reports`
текущей директории. Секреты в отчётах по умолчанию маскируются; полные
значения — только с `perimeter dlp ... --show-secrets`.

### Что ищет DLP

Пароли и токены в любых текстовых файлах (`password:`, `DB_PASSWORD=`,
`api_key =`, JSON/YAML/TOML), приватные ключи (RSA, EC, OpenSSH, PKCS#8,
PGP, PuTTY), API-ключи AWS/GitHub/GitLab/OpenAI/Stripe/Slack/Google/
SendGrid/npm/DigitalOcean/Telegram, JWT, строки подключения с паролем
(`postgres://user:pass@host`), файлы хешей паролей, `.netrc` и дампы из
5+ секретов в одном файле.

Пропускаются: зависимости (`node_modules`, `venv`), сборки (`dist`, `build`,
`target`), `.git`, lock-файлы, минифицированный код, двоичные файлы и файлы
больше 1 МБ. Нечитаемые/пропущенные файлы видны в итоговой строке скана.
YARA-правила проверяют только то, что не выразить одной строкой; если YARA
недоступна, DLP продолжает работать на regex-детекторах и предупреждает об этом.

Полная справка по модулю: `perimeter <команда> -h` (описание, аргументы, примеры).
Примеры в справке — на любой ОС: пути можно писать как `~/project`, так и `C:\project`.

## Автодополнение (Tab)

```bash
# Linux / macOS / Git Bash / WSL — в ~/.bashrc
eval "$(perimeter completion bash)"

# zsh — в ~/.zshrc
eval "$(perimeter completion zsh)"
```

Tab по `perimeter <Tab>` предлагает команды, `perimeter vault <Tab>` — действия,
`perimeter web --<Tab>` — флаги модуля. Обычное дополнение файлов при этом
сохраняется (`perimeter dlp <Tab>` подставит путь).

PowerShell: работает на **7+** (во встроенной 5.1 нет `Register-ArgumentCompleter -Native`).

```powershell
# PowerShell 7+
perimeter completion powershell | Add-Content $PROFILE
```

На 5.1 либо обновиться (`winget install --id Microsoft.PowerShell`), либо включить
подсказки по истории ввода: `Set-PSReadLineOption -PredictionSource History`.

## Тест

```bash
python tests/test_cli.py   # CLI, сеть, PDF, vault
python tests/test_dlp.py   # DLP и YARA: находки, ложные срабатывания, лимиты
```
