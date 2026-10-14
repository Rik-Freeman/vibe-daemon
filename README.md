# 🛡️ vibe-daemon

[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://www.rust-lang.org/)
[![MCP](https://img.shields.io/badge/MCP-2024--11--05-blue.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/Rik-Freeman/vibe-daemon/actions/workflows/ci.yml/badge.svg)](https://github.com/Rik-Freeman/vibe-daemon/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-238%20passed-brightgreen.svg)]()
[![Clippy](https://img.shields.io/badge/clippy-clean-brightgreen.svg)]()

> **vibe-daemon** — высокопроизводительный, безопасный и расширяемый автономный демон на Rust для интеллектуального серверного администрирования через [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).

Демон выступает отказоустойчивым защитным барьером и прокси-контроллером между AI-моделями (Claude, Cursor, Antigravity IDE и автономными агентами) и операционной системой хоста (Linux / cross-platform). Демон предоставляет полный арсенал из **33 инструментов**, подсистему **MCP Resources**, шину асинхронных уведомлений (**Server-Initiated Notifications**) и поддерживает как локальный **Stdio**, так и сетевые транспорты **Streamable HTTP** и **Server-Sent Events (SSE)** с Bearer-авторизацией.

---

## 🚀 Ключевые возможности и архитектурные решения

| Подсистема | Проблема классических AI-агентов | Решение в `vibe-daemon` |
|---|---|---|
| **Защита доступа (Guard Engine)** | Случайный суицид хоста: закрытие SSH (порт 22), выключение сети или `killall vibe-daemon`. | Защищенные порты (`protected_ports`), черные списки служб (`protected_services`) и паттернов опасных команд (`rm -rf /`, `mkfs`, fork-бомбы). |
| **Безопасные файлы (File Ops)** | Повреждение файлов при сбое, symlink-атаки и утечка `/etc/shadow`. | Атомарная запись через временные файлы (`.tmp.<pid>`), автобэкап (`.bak.<timestamp>`), проверка `fs_guard` и защита от TOCTOU. |
| **Эффективное чтение логов** | Token Bleed и переполнение RAM при чтении многогигабайтных журналов. | `tail_logs` со смещением с конца файла (`SeekFrom::End`) и постраничная курсорная пагинация для каталогов (`list_directory`). |
| **Фоновые задачи (TaskManager)** | Зависание демона на долгих сборках (`cargo build`, `npm install`), зомби-процессы. | Асинхронный запуск с квотами (`max_active_tasks`, `max_retained_tasks`), TTL-очисткой и гарантированным завершением деревьев процессов. |
| **Аудит (Audit Trail)** | Незаметная подмена логов, утечка секретов модели в журнал аудита. | Криптографическая цепочка хэшей SHA-256 (Tamper-evident), маскирование секретов (Bearer токены, пароли, ключи) и `sync_data`. |
| **Сетевые транспорты** | Невозможность удаленного подключения агентов вне локальной машины. | Полноценная поддержка **Streamable HTTP** (POST `/mcp`) и **SSE** (GET `/sse`) с Bearer Token авторизацией и сессионной изоляцией. |
| **MCP Resources** | Необходимость постоянного вызова команд для мониторинга конфигов и системы. | Стандартизированный доступ к ресурсам по схемам `system://`, `config://`, `log://` с сессионными подписками (`resources/subscribe`). |
| **Server Notifications** | AI-модель вынуждена опрашивать демон в цикле (polling) в ожидании событий. | Транспортно-нейтральная шина событий (`EventBus`) для доставки уведомлений о завершении задач, изменении ресурсов и системных алертах. |
| **Rate Limiter** | Зацикливание модели и DoS сервера шквалом повторяющихся запросов. | Алгоритм скользящего окна (Sliding Window): глобальные и помодульные лимиты (`max_calls_per_minute`, `tool_limits`). |

---

## 🏛️ Архитектура системы

```mermaid
flowchart TD
    subgraph Clients ["AI Clients & Agents"]
        Claude["Claude Desktop (Stdio)"]
        Cursor["Cursor IDE (Stdio / HTTP)"]
        RemoteAgent["Remote Agent (Streamable HTTP / SSE)"]
    end

    subgraph Transports ["Transport Layer (src/transport)"]
        StdioT["Stdio Transport (Atomic Event Loop)"]
        HttpT["Streamable HTTP (/mcp + Bearer Auth)"]
        SseT["Server-Sent Events (/sse + Event Stream)"]
    end

    subgraph Core ["vibe-daemon Core"]
        Dispatcher["MCP Dispatcher (JSON-RPC 2.0 Router)"]
        AuthFilter["Bearer Token Auth Guard"]
        RateLimiter["Sliding Window Rate Limiter"]
        AuditLogger["Tamper-evident Audit Trail (SHA-256 Chained + Redaction)"]
        EventBus["Event Bus (System Alerts / Task & Resource Notifications)"]
        SubMgr["Session Subscription Manager"]
        
        subgraph Subsystems ["Core Subsystems"]
            ToolReg["Tool Registry (33 Plugin Tools)"]
            ResReg["Resource Registry (system://, config://, log://)"]
            TaskMgr["Task Manager (Quotas, TTL & Process Tree Killing)"]
            GuardEng["Guard Engine (Ports, Services, Traversal & Patterns)"]
            Inspector["System Inspector (/proc, ss, systemd)"]
        end
    end

    subgraph Host ["Host Operating System"]
        OS_Procs["Processes & Process Groups"]
        OS_FS["Filesystem (Atomic Writes & Backups)"]
        OS_Net["Network / Sockets / Firewall (ss, ufw, iptables)"]
        OS_Services["Systemd Services & Journalctl"]
        OS_Docker["Docker & Podman Daemon"]
    end

    Claude <--> StdioT
    Cursor <--> StdioT
    RemoteAgent <--> AuthFilter
    AuthFilter --> HttpT
    AuthFilter --> SseT
    StdioT <--> Dispatcher
    HttpT <--> Dispatcher
    Dispatcher --> RateLimiter
    Dispatcher --> AuditLogger
    Dispatcher --> ToolReg
    Dispatcher --> ResReg
    
    ToolReg --> GuardEng
    ToolReg --> TaskMgr
    ToolReg --> Inspector
    
    TaskMgr --> EventBus
    ResReg --> EventBus
    EventBus -.->|"Push Notifications"| StdioT
    EventBus -.->|"Push Events"| SseT
    
    GuardEng --> Host
    TaskMgr --> OS_Procs
    ToolReg --> Host
    Inspector --> Host
```

---

## 🧰 Каталог поддерживаемых MCP-инструментов (33 инструмента)

Все инструменты реализованы в виде модульных плагинов на базе трейта `McpTool` и зарегистрированы в `ToolRegistry`:

### 1. Системное администрирование и инспектор (5)
* **`get_system_status`**: Комплексный срез состояния хоста: использование памяти (`/proc/meminfo`), время аптайма, статусы отслеживаемых служб (`systemd`) и список всех активных слушающих сокетов (`ss -tulpn`) с привязкой к PID и именам процессов.
* **`read_server_config`**: Безопасное чтение файлов конфигурации из белого списка разрешенных директорий (`allowed_config_dirs`) с лимитом размера (1 МБ) и строгой защитой от Path Traversal (`..`).
* **`execute_safe_command`**: Выполнение shell-команд в изолированной среде с таймаутом (по умолчанию 30с), защитой от деструктивных команд (fork-бомбы, `rm -rf /`, `mkfs`), арбитражем занятых портов и сжатием вывода успешных операций (Smart Log Engine).
* **`manage_port`**: Управление правилами файрвола (UFW / iptables) с гарантированной защитой порта 22 (SSH) и предупреждением о занятости сокетов другими процессами.
* **`manage_service`**: Управление демонами systemd (`status`, `restart`, `reload`) с защитой от остановки ключевых служб (`vibe-daemon`, `sshd`, сетевой стек).

### 2. Безопасные файловые операции (5)
* **`list_directory`**: Структурированный листинг каталогов с поддержкой ограничения глубины (`max_depth`), детерминированной пагинацией по курсору (`cursor`, `page_size`), размерами файлов в байтах и временными метками модификации.
* **`read_file`**: Чтение содержимого файлов с лимитом размера (до 10 МБ), защитой от чтения виртуальных/специальных устройств (`/dev/zero`, `/proc`) и системных файлов аутентификации (`/etc/shadow`, `/etc/sudoers`).
* **`write_file`**: Атомарная запись данных через временный файл (`.tmp.<pid>`), создание резервной копии (`.bak.<timestamp>`), проверка путей в `fs_guard` и защита от TOCTOU/symlink подмены.
* **`search_files`**: Рекурсивный поиск файлов по имени и содержимому (regex и текст) с лимитом выдачи и автоматическим исключением виртуальных каталогов (`/proc`, `/sys`, `/dev`).
* **`tail_logs`**: Высокоэффективное чтение хвоста лог-файлов со смещением с конца (`SeekFrom::End`) без загрузки всего файла в оперативную память.

### 3. Запись конфигураций с валидацией и откатом (1)
* **`write_server_config`**: Запись конфигурационных файлов веб-серверов (`/etc/nginx`, `/etc/caddy`, `/etc/supervisor`) с автоматическим резервным копированием, синтаксической валидацией (например, `nginx -t`) и **мгновенным откатом (rollback)** к предыдущей версии в случае ошибки валидации.

### 4. Расширенный мониторинг и журналы (5)
* **`get_disk_usage`**: Анализ дискового пространства всех примонтированных файловых систем (общий объем, занято, свободно, процент использования, точки монтирования).
* **`get_cpu_info`**: Детальная информация о процессоре: число ядер, тактовая частота, архитектура, средняя загрузка (Load Average 1m/5m/15m) и процент утилизации CPU.
* **`get_top_processes`**: Список наиболее ресурсоемких процессов, отсортированных по потреблению CPU или RAM с указанием PID, пользователя, памяти и полной командной строки.
* **`get_network_stats`**: Сетевая статистика сетевых адаптеров: входящий/исходящий трафик (байты, пакеты, ошибки) и счетчики открытых соединений.
* **`tail_service_logs`**: Выборка журналов служб через `journalctl` с поддержкой временных интервалов `--since` и `--until` в формате RFC 3339, ограничением количества строк и smart-сжатием.

### 5. Менеджер фоновых задач (4)
* **`start_background_task`**: Запуск длительных команд (сборка проектов, миграции, дампы) в фоновом режиме с генерацией уникального `task_id` и валидацией через Guard Engine.
* **`check_task_status`**: Получение текущего состояния задачи (`Running`, `Completed`, `Failed`, `Cancelled`), времени работы, кода завершения и прогресса.
* **`get_task_output`**: Чтение накопленного потока вывода stdout/stderr с курсорной пагинацией и контролем лимита буфера (`output_limit_bytes`).
* **`cancel_task`**: Надежная отмена задачи с корректным завершением всего дерева процессов (process group / Job Object) через grace period (SIGTERM -> SIGKILL).

### 6. Управление контейнерами Docker (5)
* **`docker_ps`**: Структурированный список запущенных и остановленных контейнеров с их идентификаторами, именами, портами и статусами.
* **`docker_logs`**: Чтение последних строк логов контейнера с интеллектуальным сжатием.
* **`docker_restart`**: Безопасный перезапуск контейнера с валидацией имени и настраиваемым таймаутом.
* **`docker_compose_up`**: Фоновый запуск и валидация стеков Docker Compose.
* **`docker_stats`**: Срез метрик реального времени по контейнерам (CPU %, память, сетевой и дисковый ввод-вывод).
*(Все команды к Docker выполняются напрямую через argv, полностью исключая shell injection).*

### 7. Управление веб-сервером Nginx (5)
* **`nginx_test_config`**: Проверка валидности конфигурационных файлов Nginx (`nginx -t`).
* **`nginx_reload`**: Безопасная перезагрузка конфигурации с нулевым простоем (zero-downtime) после предварительного тестирования.
* **`nginx_list_sites`**: Инвентаризация виртуальных хостов в `sites-available` и `sites-enabled` с индикатором активности.
* **`nginx_enable_site`**: Активация виртуального хоста созданием символической ссылки.
* **`nginx_disable_site`**: Деактивация виртуального хоста удалением символической ссылки.

### 8. Управление SSL/TLS-сертификатами (3)
* **`ssl_check_expiry`**: Проверка срока действия сертификата для домена или локального файла с расчетом оставшихся дней до экспирации.
* **`ssl_certbot_renew`**: Запуск обновления сертификатов Let's Encrypt через Certbot (с поддержкой режима `--dry-run`).
* **`ssl_list_certs`**: Поиск и инвентаризация локально установленных сертификатов хоста.

---

## 🔒 Безопасность и надежность

### 1. Fail-closed Tamper-evident Audit Trail
Каждый вызов инструментов регистрируется в формате **JSON Lines (JSONL)** с криптографической цепочкой хэшей:
* **Хэш-цепочка:** Каждая запись содержит `entry_id` (sequence), `prev_entry_hash` и собственный `entry_hash` (SHA-256 по всем каноническим полям). Невозможно удалить или изменить запись в прошлом без нарушения валидности всей цепочки.
* **Fail-closed валидация:** При обнаружении повреждения хэш-цепочки в существующем файле лога демон немедленно прерывает старт с фатальной ошибкой (fail-closed), исключая молчаливый сброс на genesis-хэш.
* **Строгая фиксация и очередность:** Инкремент sequence и обновление хэша происходят строго после подтвержденной записи и flush на диск. Диспетчер MCP гарантирует подтверждение записи до отправки ответа клиенту.
* **Автоматическое маскирование секретов (Redaction):** Модуль аудита автоматически распознает и скрывает:
  * Заголовки авторизации (`Bearer [REDACTED]`);
  * Приватные ключи RSA, ECDSA, OpenSSH (`[REDACTED_PRIVATE_KEY]`);
  * Пароли и токены в аргументах команд (`--password`, `-p`, `token=***`).
* **Надежность (Durability):** Запись производится через bounded actor; каждый подтверждённый обязательный audit-record проходит `write_all`, `flush` и `sync_data()` до ответа клиенту. Ошибка переводит actor в fail-closed состояние.

### 2. Защита файловых операций, атомарность и Canonical Containment
* **Атомарная запись:** Данные сначала сохраняются во временный файл в том же каталоге (`.tmp.<filename>.<pid>`), после чего атомарно перемещаются (`rename`) на целевое место.
* **Автоматические резервные копии:** Перед перезаписью любого файла создается копия с временной меткой `.bak.YYYYMMDD_HHMMSS`.
* **Canonical Containment:** Разрешение целевых путей в провайдере `config://` производится через `std::fs::canonicalize`. Строгая проверка вхождения в `allowed_config_dirs` на 100% блокирует любые попытки обхода каталогов через внешние симлинки.
* **Filesystem Guard:** Категорический запрет на запись в `/etc/shadow`, `/etc/sudoers`, `/boot`, `/dev`, `/proc`, `/sys`.

### 3. Квоты фоновых задач (TaskManager)
* `max_active_tasks = 8`: Жесткий лимит на число одновременно работающих фоновых процессов.
* `max_retained_tasks = 100`: Ограничение на количество задач, сохраняемых в истории.
* `output_limit_bytes = 5242880` (5 МБ): Защита от переполнения оперативной памяти буферами вывода.
* `completed_ttl_secs = 3600` (1 час): Автоматическая очистка завершенных задач.
* **Изоляция процессов:** Завершение задачи убивает всю группу процессов (включая дочерние подпроцессы).

---

## 🌐 Сетевые транспорты и Bearer-авторизация

`vibe-daemon` поддерживает три режима работы:
1. **`stdio`**: Локальный режим для работы с десктопными клиентами (Claude Desktop, Cursor). Стандартный вывод зарезервирован исключительно под протокол JSON-RPC, логирование выводится в `stderr`.
2. **`http` (Streamable HTTP)**: Высокопроизводительный HTTP-сервер на базе `axum`. Эндпоинт `POST /mcp` принимает стандартные вызовы JSON-RPC 2.0.
3. **`sse` (Server-Sent Events)**: Двунаправленный сетевой режим. Эндпоинт `GET /sse` открывает постоянный поток событий и уведомлений, а запросы отправляются на `POST /mcp`.

### Безопасность сетевого транспорта (Loopback и Bearer Auth)
Демон придерживается строгой модели защиты:
* **Локальное подключение:** При привязке к loopback-интерфейсам (`127.0.0.1` или `[::1]`) демон доступен только локальным процессам хоста.
* **Удаленное подключение (Fail-closed):** При попытке привязки к внешним интерфейсам (`0.0.0.0`, публичные IP) демон **требует обязательного наличия непустого токена** в конфигурации. Запуск с внешним bind без токена немедленно завершается с ошибкой `Remote HTTP/SSE bind requires an auth_token`.

Для защиты сетевых интерфейсов в секции `[security]` настраивается секретный токен:
```toml
[security]
auth_token = "your-super-secret-token"
```
Все сетевые клиенты обязаны передавать заголовок:
```http
Authorization: Bearer your-super-secret-token
```
При отсутствии или несовпадении токена запрос немедленно отклоняется со статусом `401 Unauthorized`.

---

## 📦 MCP Resources и подписки

Демон реализует спецификацию **MCP Resources** (`resources/list`, `resources/read`, `resources/subscribe`, `resources/unsubscribe`):
* **`system://`**:
  * `system://status` — мгновенный срез состояния системы (JSON);
  * `system://ports` — активные слушающие порты и установленные TCP-соединения;
  * `system://services` — операционные статусы ключевых системных служб (`inspector.key_services`).
* **`config://`**:
  * Чтение конфигураций из белого списка каталогов (например, `config://nginx/nginx.conf`) с канонической защитой от симлинков (`canonicalize`).
* **`log://`**:
  * Доступ к журналам сервисов из разрешенных каталогов (например, `log://nginx/access.log`).

Клиенты могут подписываться на изменение ресурсов. При фиксации изменений демон автоматически рассылает уведомления подписанным сессиям.

---

## 📡 Шина асинхронных уведомлений (Server-Initiated Notifications)

Демон оснащен транспортно-нейтральной шиной событий (`EventBus`) с встроенными периодическими продюсерами (`producers`), отправляющими стандартные JSON-RPC 2.0 уведомления без `id`:
* **`notifications/resources/updated`**: Уведомления об изменении отслеживаемого ресурса по URI (`ResourceUpdated`).
* **`notifications/system/memory_threshold`**: Предупреждение о превышении порога RAM (`MemoryThresholdExceeded`).
* **`notifications/services/down`**: Уведомление о падении ключевой службы (`ServiceDown`).
* **`notifications/certificates/expiring`**: Предупреждение о приближении срока окончания SSL-сертификата (`CertificateExpiring`).
* **Завершение фоновых задач (`notifications/tasks/completed`)**: При завершении длительной задачи клиент получает событие со статусом и taskId без необходимости циклического опроса.
* **Доставка в Stdio**: Атомарный цикл `select!` предотвращает интерливинг строк между ответами на запросы и асинхронными нотификациями.
* **Доставка в SSE**: Буферизованная неблокирующая передача подписчикам через `try_send` с защитой от зависания медленных клиентов.

---

## ⚙️ Конфигурация (`config.example.toml`)

Все параметры опциональны и используют безопасные дефолты при отсутствии:

```toml
[daemon]
log_level = "info"                         # trace, debug, info, warn, error
default_command_timeout_secs = 30          # Базовый таймаут выполнения команд
max_stdout_bytes = 1048576                 # Лимит вывода stdout в памяти (1 МБ)
max_stderr_bytes = 1048576                 # Лимит вывода stderr в памяти (1 МБ)
termination_grace_ms = 2000                # Время на мягкое завершение перед SIGKILL
# audit_log_path = "/var/log/vibe-daemon/audit.jsonl"

[audit]
# log_path = "/var/log/vibe-daemon/audit.jsonl"

[security]
protected_ports = [22]                     # Защищенные порты (SSH)
protected_services = [                     # Защищенные системные службы
    "vibe-daemon",
    "sshd",
    "ssh",
    "NetworkManager",
    "systemd-networkd",
    "networking",
    "systemd-resolved"
]
max_calls_per_minute = 60                  # Глобальный лимит вызовов (0 = без лимита)
# auth_token = "your-secret-bearer-token"  # Bearer токен для HTTP/SSE транспорта

# [security.tool_limits]                   # Индивидуальные лимиты вызова инструментов
# execute_safe_command = 10

# protected_write_paths = ["/var/data/critical", "/srv/production"]

[inspector]
allowed_config_dirs = [                    # Разрешенные каталоги для чтения/записи конфигов
    "/etc/nginx",
    "/etc/caddy",
    "/etc/supervisor",
    "/etc/haproxy",
    "/etc/letsencrypt"
]
key_services = [                           # Ключевые сервисы для системного инспектора
    "nginx",
    "sshd",
    "docker",
    "postgresql"
]

[tasks]
max_active_tasks = 8                       # Максимум одновременно активных задач
max_retained_tasks = 100                   # Максимум сохраненных задач в истории
output_limit_bytes = 5242880               # Буфер логов задачи (5 МБ)
completed_ttl_secs = 3600                  # Время жизни завершенной задачи (1 час)
termination_grace_secs = 3                 # Grace period завершения задачи перед SIGKILL
```

---

## 🛠️ Сборка и запуск

### Требования
* **Rust:** версия 1.85+ (редакция 2024).
* **ОС:** Linux, macOS, Windows (развертывание на production Linux-хосте с физическим управлением Docker, systemd, Nginx и Certbot подлежит отдельной физической приемке).

### Сборка
```bash
git clone https://github.com/Rik-Freeman/vibe-daemon.git
cd vibe-daemon

# Сборка релизной версии
cargo build --release --locked
```

Бинарный файл доступен в `target/release/vibe-daemon`.

### Опции командной строки
```text
Usage: vibe-daemon [OPTIONS]

Options:
  -c, --config <CONFIG>       Путь к файлу конфигурации TOML (см. config.example.toml)
  -a, --audit-log <AUDIT_LOG> Путь к файлу аудита JSONL
  -f, --log-file <LOG_FILE>   Путь к файлу логов демона (по умолчанию stderr)
  -l, --log-level <LOG_LEVEL> Уровень логирования (trace, debug, info, warn, error)
  -t, --transport <TRANSPORT> Режим транспорта: stdio, http, sse (по умолчанию: stdio)
      --host <HOST>           Сетевой интерфейс привязки (по умолчанию: 127.0.0.1)
  -p, --port <PORT>           Сетевой порт привязки (по умолчанию: 8900)
  -h, --help                  Справка
  -V, --version               Версия
```

### Примеры запуска

#### 1. Локальный Stdio (по умолчанию)
```bash
vibe-daemon --config config.example.toml --audit-log audit.jsonl
```

#### 2. Сетевой HTTP / SSE с Bearer авторизацией
```bash
# Локальный bind на loopback:
vibe-daemon --transport sse --host 127.0.0.1 --port 8900 --config config.example.toml

# Внешний bind (требует обязательный auth_token в config.toml):
vibe-daemon --transport sse --host 0.0.0.0 --port 8900 --config config.example.toml
```

---

## 🔌 Подключение к MCP-клиентам

### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "vibe-daemon": {
      "command": "/usr/local/bin/vibe-daemon",
      "args": ["--config", "/etc/vibe-daemon/config.toml"]
    }
  }
}
```

### Cursor (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "vibe-daemon": {
      "command": "vibe-daemon",
      "args": ["--log-level", "info"]
    }
  }
}
```

### Antigravity IDE (`mcp_config.json`)
```json
{
  "mcpServers": {
    "vibe-daemon": {
      "command": "vibe-daemon",
      "args": ["--config", "config.example.toml"]
    }
  }
}
```

---

## 🧪 Тестирование и верификация

Демон покрыт всесторонними модульными и интеграционными тестами (238 тестов):
* Модульные тесты Guard Engine, Rate Limiter, Tamper-evident Audit, File Ops, Task Manager, Resources, Event Bus.
* Сквозные интеграционные тесты протокола MCP (Stdio handshake, tools/list, tools/call, resources/list, resources/subscribe, server notifications).

```bash
# Проверка форматирования
cargo fmt --all -- --check

# Проверка статическим анализатором без предупреждений
cargo clippy --all-targets -- -D warnings

# Запуск полного набора тестов
cargo test --all-targets --locked
```

---

## 📁 Структура кодовой базы

```text
vibe-daemon/
├── Cargo.toml                  # Зависимости и конфигурация пакета (Rust 2024)
├── config.example.toml         # Эталонный конфигурационный файл со всеми секциями
├── implementation_checklist.md # Синхронизированный чеклист всех фаз и этапов
├── mcp_config.json             # Конфигурация для MCP-клиентов
├── README.md                   # Архитектурная и эксплуатационная документация
├── src/
│   ├── main.rs                 # Парсинг CLI (clap), инициализация логов и запуск транспорта
│   ├── lib.rs                  # Корневая библиотека и экспорт публичных модулей
│   ├── config.rs               # Строгая конфигурация (fail-closed) и дефолты
│   ├── audit.rs                # Tamper-evident Audit Trail (SHA-256 хэш-цепочка + redaction)
│   ├── rate_limiter.rs         # Sliding Window Rate Limiter
│   ├── tasks.rs                # Background TaskManager (квоты, TTL, изоляция процессов)
│   ├── events/                 # Шина асинхронных уведомлений (EventBus, ServerEvent)
│   ├── guard/                  # Защитный барьер безопасности (Firewall, FS Guard, Path Guard)
│   ├── inspector/              # Системный инспектор (состояние, память, сокеты, службы)
│   ├── executor/               # Исполнитель команд и Smart Log Engine
│   ├── mcp/                    # Протокол Model Context Protocol (Dispatcher & Protocol Types)
│   ├── resources/              # Подсистема MCP Resources (провайдеры system://, config://, log://)
│   ├── tools/                  # Каталог 33 инструментов (McpTool trait & ToolRegistry)
│   │   ├── registry.rs         # Реестр инструментов и контекст выполнения ToolContext
│   │   ├── system.rs           # Системные инструменты (get_system_status, execute, ports, services)
│   │   ├── file_ops.rs         # Файловые инструменты (list, read, write, search, tail)
│   │   ├── config_writer.rs    # Запись конфигураций с синтаксической проверкой и rollback
│   │   ├── monitoring.rs       # Мониторинг диска, CPU, процессов, сети и journalctl
│   │   ├── docker.rs           # Управление Docker (ps, logs, restart, compose, stats)
│   │   ├── webserver.rs        # Управление Nginx (test, reload, sites)
│   │   └── ssl.rs              # Управление SSL-сертификатами (expiry, renew, list)
│   └── transport/              # Сетевой и Stdio транспорт (Stdio, Streamable HTTP, SSE)
└── tests/
    └── integration_test.rs     # Сквозные интеграционные тесты протокола и нотификаций
```

---

## 📄 Лицензия

Распространяется под лицензией MIT. Подробности в файле [LICENSE](LICENSE).
