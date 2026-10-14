# 📋 vibe-daemon — Чеклист Реализации

> Рабочий трекер для пошаговой реализации. Отмечай `[x]` по мере завершения.

---

## Phase 1: Hardening (Безопасность и надёжность)

### 1.1 Конфигурационный файл (TOML)
- [x] Добавить `toml` в `Cargo.toml` зависимости
- [x] Создать `src/config.rs` — структуры конфигурации (`DaemonConfig`, `SecurityConfig`, `InspectorConfig`, `TasksConfig`, `AuditConfig`)
- [x] Создать `config.example.toml` в корне проекта
- [x] Добавить CLI-флаг `--config <path>` в [`main.rs`](file:///c:/Users/User/Desktop/vibe-daemon/src/main.rs)
- [x] Рефакторинг `protected_ports`, `protected_services`, `allowed_config_dirs` — вынести из хардкода в конфиг
- [x] Рефакторинг `command_timeout` (30s) — сделать настраиваемым
- [x] Fallback на дефолтные значения если конфиг не указан
- [x] Тесты загрузки конфига

### 1.2 Аудит-лог (Audit Trail)
- [x] Создать `src/audit.rs` — `AuditLogger` struct
- [x] Формат записи: JSONL (JSON Lines) в файл
- [x] Поля: timestamp, tool_name, arguments, result_status, duration_ms, client_info, entry_id, prev_entry_hash, entry_hash
- [x] Интеграция в `McpDispatcher::handle_tools_call()` — логирование каждого вызова
- [x] CLI-флаг `--audit-log <path>` или секция в конфиге
- [x] Tamper-evident хэш-цепочка (SHA-256) и верификация целостности
- [x] Автоматическое маскирование секретов (Bearer токены, пароли, приватные ключи)
- [x] Гарантированный сброс на диск (flush / sync_data)

### 1.3 Rate Limiting
- [x] Создать `src/rate_limiter.rs` — sliding window rate limiter
- [x] Настраиваемые лимиты: max_calls_per_minute, max_calls_per_tool_per_minute (`tool_limits`)
- [x] Интеграция в `McpDispatcher` — проверка перед выполнением tool call
- [x] Возвращать понятную ошибку при превышении лимита

### 1.4 Исправление технического долга
- [x] [`mcp/mod.rs:14`](file:///c:/Users/User/Desktop/vibe-daemon/src/mcp/mod.rs#L14) — заменить `SERVER_VERSION` на `env!("CARGO_PKG_VERSION")`
- [x] [`sys.rs:333`](file:///c:/Users/User/Desktop/vibe-daemon/src/inspector/sys.rs#L333) — расширить `default_allowed_dirs`: добавить `/etc/caddy`, `/etc/supervisor`, `/etc/haproxy`, `/etc/letsencrypt`
- [x] [`firewall.rs:295`](file:///c:/Users/User/Desktop/vibe-daemon/src/guard/firewall.rs#L295) — fallback в `find_alternative_port` проверяет занятость портов
- [x] [`sys.rs:374`](file:///c:/Users/User/Desktop/vibe-daemon/src/inspector/sys.rs#L374) — добавить лимит размера файла в `safe_read_config_file` (1 MB)
- [x] [`firewall.rs:119`](file:///c:/Users/User/Desktop/vibe-daemon/src/guard/firewall.rs#L119) — сделать стриппинг `sudo`/`doas`/`nohup` рекурсивным (через `loop`)
- [x] [`runner.rs:8`](file:///c:/Users/User/Desktop/vibe-daemon/src/executor/runner.rs#L8) — добавить лимит на размер stdout/stderr (предотвращение OOM)
- [x] [`sys.rs:313`](file:///c:/Users/User/Desktop/vibe-daemon/src/inspector/sys.rs#L313) — сделать `key_services` настраиваемым через конфиг
- [x] Добавить `pub mod config;` в [`lib.rs`](file:///c:/Users/User/Desktop/vibe-daemon/src/lib.rs)

---

## Phase 2: Core Tools (Базовые инструменты)

### 2.1 File Operations
- [x] Создать `src/tools/` директорию — модульная архитектура
- [x] `src/tools/mod.rs` — общий интерфейс и экспорт модулей
- [x] `src/tools/file_ops.rs`:
  - [x] `list_directory` — с детерминированной курсорной пагинацией и лимитом глубины
  - [x] `read_file` — с лимитом размера, path traversal guard и проверкой секретов
  - [x] `write_file` — атомарная запись через tempfile, автобэкап, path guard и защита symlink
  - [x] `search_files` — grep/find с ограничениями и исключением виртуальных ФС
  - [x] `tail_logs` — чтение последних N строк с конца файла (seek с буферизацией)
- [x] Guard-правила для файловых операций (запрет записи в системные директории)
- [x] Регистрация в `tools/list` и `tools/call` через `ToolRegistry`
- [x] Тесты для каждой операции

### 2.2 Write Server Config (с бэкапом)
- [x] `write_server_config` tool — запись конфига с автобэкапом
- [x] Валидация синтаксиса перед записью (`nginx -t`, автоподстановка для `/etc/nginx`)
- [x] Автоматический rollback при ошибке валидации (восстановление из бэкапа)
- [x] Guard: запрет перезаписи `/etc/shadow`, `/etc/passwd` и выход за пределы `allowed_config_dirs`

### 2.3 Расширенный мониторинг
- [x] `src/tools/monitoring.rs`:
  - [x] `get_disk_usage` — парсинг `df -h` / кроссплатформенный сбор метрик ФС
  - [x] `get_cpu_info` — `/proc/stat`, `/proc/loadavg`, ядра и частоты
  - [x] `get_top_processes` — top-N по CPU/RAM
  - [x] `get_network_stats` — `/proc/net/dev`, подсчет открытых соединений
  - [x] `tail_service_logs` — чтение логов `journalctl` с фильтрацией `--since` и `--until` (RFC 3339)
- [x] Smart compression для логов сервисов

### 2.4 Background Tasks
- [x] `src/tasks.rs` — `TaskManager` struct
- [x] Квоты и лимиты: `max_active_tasks`, `max_retained_tasks`, `output_limit_bytes`
- [x] Изоляция и гарантированное завершение процессных деревьев (process group / Job Object)
- [x] Tools:
  - [x] `start_background_task` — асинхронный запуск с генерацией TaskId
  - [x] `check_task_status` — статус (Running, Completed, Failed, Cancelled) + exit_code + duration
  - [x] `get_task_output` — чтение вывода с пагинацией/лимитом строк
  - [x] `cancel_task` — мягкое завершение (SIGTERM / grace period) с переходом в SIGKILL
- [x] Guard-проверка команд перед фоновым запуском
- [x] Автоочистка завершённых задач по TTL (`completed_ttl_secs`)

---

## Phase 3: Integrations (Интеграции)

### 3.1 Docker Manager
- [x] `src/tools/docker.rs`:
  - [x] `docker_ps` — список контейнеров (форматированный JSON)
  - [x] `docker_logs` — чтение логов контейнеров со smart compression
  - [x] `docker_restart` — безопасный перезапуск контейнера
  - [x] `docker_compose_up` — запуск Compose стека
  - [x] `docker_stats` — метрики CPU/RAM/Network контейнеров
- [x] Guard: запрет деструктивных операций без подтверждения
- [x] Защита от shell injection: вызов команд напрямую через раздельные аргументы (`Command::args`)

### 3.2 Nginx/Caddy Manager
- [x] `src/tools/webserver.rs`:
  - [x] `nginx_test_config` — проверка конфигурации (`nginx -t`)
  - [x] `nginx_reload` — безопасная перезагрузка конфигурации после теста
  - [x] `nginx_list_sites` — список сайтов и виртуальных хостов (`sites-available`, `sites-enabled`)
  - [x] `nginx_enable_site` / `nginx_disable_site` — управление симлинками сайтов
- [x] Интеграция с `write_server_config` — превентивная валидация синтаксиса

### 3.3 SSL Certificate Manager
- [x] `src/tools/ssl.rs`:
  - [x] `ssl_check_expiry` — проверка сроков действия сертификатов
  - [x] `ssl_certbot_renew` — обновление сертификатов через Certbot
  - [x] `ssl_list_certs` — инвентаризация локальных сертификатов
- [x] Защита от shell injection: прямая передача параметров без шелла

### 3.4 Journal/Log Tail
- [x] `tail_service_logs` — вызов `journalctl` с аргументами без shell-интерполяции
- [x] Поддержка временных диапазонов `--since` и `--until` в формате RFC 3339
- [x] Smart compression для длинных журнальных выводов

---

## Phase 4: Architecture (Архитектурные изменения)

### 4.1 Plugin System (Trait-based Tools)
- [x] Создать `src/tools/registry.rs`:
  - [x] Трейт `McpTool` (`name`, `description`, `input_schema`, `execute`)
  - [x] Структура `ToolContext` с конфигурацией, аудитом, rate limiter и task manager
  - [x] Структура `ToolRegistry` с динамической регистрацией и поиском инструментов
- [x] Полный перевод всех 33 инструментов на модульный трейт `McpTool`
- [x] Делегирование `tools/list` и `tools/call` через `ToolRegistry`

### 4.2 HTTP/SSE Транспорт
- [x] Интеграция `axum` и Tokio сетевого стека в `src/transport/`
- [x] `src/transport/mod.rs` — перечисление `TransportType` (Stdio, Http, Sse)
- [x] `src/transport/stdio.rs` — транспорт через Stdio с асинхронным циклом сообщений и событий
- [x] `src/transport/http.rs` — Streamable HTTP и Server-Sent Events (SSE)
- [x] CLI-флаги `--transport`, `--host`, `--port`
- [x] Bearer Token авторизация для сетевых эндпоинтов

### 4.3 MCP Resources
- [x] Подсистема MCP Resources в `src/resources/`
- [x] Протокольные методы: `resources/list`, `resources/read`, `resources/subscribe`, `resources/unsubscribe`
- [x] Провайдерно-ориентированный трейт `ResourceProvider`
- [x] Встроенные провайдеры схем:
  - [x] `system://` (`system://status`, `system://ports`, `system://services`)
  - [x] `config://` (безопасное чтение конфигураций с проверкой `allowed_config_dirs`)
  - [x] `log://` (чтение логов из разрешенных каталогов)
- [x] Сессионный реестр подписок `ResourceSubscriptionManager`

### 4.4 Server → Client Notifications
- [x] Транспортно-нейтральная шина событий `EventBus` (`src/events/`)
- [x] Системные события `ServerEvent`:
  - [x] Завершение фоновых задач (`task_completed`)
  - [x] Обновление ресурсов (`resource_updated`)
  - [x] Системные пороги (`system_alert`)
- [x] JSON-RPC нотификации без `id` (`notifications/message`, `notifications/resources/updated`)
- [x] Интеграция доставки уведомлений в Stdio (атомарный цикл без интерливинга)
- [x] Интеграция доставки в SSE (сессионная фильтрация и `try_send` с буферизацией)

---

## Phase 5: Production & Publishing (Подготовка к релизу и CI/CD)

### 5.1 Метаданные и публикация
- [x] Заполнить метаданные в `Cargo.toml` (`description`, `repository`, `license`, `keywords`, `categories`, `authors`, `readme`)
- [x] Настроить `.gitignore` (исключение артефактов сборки, логов, бэкапов, конфигов и IDE)
- [x] Лицензия `LICENSE` (MIT)

### 5.2 CI/CD Automation
- [x] `.github/workflows/ci.yml` — автоматический CI пайплайн (push/PR: checkout, toolchain, rust-cache, fmt check, clippy -D warnings, test --all-targets)

---

## 🛡️ Remediation & Hardening Stages (Этапы 0–9)

- [x] **Этап 0: Baseline & Strict Lints** — устранение warnings, clippy check, стабилизация базовой сборки.
- [x] **Этап 1: MCP Protocol Hardening & Trait Plugin System** — 33 инструмента, унификация сигнатур, ToolRegistry.
- [x] **Этап 2: Fail-closed конфигурация и гибкий инспектор** — разделение отсутствия и повреждения конфига, кастомизация key_services и allowed_config_dirs.
- [x] **Этап 3: Надежные файловые операции** — bounded tail через seek, курсорная пагинация list_directory, атомарная запись с backup и защитой от symlink-атак.
- [x] **Этап 4: Укрепление менеджера фоновых задач** — квоты `max_active_tasks`, `max_retained_tasks`, `output_limit_bytes`, TTL очистка, завершение деревьев процессов.
- [x] **Этап 5: Укрепленный Audit Trail** — криптографическая хэш-цепочка (SHA-256), маскирование секретов (Bearer, private keys, passwords), fsync/sync_data durability.
- [x] **Этап 6: Журналы Journalctl и исключение Shell Injection** — временные диапазоны RFC 3339 (--since, --until), аудит всех внешних команд на `Command::args`.
- [x] **Этап 7: Подсистема MCP Resources** — провайдеры `system://`, `config://`, `log://`, сессионный менеджер подписок, валидация путей.
- [x] **Этап 8: Server-Initiated Notifications** — транспортно-нейтральная шина событий, нотификации для Stdio и SSE, защита от гонок и зависания клиентов.
- [x] **Этап 9: Документация, Cleanup и Финальная полировка** — актуализация README.md, config.example.toml, синхронизация чеклиста, cargo fmt, clippy -D warnings, 227+ тестов.

---

## 📌 Финальная приемка (Definition of Done)

1. **Компиляция**: `cargo build --release` без warnings
2. **Тесты**: `cargo test` — 227 тестов проходят со 100% успехом
3. **Clippy**: `cargo clippy --all-targets -- -D warnings` — 0 предупреждений
4. **Форматирование**: `cargo fmt --check` — чисто
5. **Безопасность**: Guard Engine защищает порты, службы, ФС, исключает shell injection
6. **Документация**: README.md и config.example.toml полностью отражают функционал
