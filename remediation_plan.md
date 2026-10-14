# План исправления замечаний приёмки vibe-daemon

## 1. Цель и границы

Этот план закрывает замечания приёмки фаз 1–4 из `project_analysis.md`:

- Phase 1 — Hardening;
- Phase 2 — Core Tools;
- Phase 3 — Integrations;
- Phase 4 — Architecture.

Phase 5 — RBAC, packaging, CI/CD, Prometheus и production deployment — остаётся вне текущего scope.

После выполнения работ проект получает статус не выше `CANDIDATE_ACCEPTED`, пока не завершены реальные Linux-проверки Docker, systemd, Nginx и certbot.

```text
Baseline
   ↓
Безопасность памяти и конфигурации
   ↓
Надёжность файлов и background tasks
   ↓
Интеграции и Linux evidence
   ↓
MCP Resources
   ↓
Notification bus и transport delivery
   ↓
Полный acceptance gate
```

---

## 2. Этап 0 — зафиксировать критерии и baseline

До исправлений необходимо отделить текущее состояние от результатов будущих изменений.

### Задачи

1. Применить `cargo fmt --all`.
2. Зафиксировать текущий список из 33 инструментов машинно-читаемым тестом.
3. Составить матрицу требований фаз 1–4:
   - критерий;
   - реализация;
   - unit test;
   - integration test;
   - физическая Linux-проверка;
   - статус.
4. Обновить `implementation_checklist.md`, но отмечать `[x]` только после появления проверяемого evidence.
5. После согласования создать исходный Git checkpoint. Сейчас все файлы untracked, поэтому сравнение с baseline невозможно.

### Критерий выхода

- `cargo fmt --check` проходит;
- текущая версия воспроизводимо собирается;
- есть baseline commit или сохранённый manifest хешей;
- ни один ещё не проверенный пункт не помечен как завершённый.

---

## 3. Этап 1 — ограниченное выполнение команд

Это главный эксплуатационный риск: обычный command runner накапливает весь stdout/stderr в памяти.

### 3.1 Новая модель bounded capture

Заменить `Command::output()` в `src/executor/runner.rs` на управляемый запуск:

```rust
pub struct CommandLimits {
    pub timeout: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub termination_grace: Duration,
}

pub struct CommandOutcome {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
}
```

Требования реализации:

- stdout и stderr читаются конкурентно;
- в памяти сохраняется не более настроенного лимита;
- после достижения лимита pipe продолжает опустошаться, чтобы дочерний процесс не заблокировался;
- результат содержит явный маркер truncation;
- timeout завершает не только оболочку, но и дерево процессов;
- после kill обязательно выполняется `wait()`, чтобы не оставлять zombie process;
- лимиты применяются ко всем tool-интеграциям, использующим executor.

Добавить в конфигурацию:

```toml
[daemon]
default_command_timeout_secs = 30
max_stdout_bytes = 1048576
max_stderr_bytes = 1048576
termination_grace_ms = 2000
```

### 3.2 Тесты

Добавить проверки:

- команда генерирует 10–100 МБ stdout;
- большой stderr;
- одновременный большой stdout и stderr;
- бесконечная команда завершается по timeout;
- процесс с дочерним процессом не остаётся после отмены;
- маркер truncation появляется ровно один раз;
- RSS демона не растёт пропорционально размеру полного вывода.

### Критерий выхода

- 100 МБ вывода не приводит к накоплению 100 МБ в daemon;
- после timeout не остаётся дочерних процессов;
- все shell-based инструменты используют один bounded executor.

---

## 4. Этап 2 — fail-closed конфигурация

### 4.1 Разделить отсутствие и повреждение конфига

Текущий `load_or_default` заменить:

```rust
pub fn load(path: Option<&Path>) -> Result<Config, ConfigError>
```

Поведение:

- `--config` не указан → безопасные defaults;
- `--config` указан, но файл отсутствует → завершение с ошибкой;
- TOML повреждён → завершение с ошибкой;
- неизвестное критическое поле → ошибка, желательно через `deny_unknown_fields`;
- некорректные диапазоны → ошибка валидации;
- пустой `auth_token`, нулевые byte limits и чрезмерный timeout обрабатываются явно.

Это предотвратит незаметный сброс пользовательских protected ports/services.

### 4.2 Сделать инспектор полностью конфигурируемым

Расширить `InspectorConfig`:

```rust
pub struct InspectorConfig {
    pub allowed_config_dirs: Vec<PathBuf>,
    pub key_services: Vec<String>,
}
```

Убрать hardcode из `src/inspector/sys.rs`.

Пример:

```toml
[inspector]
key_services = ["nginx", "sshd", "docker", "postgresql"]
```

### 4.3 Валидация конфигурации

Добавить `Config::validate()`:

- нет дубликатов protected ports;
- порт не равен `0`;
- пути нормализованы;
- output limits имеют допустимые минимум и максимум;
- rate limits не превышают разумный предел;
- `allowed_config_dirs` не содержит `/`;
- audit path не пересекается с запрещёнными путями;
- HTTP на non-loopback без auth отклоняется либо требует явного небезопасного флага.

### Критерий выхода

- переданный пользователем повреждённый конфиг никогда не заменяется defaults;
- все значения, объявленные конфигурируемыми в Phase 1, реально используются.

---

## 5. Этап 3 — исправить файловые операции

### 5.1 Настоящий bounded `tail_logs`

Вместо полного `tokio::fs::read`:

1. открыть файл через `File`;
2. получить длину;
3. перейти через `seek(SeekFrom::End(...))`;
4. прочитать максимум `max_tail_bytes`;
5. отбросить первую неполную строку;
6. выбрать последние N строк;
7. корректно обработать UTF-8 boundary.

Добавить параметр конфигурации:

```toml
[security]
max_tail_bytes = 5242880
```

Тесты:

- sparse-файл размером более 1 ГБ;
- последняя строка без `\n`;
- UTF-8 символ пересекает границу read window;
- бинарный файл;
- файл меняется во время чтения.

### 5.2 Пагинация `list_directory`

Расширить контракт:

```json
{
  "path": "/srv/apps",
  "max_depth": 1,
  "limit": 100,
  "cursor": "..."
}
```

Ответ:

```json
{
  "entries": [],
  "next_cursor": "...",
  "truncated": true
}
```

Cursor должен кодировать нормализованный последний путь и параметры запроса. Нельзя использовать простой числовой offset без стабильной сортировки.

Тесты:

- более 500 элементов;
- отсутствие дубликатов между страницами;
- изменение каталога между страницами;
- невалидный cursor;
- symlink и permission errors.

### 5.3 Backup и атомарная запись `write_file`

Обычный `write_file` должен:

1. проверить путь и canonical parent;
2. при существующем файле создать backup;
3. записать данные во временный файл в том же каталоге;
4. выполнить `flush`/`sync_all`;
5. сохранить необходимые permissions;
6. атомарно заменить целевой файл;
7. удалить временный файл при ошибке.

Результат должен возвращать `backup_path`. Для новых файлов backup может быть `null`.

### 5.4 Защита от symlink/TOCTOU

Перед записью и перед rename повторно проверить canonical parent и target. На Linux желательно использовать `openat`/`O_NOFOLLOW` либо аналогичный безопасный механизм.

### Критерий выхода

- операции не загружают большие файлы целиком;
- пагинация работает детерминированно;
- существующий файл можно восстановить из backup;
- symlink не позволяет выйти в защищённый путь.

---

## 6. Этап 4 — Background Tasks

### 6.1 Ограничения и квоты

Добавить:

```toml
[tasks]
max_active_tasks = 8
max_retained_tasks = 100
output_limit_bytes = 5242880
completed_ttl_secs = 3600
termination_grace_secs = 3
```

`TaskManager` должен отклонять новые задачи при достижении лимита.

### 6.2 Управление процессной группой

На Unix:

- запускать задачу в отдельной process group;
- cancel сначала посылает SIGTERM группе;
- ждать grace period;
- затем SIGKILL;
- выполнить `wait()`.

На Windows:

- использовать отдельную process group или Job Object;
- завершать полное дерево процессов;
- не ограничиваться уничтожением `cmd.exe`.

### 6.3 Исправить гонки состояний

Нужен единый переход состояний:

```text
Running → Success
Running → Failed
Running → Cancelling → Cancelled
```

После `Cancelled` worker не должен переписать состояние на `Failed` или `Success`.

### 6.4 TTL cleanup

Варианты реализации:

- периодический cleanup worker;
- lazy cleanup перед `start_task` и `check_status`.

Удалять только завершённые задачи старше TTL. Для диагностики добавить счётчики retained/active.

### 6.5 Тесты

- превышение `max_active_tasks`;
- cancel во время естественного завершения;
- многократный cancel;
- процесс с дочерним процессом;
- TTL cleanup;
- ограничение количества retained tasks;
- параллельный output stdout/stderr;
- отсутствие превышения output buffer.

### Критерий выхода

- дерево процессов гарантированно прекращается;
- память TaskManager ограничена;
- состояние задачи детерминировано при гонках.

---

## 7. Этап 5 — Audit Trail

Требование «неизменяемый лог» необходимо разделить на tamper-evident журнал внутри приложения и OS-level защиту.

### 7.1 Tamper-evident журнал

Расширить запись:

```json
{
  "sequence": 42,
  "timestamp": "...",
  "tool": "...",
  "arguments": {},
  "status": "success",
  "previous_hash": "...",
  "record_hash": "..."
}
```

`record_hash` вычисляется по канонической сериализации записи и `previous_hash`.

При старте:

- проверить последовательность;
- проверить hash-chain;
- отказать или явно сигнализировать при повреждении.

### 7.2 Durability

- bounded channel вместо `unbounded_channel`;
- определённая политика при переполнении;
- tool call не должен считаться успешно проаудированным, если обязательная запись потеряна;
- `flush` и `sync_data`;
- graceful close writer;
- обязательный flush при завершении stdio и сетевого транспорта;
- ошибки записи отражаются в health/status, а не только в tracing.

### 7.3 Редактирование секретов

Не записывать открытым текстом:

- bearer tokens;
- private keys;
- полное содержимое конфигураций;
- потенциальные пароли в command arguments.

В журнале хранить redacted value и, при необходимости, hash содержимого.

### 7.4 OS-level immutability

Это отдельный deployment-критерий:

- минимальные permissions;
- отдельный владелец файла;
- journald/remote syslog;
- append-only filesystem attribute, если он применяется.

Обычный локальный JSONL-файл нельзя называть неизменяемым без этого слоя.

### Критерий выхода

- потерянная audit-запись является наблюдаемой ошибкой;
- изменение старой строки обнаруживается проверкой цепочки;
- shutdown дожидается записи очереди.

---

## 8. Этап 6 — довести интеграции Phase 3

### 8.1 Journal filtering

Расширить `tail_service_logs`:

```json
{
  "service_name": "nginx",
  "lines": 100,
  "since": "2026-10-14T00:00:00Z",
  "until": "2026-10-14T01:00:00Z"
}
```

Требования:

- строгий парсинг RFC 3339;
- `since <= until`;
- максимальный диапазон;
- аргументы передаются через `Command::args`, а не конкатенацией shell-строки;
- output проходит через bounded executor и smart compression.

### 8.2 Интеграционные команды без shell injection

Docker, Nginx, certbot и journalctl по возможности должны запускаться как:

```rust
Command::new("docker").args([...])
```

Входные значения должны быть отдельными аргументами, а не частями командной строки.

### 8.3 Linux physical test environment

На отдельной VM или disposable container-host проверить:

- Docker daemon доступен;
- `docker_ps`, logs, stats;
- restart тестового контейнера;
- compose up тестового стека;
- `nginx -t`;
- enable/disable site с rollback;
- реальный `systemctl reload nginx`;
- чтение journalctl с `since`/`until`;
- локальный тестовый сертификат;
- certbot только dry-run в изолированном окружении.

Каждый mutating test должен иметь cleanup.

### Критерий выхода

- результаты получены от реальных бинарников, а не от mock/fallback;
- сохранены команды, версии, stdout/stderr, exit codes и cleanup status;
- Windows unit tests не выдаются за Linux acceptance.

---

## 9. Этап 7 — MCP Resources

### 9.1 Протокольные типы

Добавить в `protocol.rs`:

- `ResourcesCapability`;
- `Resource`;
- `ResourceContents`;
- `resources/list`;
- `resources/read`;
- `resources/subscribe`;
- `resources/unsubscribe`;
- cursor pagination;
- стандартные MCP error responses.

В `initialize` объявлять `resources` только когда handlers действительно активны.

### 9.2 Provider-based registry

Не хардкодить URI в dispatcher. Добавить:

```rust
#[async_trait]
pub trait ResourceProvider: Send + Sync {
    fn schemes(&self) -> &[&str];
    async fn list(&self, cursor: Option<&str>) -> Result<ResourcePage, ResourceError>;
    async fn read(&self, uri: &str) -> Result<ResourceContents, ResourceError>;
}
```

Первые providers:

- `system://status`;
- `config://nginx/...`;
- `log://service/...`.

Все чтения обязаны повторно использовать существующие guard и size limits.

### 9.3 Подписки

Хранить подписки по session, а не глобально:

```text
session_id → set(resource_uri)
```

Событие изменения ресурса должно отправляться только подписанным клиентам.

### 9.4 Тесты

- initialize capability;
- list/read;
- неизвестная схема;
- path traversal в URI;
- oversized resource;
- subscribe/unsubscribe;
- disconnect cleanup;
- несколько независимых клиентов.

### Критерий выхода

- физический `resources/list` возвращает ресурсы;
- `resources/read` применяет те же guard-политики, что и tools;
- подписки не протекают между сессиями.

---

## 10. Этап 8 — Server-Initiated Notifications

### 10.1 Transport-neutral event bus

```rust
pub enum ServerEvent {
    TaskCompleted { task_id: String, status: TaskStatus },
    MemoryThresholdExceeded { percent: f64 },
    ServiceDown { service: String },
    CertificateExpiring { domain: String, days: i64 },
    ResourceUpdated { uri: String },
}
```

Нужны:

- bounded broadcast/channel;
- debounce;
- deduplication;
- cooldown;
- severity;
- timestamps;
- dropped-event counter.

### 10.2 Outbound sinks

- stdio: единый writer task, чтобы responses и notifications не перемешивали байты;
- SSE: session-specific sender;
- direct HTTP: только request/response, если активной stream-сессии нет;
- отключённый клиент удаляется из session registry;
- медленный клиент не блокирует остальных.

### 10.3 Источники событий

Подключать по очереди:

1. завершение background task;
2. resource updated;
3. memory threshold;
4. service down;
5. certificate expiring.

Первые два события детерминированы и проще для приёмки. Периодический мониторинг следует добавлять после стабилизации delivery.

### 10.4 Multi-client isolation

Текущий глобальный `connected_client` заменить на request/session context. Иначе параллельные HTTP-клиенты могут перезаписывать идентичность друг друга в audit log.

### 10.5 Тесты

- notification не имеет JSON-RPC `id`;
- два клиента получают только свои события;
- медленный SSE-клиент;
- disconnect cleanup;
- reconnect;
- очередь переполнена;
- task completion notification;
- resource subscription notification;
- response и notification не повреждают stdio framing.

### Критерий выхода

- уведомления реально доставляются по stdio и SSE;
- события не выдаются за доставленные, если sink отсутствует;
- сессии очищаются после disconnect.

---

## 11. Этап 9 — документация и cleanup

Обновить:

- README: 33 инструмента либо генерируемое актуальное число;
- статический badge с количеством тестов удалить или генерировать автоматически;
- описание HTTP/SSE и поддерживаемой версии MCP;
- конфигурационные поля;
- ограничения платформ;
- semantics audit-log;
- ресурсы и notifications;
- примеры ошибок;
- матрицу Linux/Windows support;
- `implementation_checklist.md`.

Также:

- привести весь код к rustfmt;
- проверить отсутствие `TODO`, `FIXME`, `unimplemented!`;
- проверить, что schema каждого tool соответствует реально поддержанным параметрам;
- не документировать Phase 5 как завершённую.

---

## 12. Предлагаемое разбиение на изменения

1. `fix: enforce bounded command output and process cleanup`
2. `fix: make explicit configuration fail closed`
3. `fix: bound log tailing and make file writes atomic`
4. `fix: add background task quotas ttl and process-tree cancellation`
5. `feat: add durable tamper-evident audit chain`
6. `feat: complete journal filtering and integration safety`
7. `feat: implement MCP resource providers and subscriptions`
8. `feat: implement session-scoped server notifications`
9. `docs: align roadmap checklist and observed capabilities`

Каждый шаг должен быть отдельно собираемым и проверяемым. Resources и notifications не следует объединять в один большой рефакторинг: notification delivery зависит от корректной session/transport модели.

---

## 13. Финальный acceptance gate

### 13.1 Обязательные команды

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release --locked
```

### 13.2 Обязательные adversarial проверки

- неограниченный stdout/stderr;
- timeout с дочерним процессом;
- symlink/path traversal;
- malformed config;
- audit tampering;
- rate-limit concurrency;
- task cancellation race;
- SSE disconnect/reconnect;
- cross-session isolation;
- oversized resource;
- notification queue overflow.

### 13.3 Статусы

- `REJECTED` — отсутствует хотя бы один обязательный handler или есть незакрытый P0/P1-дефект;
- `LOCALLY_VERIFIED` — проходят Rust и локальные E2E-тесты;
- `CANDIDATE_ACCEPTED` — дополнительно пройдены реальные Linux-интеграции и сохранено evidence;
- `ACCEPTED` — только после отдельного решения по результатам отчёта.

