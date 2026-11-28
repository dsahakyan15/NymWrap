# NymWrap

Локальная программа для разделения личных вопросов (Shield) и выбранной легенды
(Drift). Purge помогает уменьшать старые следы, Mirror измеряет изменение профиля.
Rust-демоны, Tauri UI, расширение MV3 для Chrome/Firefox.

Работа продолжается по [SPEC](docs/SPEC.md). Диалог работает локально (L0) и через
Tor с отдельным ключом провайдера (L3, standard), с одноразовым просмотром перед
отправкой. Фоновые приманки и очередь постоянных слотов standard включаются
отдельно; есть сохраняемые задания и async HTTP API. Маршруты paranoid,
Nym/zkAPI и укрепление всех процессов ещё не завершены.
Текущее состояние и оставшиеся проверки: [IMPLEMENTATION](docs/IMPLEMENTATION.md).
M0–M7 не объявлены закрытыми.

Проверки: `scripts/check.ps1` или `scripts/check.sh`. Source SBOM строится
`node scripts/sbom.mjs --target x86_64-pc-windows-msvc --out target/nymwrap.cdx.json`
после получения зависимостей всех трёх Cargo-workspace; официальная схема
проверяется `./scripts/validate-sbom.ps1 -Path target/nymwrap.cdx.json`.
Это ведомость исходных компонентов, не подпись готовой программы.

## Запуск на Windows

Нужны Rust из rust-toolchain.toml, Node.js 24+, Visual Studio C++ Build Tools,
Windows SDK и WebView2. Из корня репозитория:

```powershell
./scripts/bootstrap-perl.ps1
./scripts/bootstrap-libclang.ps1
cd app
npm ci
npm run desktop
```

Средства сборки загружаются по закреплённым версиям и SHA-256 в target/tools.
Скрипт desktop собирает все необходимые демоны и запускает интерфейс без HTTP
dev-сервера. На «Обзоре» создайте пространство; Standard допускает пустой пароль,
Strict/Paranoid требуют пароль. Ключ также зависит от хранилища ключей ОС.

В настройках укажите абсолютные пути chat GGUF и nomic-embed-text GGUF, SHA-256
обоих файлов и нажмите «Запустить проверенные модели». Загрузка может занять
до двух минут. Для проверки разработчика есть scripts/fetch-test-models.ps1 с
закреплёнными официальными Qwen2.5-0.5B и nomic. Модели не входят в репозиторий.

## Что работает

- SQLCipher по отдельным доменам, XChaCha20-Poly1305, OS key store + Argon2id,
  защищённые ключи в памяти, retention и crypto-shredding.
- nymwrapd владеет пространством. UI и OpenAI API используют общую историю;
  разговоры продолжаются после повторного открытия с прежними плейсхолдерами.
- Собственный CPU worker llama.cpp, проверка GGUF по SHA-256, приватные Unix
  sockets / Windows named pipes, без TCP-коннектора модели; native GGUF/inference
  на Windows в одноразовом LPAC с дескрипторами моделей только на чтение.
- Импорт JSON/HTML/ZIP, SQLite backup Chrome/Firefox/Safari в памяти, отдельный
  ограниченный worker. Локальная персона с подтверждением каждого утверждения.
- Проверка плана эмбеддингами, одобрения по хешу, отдельные формулировки дня,
  сохранение прогресса, пауза и минимум 12 часов между днями.
- Purge: ранжирование и одобрение партии удаления; Mirror: снимки и измерения.
  Расширение получает только одобренные задания легенды через native messaging.
- Tor с отдельной изоляцией разговоров, HTTPS, EFS/fscrypt для состояния,
  аутентифицированный IPC, полный Shield/NER/Route, резерв бюджета до send,
  отсутствие retry/fallback и завершение дочернего процесса с ядром.
- Одноразовый просмотр без повторного вызова модели, TTL, привязка к провайдеру;
  фоновые синтетические приманки с зашифрованными слотами и uncertain без replay.

Локальные проверки включают настоящий CPU inference, Credential Manager,
сквозной HTTP API через named pipe, перезапуск core, отсутствие синтетического
открытого текста в store и разные идентификаторы настоящих Tor-цепочек.
Они не заменяют CI, захват всего трафика, 24-часовой fuzz, подписи и аудит M6.

## CLI и API

После `. ./scripts/build-env.ps1`:

```powershell
cargo run -p nw-core --bin nymwrap -- demo
cargo run -p nw-core --bin nymwrap -- paths
Get-Content -Raw export.json | cargo run -p nw-core --bin nymwrap -- audit takeout
cargo run -p nw-api -- --help
```

`nymwrap rpc` отключён (ADR 0076): открытым пространством управляет только
приложение через авторизованную сессию nymwrapd. API требует открытого
пространства и работающей локальной модели. После Lock/DestroyData runtime-сессия
core завершается; UI запускает её снова.

Сквозная проверка того же пути, что использует UI (пространство Standard,
импорт синтетического Takeout, проверенные модели, L0 через named pipe, Drift,
Purge, Mirror), — `node tests/e2e/local.mjs --with-os-keystore`. Обёртка собирает
демоны и запускает `crates/nw-core/tests/desktop_flow.rs` во временном каталоге;
пространство и запись в хранилище ключей ОС удаляются в конце. Перед запуском
закройте приложение и выполните scripts/fetch-test-models.ps1. С 0.5B план Drift
обычно не проходит проверки кода (`plan_checks_failed`, тест пишет NOT VERIFIED);
полное одобрение плана проверяется с `--model-7b`.

Полная инструкция, импорт SQLite WAL, подключение расширения и ограничения:
[USER_GUIDE](docs/USER_GUIDE.md). Требования безопасности:
[THREAT_MODEL](docs/THREAT_MODEL.md).

## Проверки и сборка

Для `check.ps1` нужен PowerShell 7 (`pwsh`), включая проверку SBOM по JSON Schema.
Windows PowerShell 5.1 подходит для базовой сборки, но не полного check.ps1.

```powershell
./scripts/check.ps1
node tests/e2e/local.mjs --with-os-keystore
cd app
npm run desktop:build
```

Сквозной тест использует синтетические данные, локальные модели в target/test-models
и настоящий OS key store; рабочее приложение перед ним нужно закрыть. Он удаляет
только собственное тестовое пространство. Linux/macOS: scripts/check.sh.

После desktop:build добавьте `--release` к команде сквозного теста для проверки
соседних бинарников из app/src-tauri/target/release; `--with-tor` включает
ограниченный тест публичной Tor-сети с синтетическими ключами. Coverage/ASan
и отдельная 24-часовая кампания описаны в [fuzz/README.md](fuzz/README.md).

Изолированные проверки расширения в настоящих Chromium и Firefox запускаются отдельно:
из `extension` выполните `npm ci`, `npm run browser:install`, на Windows также
`npm run firefox:install`, затем `npm run test:browser`.
Нужен PowerShell 7 для временного TLS-сертификата. Тесты используют синтетические
HTTPS-страницы на loopback, собственный профиль и тестовый native host; реальные
сервисы и профиль браузера не затрагиваются. В CI выделена отдельная Linux/Windows
задача; штатный Firefox пока проверяется на Windows. Отдельная явная команда
`npm run probe:public:firefox` читает живые публичные Google/YouTube/MyAdCenter и
страницы трёх ИИ-сервисов в новом профиле без входа, запросов или сообщений.
Она сохраняет только состояния/количества в target/browser-tests/reports.
Это не проверка аккаунтных интерфейсов и не обход CAPTCHA.

Настоящий Firefox Native Messaging → release nw-drift-host → core проверяется
отдельно: после desktop:build и firefox:install выполните из extension
npm run test:native:firefox. Нужны Rust и PowerShell 7; модели не запускаются.
Тест создаёт пустое синтетическое пространство и уникальную временную запись
HKCU для native host, проверяет паузу/возобновление и удаляет регистрацию,
пространство и профиль. Основная регистрация NymWrap не меняется. Рабочий desktop
перед этим тестом должен быть закрыт. JavaScript продукта и CSP сохраняются;
в тестовой копии меняется только имя host и запуск popup.

Качество NER измеряется отдельно от корректности JSON. После получения тестовых
моделей и сборки worker выполните `cargo build -p nw-llm --example privacy_eval --locked`,
затем `node scripts/privacy-eval.mjs --release --report-only`. Флаг `--release`
выбирает worker из desktop-комплекта; без него нужен target/debug/nw-llmd.
Синтетический отчёт и SHA-256 инструментов появятся в target/privacy-eval/latest.json.
Без `--report-only` пропуск, отвергнутый ответ или ошибка дают ненулевой exit code.
Маленькая тестовая Qwen 0.5B не проходит этот критерий качества; она подходит для
проверки движка и безопасных отказов. Корпус не доказывает отсутствие утечек на
произвольных данных и не заменяет список секретов или просмотр перед отправкой.

Расширенная проверка выполняет настоящий Engine на 62 синтетических кейсах,
включая EN/RU/HY, кодировки, инъекции и связывание косвенных признаков между
двумя ходами. Дополнительная Qwen2.5-7B Q4_K_M закреплена в scripts/privacy-models.json:

```powershell
node scripts/fetch-privacy-model.mjs qwen2.5-7b-q4_k_m
node scripts/merge-privacy-model.mjs qwen2.5-7b-q4_k_m
cargo build -p nw-llmd --release --locked
cargo build -p nw-core --example privacy_pipeline --locked
node scripts/privacy-benchmark.mjs --model smoke
node scripts/privacy-benchmark.mjs --model qwen2.5-7b-q4_k_m
node scripts/privacy-report.mjs
```

Сначала нужны небольшая контрольная модель и nomic из fetch-test-models.ps1.
Скачивается около 4,7 GB; сохраняются части и объединённый GGUF. Ограниченный
Node-парсер меняет только метаданные и смещения, проверяя байты тензоров;
нативная загрузка остаётся внутри LPAC. Повторно объединять уже готовый файл
команда не будет. Производный SHA-256 — в target/test-models/*.merged.json.
Проверка копирует бинарники под их хешами, пишет checkpoint после каждого кейса;
`--limit N` ограничивает запуск, `--resume` продолжает при том же происхождении.
При смене Cargo features перед resume повторите точную команду сборки примера.
Модельные прогоны выполняйте последовательно, после завершения ресурсоёмких
сборок: CPU-нагрузка может превратить долгую генерацию в безопасный таймаут.
Время в отчёте не является сравнительным тестом производительности.

Отчёт target/privacy-eval/report.html разделяет утечки, L0, отказы, сохранение
публичной задачи и попытки связывания с восемью вымышленными профилями.
Исходящего сетевого запроса нет: штатное формирование перехватывается в памяти.
Сырые тексты и вывод модели в отчёт не попадают. Это не процент анонимности
реального человека; вход в аккаунт или оплаченный API-ключ остаются привязками.
Отдельную исходную NER-проверку из 16 кейсов можно повторить на 7B:
`node scripts/privacy-eval.mjs --model qwen2.5-7b-q4_k_m --benchmark-worker --report-only`.
`--benchmark-worker` использует проверенную копию worker из текущего benchmark,
даже если desktop-сборка уже заменила исходный exe; `--root-release` выбирает
текущий target/release без привязки к benchmark.
Флаг `--model-7b` у tests/e2e/local.mjs выбирает подготовленный 7B GGUF для
проверки настоящего core/HTTP, финальных ответов L0 и сохранённого разговора.
В этом тесте создаётся только синтетическое пространство; рабочий desktop
перед ним должен быть закрыт, как и для обычного E2E.

Linux-изоляцию можно проверить из Windows без WSL и администратора:
`node scripts/linux-isolation-probe.mjs --prepare`. Явная команда получает
закреплённые QEMU/Alpine/7-Zip в target/tools и musl target Rust. Установщики
не запускаются, Windows не перенастраивается. Linux работает в RAM; в гостя
передаются только синтетические test executables. Под UID 1000 проверяются
seccomp для старых/новых потоков и bwrap с единственным API socket, без TCP/UDP
или приватного файла вне рабочего каталога в Linux-госте. Отчёт и serial.log — в target/linux-isolation.
Это проверка конкретных границ, а не замена проверки всех демонов или MicroVM
для пользовательских агентов. Последующие запуски допускают отсутствие --prepare.

Release-бинарники и необходимые соседние демоны появляются в
app/src-tauri/target/release. Статический app/dist/index.html показывает интерфейс;
для действий нужен Tauri. Модели, регистрация native host и установка расширения
выполняются отдельно пользователем.
