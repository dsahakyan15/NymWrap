# Аудиты зависимостей продуктового графа root

Дополняет [ADR 0073](0073-locked-dependency-audit-gates.md) только для
`Cargo.toml` в корне и `supply-chain/root/`. Исходная ревизия —
`4691e27f15b7ea109c2a01116387f450454b7054`, дата — 2026-11-26.
Продуктовый критерий **safe-to-deploy сохранён**: root использует стандартную
политику cargo-vet; локальных policy overrides на safe-to-run нет.
Версии, все Cargo.lock и правило audit-as-crates-io для llama-cpp-2 не меняются.

Метод взят из [ADR 0088](0088-fuzz-dependency-audit-sources.md), но доверие для
fuzz не перенесено автоматически. safe-to-deploy требует рассмотреть unsafe,
ambient capabilities и генерируемый deployed-код при недоверенном вводе,
а не только отсутствие неожиданных действий при сборке/локальном запуске:
[семантика cargo-vet](https://mozilla.github.io/cargo-vet/built-in-criteria.html).

## Закреплённые внешние аудиты

Прямо доверяем опубликованным именованным проверкам следующих официальных
команд с их исходными критериями. Mozilla/Google сохранены на commits ADR 0073.
Дополнительно взяты те же immutable источники, что рассмотрены в ADR 0088:

- Bytecode Alliance / Wasmtime: `1499ce8728f5f1b7fae0db88e1417991b01cfc13`.
  Команда развивает runtime и проверяет production Rust/FFI и его зависимости.
- ISRG / Divvi Up libprio-rs: `7549f3c7dffe96d3a6e6fb214007911cdec3e8e6`.
  Релевантна работа с криптографией и агрегацией данных для приватности.
- Zcash Rust ecosystem: `ce132d7abdd52f2b3b0d55ed5dc9f152331535c2`.
  Принимаются атрибутированные проверки команд librustzcash/wallet/zcash,
  описанных в ADR 0088, для криптографического production ПО.
- Embark Studios: `732513edfd9172f4eda358b2d0cefc6cad1585ee`.
  Команда cargo-deny и Rust tooling публикует проверки production-зависимостей.

Точные URL и SHA-256 загруженных наборов записаны в
[JSON-отчёте](../../supply-chain/root/review-2026-11-26.json). Наборы не передают
собственные imports/exemptions; custom criteria не отображаются на более
сильные локальные. Собственные safe-to-run проверки fuzz не повышались и
не копировались. Внешние аудиты дали **268 → 245 → 242 → 235 → 233** пробела.

## Доверие к публикаторам именно для safe-to-deploy

[Trusted entries](https://mozilla.github.io/cargo-vet/trusting-publishers.html) —
явное доверие качеству production-релизов определённого сопровождающего,
а не доказательство авторства каждого изменения и не собственный source audit.
Выбраны 15 crates.io user-id и 7 официальных repository identities из списка
ADR 0088. Для каждого ниже заново принято ограниченное продуктовое доверие.
Полное обоснование повторено в notes каждой записи и в JSON вместе с
проверенными первичными upstream-источниками и их SHA-256.

| Публикатор | Основание safe-to-deploy в ограниченном семействе | Закрыто |
|---|---|---:|
| dtolnay (3618) | Сериализация недоверенных данных и безопасность сгенерированного Rust в Serde/syn и связанных макросах. | 17 |
| alexcrichton (1) | Только wasi: сопровождение Rust/Cargo/Wasmtime и production WASI ABI; openssl-src отложен. | 1 |
| tarcieri (267) | Руководитель RustCrypto: аутентификация, ключи, constant-time ограничения шифров/MAC и CPU dispatch. | 10 |
| newpavlov (5059) | Руководитель RustCrypto: production хеши/KDF, CBC, padding и размерные интерфейсы; getrandom исключён из итогового доверия. | 5 |
| taiki-e (33035) | Инварианты pinning, атомиков, cancellation/wakeup и владения в futures/smol/Crossbeam. | 11 |
| seanmonstar (359) | Сетевые HTTP-парсеры, framing, буферы и композиция сервисов Hyper/Tower; опубликована security policy. | 8 |
| Darksonn (6741) | Production Tokio: конкурентность, владение bytes/slab, генерация entry points, axum и tokio-util. | 6 |
| BurntSushi (189) | Недоверенные текст/шаблоны и ограничения сложности regex; для walkdir/same-file/winapi-util — заявленные файловые/symlink контракты. | 8 |
| cuviper (539) | Production арифметика rust-num, инварианты контейнеров indexmap/either и build capability detection. | 8 |
| kennykerr (64539) | Microsoft windows-rs: сгенерированные Windows ABI и упакованные target import libraries; unsafe предусловия вызывающего кода сохраняются. | 22 |
| epage (6743) | Парсинг/сериализация недоверенной TOML-конфигурации и parser combinators winnow. | 5 |
| Amanieu (2915) | Владение блокировками, атомарные состояния, RAII/unwind и Drop в parking_lot/lock_api/scopeguard. | 4 |
| sunfishcode (6825) | Безопасные syscall-обёртки rustix и согласованные ABI linux-raw-sys. | 2 |
| rust-lang-owner (55123) | Только jobserver, cmake, glob и hashbrown: официальная Rust toolchain/collection инфраструктура; общий аккаунт не разрешён целиком. | 4 |
| Thomasdezeeuw (6025) | Production Mio/socket2: владение сокетами, readiness, FFI длины и платформенные I/O контракты. | 2 |
| github:rust-lang/cc-rs | Официальный release cc/find-msvc-tools: native build arguments и compiler discovery; чужой компилируемый C/C++ не получает аудит. | 2 |
| github:rust-lang/flate2-rs | Production decompression wrapper на недоверенных байтах; backends и лимиты распаковки проверяются отдельно. | 1 |
| github:rust-lang/libc | Сопровождение production OS ABI/layout Rust-проектом; безопасность unsafe-вызовов требует проверки клиентов. | 1 |
| github:rust-lang/log | Синхронизация глобального logger и formatting dispatch; политика содержания журналов остаётся у приложения. | 1 |
| github:RustCrypto/hashes | Реализация sha1 и её dispatch на недоверенных байтах; стойкость SHA-1 к коллизиям не заявляется. | 1 |
| github:RustCrypto/utils | zeroize/derive: устойчивое к оптимизации очищение памяти и soundness сгенерированного cleanup. | 2 |
| github:taiki-e/pin-project-lite | Soundness структурной pin projection и ограничений Drop/Unpin в deployed async-коде. | 1 |

Итого **122 записи / 122 закрытых пары crate/version**, **233 → 111**.
Разрешены только перечисленные в JSON пакеты, с отдельным однодневным окном
`[день публикации, следующий день)`. Будущих релизов и широких периодов нет.
Это не утверждение о новом независимом криптографическом или native-аудите;
полагаемся на указанную компетенцию и сопровождение ровно этих upstream.

Для каждой точной locked-версии заново получен crates.io API response:
проверены published_by.id/login либо trustpub_data.repository/provider,
created_at, отсутствие yank; SHA-256 локального .crate совпал с checksum API,
Cargo.lock и sparse index. Текущий owner не подменяет uploader публикации.
При published_by=null не придуман человеческий user-id: используются
`github:<repository>`, а run_id/SHA сохранены как registry metadata. Отдельного
аудита этих workflows не заявляем. У path fork llama-cpp-2 нет registry checksum
в Cargo.lock: он не получил нового доверия или source audit; опубликованная
база и локальная/native разница остаются открытыми согласно ADR 0073.

Дополнительная запись getrandom 0.2.17 по newpavlov не дала измеримого покрытия
в locked resolver и удалена: **107 → 107** после исходных аудитов. Её проверенные
метаданные и история оставлены в deferred_publisher_trust; imports.lock вручную
не дополнялся. Доверие к alexcrichton не распространили на openssl-src: для
bundled OpenSSL C и обвязки общего опыта Rust toolchain недостаточно.

## Исходные проверки агента и честный остаток

Добавлены четыре полных записи safe-to-deploy: bitflags 2.13.2, version_check
0.9.5, wasm-bindgen-shared 0.2.130, endi 1.1.1. Каждая явно помечена
**«Проверено агентом, не человеком»**, имеет SHA архива, перечень рассмотренных
опасных операций/макросов и ограничения. По JSON можно сверить SHA каждого
просмотренного файла с опубликованным архивом. Исходные записи root сохранены.

Сначала рассматривались узлы с наибольшим числом транзитивных потребителей:
bitflags — 46, typenum/version_check — по 39. Для typenum просмотрены manifest,
структура и sealed marker traits, но арифметика/генерируемые таблицы не проверены
полностью — сертификата нет. generic-array (38) и errno (34) также оставлены
открытыми. У errno просмотрены все платформенные реализации, но требуется
завершить проверку ABI и NUL-терминации для strlen после strerror_r/ERANGE.
Это не заявление о подтверждённой уязвимости. Частичное чтение phf_shared
и native C/ASM тоже не объявлено аудитом.

Четыре аудита дали **111 → 110 → 109 → 108 → 107**. Новых exemptions нет.
Оставшиеся **107** пар с критериями и приоритетами перечислены в JSON.
Root dependency gate и M6 остаются **открытыми**; конечное состояние —
промежуточная партия, не зелёная приёмка.

## Локальная проверка

- Закреплённый cargo-vet 0.10.4: финальный
  `node scripts/vet-dependencies.mjs root`, без обновления imports, —
  failed, 107 gaps; все четыре хеша входов неизменны в финальном прогоне.
- cargo-deny 0.22.0: `cargo deny check --hide-inclusion-graph` — exit 0,
  advisories/bans/licenses/sources ok; предупреждения о дубликатах.
- Прямые проверки pinned rustc: version_check — 10 unit tests (исторический
  static corpus отсутствует и соответствующий тест возвращается без проверки);
  bitflags — 2 review tests, включая все 256 масок u8; wasm-bindgen-shared —
  schema hash approval test; endi — 11 unit tests и no_std compilation.
  Это не полный upstream feature matrix и не cross-platform CI.
- Тесты vet wrapper — 3/3; расширение `npm ci; npm test` — 24/24.
- `cargo test --workspace --locked`, `cargo clippy -- -D warnings` и
  `cargo test -p nw-leak-tests --locked` завершились exit 101 до окончания
  проверки проекта: сборке OpenSSL не хватило Perl; имеющийся Git Perl
  при process-local PATH не содержит `Locale::Maketext::Simple`.
  Инструменты не устанавливались, зелёного результата этих проверок нет.
- cargo vet fmt для root и git diff --check. Другие stores не менялись,
  пользовательское поведение не менялось; CI не запускался.
