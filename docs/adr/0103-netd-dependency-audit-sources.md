# cargo-vet: источники и промежуточный аудит графа netd

2026-11-26. Дополняет [ADR 0073](0073-locked-dependency-audit-gates.md) только
для `daemons/nw-netd/Cargo.toml` и `supply-chain/netd/`. Исходный commit —
`4691e27f15b7ea109c2a01116387f450454b7054`. Манифесты, версии, все Cargo.lock,
остальные stores и cargo-vet 0.10.4 сохранены. Новых exemptions нет.

Результат этой партии: **499 → 312 пробелов**. Это промежуточная работа:
`node scripts/vet-dependencies.mjs netd` по-прежнему завершается провалом
аудитного покрытия. M6 и CI dependency-audits не закрыты.

## Критерий продукта

netd — поставляемый сетевой демон, обрабатывающий недоверенные ответы и байты
Tor/HTTP/TLS. Его требования остаются прежними: production-путь требует
`safe-to-deploy`, включая безопасность unsafe-кода, сильных возможностей и
генерируемого для продукта кода на враждебных данных. Существующая dev-политика
cargo-vet также не меняется. Не добавлены переопределения policies, ослабление
criteria или отображение `safe-to-run` на `safe-to-deploy`.

Послабление отдельного fuzz из [ADR 0088](0088-fuzz-dependency-audit-sources.md)
сюда не переносится. Его список авторов — только исходные кандидаты для нового
решения о доверии. Семантика взята из документации cargo-vet:
[criteria](https://mozilla.github.io/cargo-vet/built-in-criteria.html),
[publisher trust](https://mozilla.github.io/cargo-vet/trusting-publishers.html).

## Закреплённые внешние проверки

Mozilla и Google остаются на commits ADR 0073. Добавлены четыре прямых импорта,
ранее рассмотренные в ADR 0088; их содержимое заново получено и SHA-256 записан
в [JSON-отчёт](../../supply-chain/netd/review-2026-11-26.json):

| Источник | Immutable commit | Пробелов после шага |
|---|---|---:|
| Bytecode Alliance / Wasmtime | `1499ce8728f5f1b7fae0db88e1417991b01cfc13` | 475 |
| ISRG / Divvi Up / libprio-rs | `7549f3c7dffe96d3a6e6fb214007911cdec3e8e6` | 470 |
| Zcash / rust-ecosystem | `ce132d7abdd52f2b3b0d55ed5dc9f152331535c2` | 464 |
| Embark Studios / rust-ecosystem | `732513edfd9172f4eda358b2d0cefc6cad1585ee` | 461 |

Эти команды публикуют атрибутированные проверки зависимостей runtime,
криптографических продуктов и Rust tooling. Доверяем опубликованным записям с
их исходными criteria; custom criteria не усиливаются, чужие imports и
exemptions не наследуются. Агрегированный Zcash имеет те же три источника,
которые описаны в ADR 0088. Ссылки на точные audits.toml находятся в конфиге
netd; доверие к продукту не выводится из одного лишь имени организации.

### Tor Project / Arti

Официальный GitLab API подтвердил проект `tpo/core/arti`, id 647. Проверено
полное публичное дерево — **2486 записей, 25 страниц** — на commit
[`12432ae63b529bccbb68c52073576b19fd6f8552`](https://gitlab.torproject.org/tpo/core/arti/-/tree/12432ae63b529bccbb68c52073576b19fd6f8552).
В этом дереве нет cargo-vet `audits.toml`/store; найден `maint/cargo-audit`,
который не является набором cargo-vet. Tor также отсутствует в просмотренном
[реестре cargo-vet](https://github.com/mozilla/cargo-vet/blob/main/registry.toml).
Raw GitLab дал HTTP 403, поэтому вывод основан на успешном полном обходе API,
а не на ошибке загрузки одного предполагаемого пути. URL и хеши ответов API
сохранены в отчёте. Это ограниченный вывод об этой ревизии и просмотренном
реестре, а не утверждение об отсутствии у Tor других security audits.
Импорт Tor и доверие всем `tor-*` не добавлены; **36 Arti/Tor пакетов** остаются
пробелами.

## Доверие публикаторам для safe-to-deploy

Добавлены **145 отдельных записей для 145 пар crate/version**, сгруппированных
по **15 user-id и восьми GitHub identities**. Каждая запись ограничена именем
пакета и одним UTC-днём `[дата публикации, следующий день)`. Это разрешает
публикации того же автора/пакета в этот день; точный используемый релиз задаёт
неизменённый Cargo.lock. Долгих окон и разрешения будущих релизов нет.

До решения проверены exact-version uploader/дата/yank/checksum в crates.io API,
SHA локального `.crate` и sparse index; перед записью publisher lock также
проверен checksum Cargo.lock. Для **19 версий** использовано уже сохранённое
подтверждение crates.io из отчёта ADR 0088 на исходном commit: текущий API после
первой части запросов вернул HTTP 429. Их архивы и индекс сверены заново;
повторная онлайн-проверка uploader не заявляется. Эти случаи явно имеют
`metadata_origin` с источником и хешем прежнего отчёта. Остальные 126 версий
имеют вновь полученный ответ API. Workflow identity не подменяется user-id;
repository/run_id/SHA из реестра — происхождение публикации, не аудит workflow.

HTTP 429 помешал `regenerate imports` получить `paste`. Поэтому publisher-блоки
`imports.lock` перенесены из проверенных API-метаданных; для одинаковых версий
из прежнего отчёта использованы соответствующие блоки fuzz imports.lock.
Внешние аудиты до этого обновлены штатным `--update-imports`. Закреплённый
`cargo vet fmt` нормализовал store; каждый содержательный шаг после этого
измерен обычным CI wrapper `check --locked`, без изменения инструмента или
проверки. Это не фиктивные исходные аудиты. Онлайн-регенерацию следует повторить,
когда реестр снова доступен, и проверить diff publisher-метаданных.

Доверие — явно принятая эвристика к сопровождению конкретного семейства для
production, а не независимая проверка исходников. Краткие основания ниже;
каждая запись audits.toml и отчёт содержат подробное обоснование для
`safe-to-deploy`, область и ограничения. Прецеденты доверия в закреплённых
наборах не считаются аудитом более нового релиза.

| Автор / identity | Основание именно для продукта | Закрыто |
|---|---|---:|
| dtolnay (3618) | Serde/syn и собственные макросы: недоверенный синтаксис, сериализация, bounds/lifetimes генерируемого кода; прецедент safe-to-deploy в ISRG/Wasmtime | 23 |
| alexcrichton (1) | Только filetime/WASI: сопровождение Rust/Cargo/Wasmtime, файловые операции и корректность ABI; то же продуктовое доверие в pinned наборах | 2 |
| tarcieri (267) | Руководитель RustCrypto; доверие обработке враждебных ключей, подписей, шифротекста и unsafe ускорению в своих криптографических семействах | 24 |
| newpavlov (5059) | Руководитель RustCrypto; буферы, hash/cipher/KDF, источники энтропии и код literal-макроса, включая границы platform/unsafe | 8 |
| taiki-e (33035) | futures/crossbeam/fastrand: pin/waker, атомарность и конкурентное исполнение; fastrand не считается криптографическим RNG | 5 |
| seanmonstar (359) | HTTP/Hyper/body/Tower/mime: framing, длины и буферы при враждебных HTTP-данных; опыт production-протоколов | 8 |
| Darksonn (6741) | Tokio/bytes/slab/axum: владение буферами, async pinning и adversarial scheduling | 6 |
| BurntSushi (189) | Поиск/regex/bstr: недоверенные шаблоны и текст, SIMD bounds; отдельно ожидаемые операции file identity/tzdb | 8 |
| cuviper (539) | rust-num/indexmap/autocfg/either: инварианты чисел/контейнеров и корректность compiler probes, опыт Rust compiler/library/release | 7 |
| kennykerr (64539) | Microsoft windows-rs: generated ABI/layout/linkage и target import libraries; не безопасность произвольных вызовов Win32 | 12 |
| epage (6743) | TOML/winnow: границы парсеров и emitted syntax на недоверенной конфигурации, сопровождение Cargo/TOML | 12 |
| Amanieu (2915) | atomic/hashbrown/parking_lot: unsafe владение памятью, синхронизация и конкурентные нагрузки | 7 |
| sunfishcode (6825) | rustix/linux-raw-sys: указатели/длины, ABI и ошибки системных вызовов, опыт capability runtime | 2 |
| rust-lang-owner (55123) | Только jobserver: владение наследуемыми FD/handles и build coordination; hashbrown/libm/lazy_static этого user-id здесь не разрешены | 1 |
| Thomasdezeeuw (6025) | Mio/socket2: socket ABI, ownership/readiness и размеры буферов на враждебной сети | 2 |
| github:rust-lang/cc-rs | cc/find-msvc-tools: native toolchain и linker output; не аудит компилируемых ими C/ASM | 2 |
| github:rust-lang/flate2-rs | flate2: bounds/state на враждебном сжатом вводе; caller обязан ограничить объём распаковки | 1 |
| github:rust-lang/hashbrown | Unsafe bucket ownership/probing в официальной реализации таблиц Rust; выбор DoS-resistant hasher остаётся за caller | 1 |
| github:rust-lang/libc | ABI/signatures/layout системных bindings; не аудит их callers или native ОС | 1 |
| github:rust-lang/log | Global logger lifetime/init и конкурентный dispatch; content-free logging остаётся обязанностью NymWrap | 1 |
| github:RustCrypto/hashes | Hash padding/compression и accelerated unsafe при враждебных длинах; SHA-1 не объявляется collision-resistant | 3 |
| github:RustCrypto/utils | Буферы, constant-time helpers, zeroize и emitted derive-код; без отдельного crypto-reviewed утверждения | 8 |
| github:taiki-e/pin-project-lite | Soundness проекций и Drop генерируемого pin-кода при произвольном polling | 1 |

После каждого автора выполнен отдельный locked check: **461 → 316**.
Полная последовательность, версии, даты, URL и SHA ответов реестра — в JSON.

## Исходные аудиты агента

Приоритет задан числом транзитивных потребителей полного all-platform графа
`cargo metadata --locked`, без фильтрации платформ или features. Это приоритет
человеческого/агентского просмотра, не мера числа автоматически проверенных
зависимостей.

| Крейт | Потребителей | Просмотр и результат | Пробелов |
|---|---:|---|---:|
| wasm-bindgen-shared 0.2.130 | 131 | Все Rust-модули, build.rs, schema macro, manifests; ограниченные операции build git/read, безопасные строки и predicates | 315 |
| wasm-bindgen-macro 0.2.130 | 129 | Весь wrapper и diagnostic glue; macro-support остаётся отдельным пробелом | 314 |
| version_check 0.9.5 | 57 | Все четыре модуля и manifests; проверено управление индексами и ограниченный compiler subprocess без shell | 313 |
| crypto-common 0.2.2 | 54 | Все три модуля и macro families; проверки длины ключей/IV, сериализация, fallible entropy и ограничения peek/unwind | 312 |

Каждый аудит содержит точный SHA-256 `.crate`, `safe-to-deploy`, описание
просмотренного и честное авторство: **«проверено агентом, не человеком»**.
Архивы заново сверены с Cargo.lock и sparse index, исходники читались из этих
архивов; SHA отдельных просмотренных файлов также сохранены. Старые fuzz
`safe-to-run` аудиты не переименовывались.

В изолированных копиях исходников version_check прошёл 10 unit tests и
26 doctests, shared — один schema-hash test. crypto-common собран offline с
all-features и версиями разрешения netd: unit tests отсутствуют, четыре
doctests ignored, поэтому это только свидетельство компиляции. Копии для
тестов получили пустой `[workspace]`, файлы продукта не менялись.

## Остаток и проверки

**312 пробелов** перечислены полностью в отчёте с missing criteria. Среди
наиболее общих непросмотренных узлов — wasm-bindgen-macro-support/bindgen/js-sys,
typenum, r-efi/getrandom 0.4, hybrid-array, libm, bitflags, smallvec и zerocopy.
У typenum просмотрены только manifests/changelog/инвентарь; исходный аудит не
завершён. Большие платформенные/криптографические/генерирующие библиотеки и
native-код не сертифицированы по одному поиску подозрительных API.

Опубликованная база path forks по-прежнему проверяется через прежнее
`audit-as-crates-io`; локальные TLS/PT/compatibility изменения и C/ASM остаются
отдельной работой M6. Канареечные тесты здесь не изменялись: runtime-код и
сетевая граница не меняются.

JSON содержит checkpoints с receipt закреплённого инструмента, хешами входов,
локальным происхождением результатов, полным остатком и фактическими статусами
проверок. Зелёный `cargo-deny` не заменяет красный cargo-vet.
